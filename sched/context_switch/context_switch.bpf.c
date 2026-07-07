#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "context_switch.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

/* ── PERCPU 中间存储：tp_btf/sched_switch 写入，finish_task_switch 读取 ── */
struct start_val {
	bpf_s32_t prev_pid, next_pid;
	bpf_s32_t prev_tgid, next_tgid;
	bpf_s32_t prev_prio, next_prio;
	bpf_s32_t prev_state, cpu;
	bpf_bool_t preempt;
	bpf_u64_t start_ts;
	bpf_s8_t  prev_comm[TASK_COMM_LEN];
	bpf_s8_t  next_comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct start_val);
} start_map SEC(".maps");

/* ── 控制 map ────────────────────────────────────────────── */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct ContextSwitch_ctrl);
} ctrl_map SEC(".maps");

/* ── 全局统计 map ────────────────────────────────────────── */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct ContextSwitch_stats);
} stats_map SEC(".maps");

/* ── 环形缓冲区 ──────────────────────────────────────────── */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* ── 获取控制配置 ────────────────────────────────────────── */
static inline struct ContextSwitch_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
}

/* ── 判断是否应跳过该事件 ────────────────────────────────── */
static inline bool should_skip(struct ContextSwitch_ctrl *ctrl,
			       bpf_s32_t prev_pid, bpf_s32_t next_pid,
			       bpf_u64_t delay_ns)
{
	if (!ctrl || !ctrl->enable)
		return true;

	/* PID 过滤：target_pid != 0 时只收集涉及该 PID 的切换 */
	if (ctrl->target_pid != 0 &&
	    prev_pid != ctrl->target_pid &&
	    next_pid != ctrl->target_pid)
		return true;

	/* 延迟阈值过滤：低于 min_delay_ns 的轻量切换直接丢弃 */
	if (ctrl->min_delay_ns != 0 && delay_ns < ctrl->min_delay_ns)
		return true;

	return false;
}



/* ── tp_btf/sched_switch：记录切换前的全部上下文 ────────────
 *   PERCPU 确保多核并发互不干扰
 */
/**
 * @brief 调度切换入口探针：记录切换发生时刻、前后进程全量基础信息
 * @param preempt 切换类型标记：true=高优先级抢占切换，false=进程自愿让出CPU(休眠/时间片耗尽/yield)
 * @param prev 即将被换下CPU的旧任务 task_struct 原生指针
 * @param next 即将调度上CPU运行的新任务 task_struct 原生指针
 * @return 0 固定返回，BPF探针无返回值业务逻辑
 */
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch_capture, bool preempt,
	     struct task_struct *prev, struct task_struct *next)
{
	struct ContextSwitch_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	// start_map 为PERCPU数组map，key固定0，每CPU独立存储单次切换起始快照
	int key = 0;
	struct start_val *v = bpf_map_lookup_elem(&start_map, &key);
	if (!v)
		return 0;

	v->start_ts    = bpf_ktime_get_ns();
	v->cpu         = bpf_get_smp_processor_id();	// 记录当前执行切换逻辑的CPU编号，区分多核调度事件
	v->preempt     = preempt;

	v->prev_pid    = BPF_CORE_READ(prev, pid);
	v->next_pid    = BPF_CORE_READ(next, pid);

	v->prev_tgid   = BPF_CORE_READ(prev, tgid);
	v->next_tgid   = BPF_CORE_READ(next, tgid);
	
	v->prev_prio   = BPF_CORE_READ(prev, prio);
	v->next_prio   = BPF_CORE_READ(next, prio);
	
	v->prev_state  = BPF_CORE_READ(prev, __state);

	bpf_probe_read_kernel_str(&v->prev_comm, sizeof(v->prev_comm), prev->comm);
	bpf_probe_read_kernel_str(&v->next_comm, sizeof(v->next_comm), next->comm);

	return 0;
}


/*
 * kprobe 挂载 finish_task_switch.isra.0
 * 功能：sched_switch 完成上下文切换后触发，计算切换耗时、过滤条件、投递事件到ringbuf、更新全局统计
 * 配合 tp_btf/sched_switch 使用：
 *   1. tp_btf/sched_switch：切换开始，记录起点时间戳+前后进程信息存入每CPU start_map
 *   2. 本kprobe：切换完全结束，读取起点时间戳算出延迟，过滤后上报、更新统计
 */
 /**
* @brief 上下文切换收尾钩子，计算切换耗时并输出事件
* @param prev 刚完成下CPU的旧任务 task_struct 指针（函数入参）
* @return 0 BPF探针固定返回值
*/
SEC("kprobe/finish_task_switch.isra.0")
int BPF_KPROBE(finish_task_switch, struct task_struct *prev)
{
	struct ContextSwitch_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	int key = 0;
	// start_map 是PER-CPU数组map，key=0 取出当前CPU保存的切换起始快照
	struct start_val *v = bpf_map_lookup_elem(&start_map, &key);
	if (!v || v->start_ts == 0)
		return 0;

	bpf_u64_t end_ts  = bpf_ktime_get_ns();
	// 计算本次上下文切换总耗时（从调度决策到寄存器栈切换完成）
	bpf_u64_t delay_ns = end_ts - v->start_ts;

	/* 过滤逻辑：PID匹配过滤 + 最小延迟阈值过滤 */
	if (should_skip(ctrl, v->prev_pid, v->next_pid, delay_ns)) {
		v->start_ts = 0;  // 清空标记，防止重复消费
		return 0;
	}

	/* 从环形缓冲区预分配事件内存，用于投递到用户态 */
	struct ContextSwitch_event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		v->start_ts = 0;
		return 0;
	}

	// 填充输出事件所有字段
	e->ts_ns       = end_ts;               // 切换完成时间戳
	e->delay_ns    = delay_ns;             // 上下文切换耗时ns
	e->cpu         = v->cpu;               // 发生切换的CPU编号
	e->prev_pid    = v->prev_pid;          // 被换下线程LWP
	e->next_pid    = v->next_pid;          // 新调度线程LWP
	e->prev_tgid   = v->prev_tgid;         // 旧进程TGID(用户态PID)
	e->next_tgid   = v->next_tgid;         // 新进程TGID(用户态PID)
	e->prev_prio   = v->prev_prio;         // 旧任务内核统一优先级
	e->next_prio   = v->next_prio;         // 新任务内核统一优先级
	e->prev_state  = v->prev_state;        // 切换前旧任务状态
	e->preempt     = v->preempt;           // true=抢占切换 false=自愿切换
	// 拷贝进程名字符串到事件缓冲区
	__builtin_memcpy(e->prev_comm, v->prev_comm, TASK_COMM_LEN);
	__builtin_memcpy(e->next_comm, v->next_comm, TASK_COMM_LEN);

	// 将事件提交ringbuf，用户态可阻塞读取
	bpf_ringbuf_submit(e, 0);

	/* 更新全局切换统计信息，用于程序退出时打印汇总 */
	struct ContextSwitch_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
	if (stats) {
		// 统计项已存在：累加计数、总耗时
		stats->count++;
		stats->total_ns += delay_ns;
		// 判断是否刷新最大延迟记录
		if (delay_ns > stats->max_ns) {
			stats->max_ns = delay_ns;
			stats->max_prev_pid = v->prev_pid;
			stats->max_next_pid = v->next_pid;
			__builtin_memcpy(stats->max_prev_comm, v->prev_comm, TASK_COMM_LEN);
			__builtin_memcpy(stats->max_next_comm, v->next_comm, TASK_COMM_LEN);
		}
	} else {
		// 统计map无条目，初始化第一条统计数据
		struct ContextSwitch_stats new_stats = {};
		new_stats.count = 1;
		new_stats.total_ns = delay_ns;
		new_stats.max_ns = delay_ns;
		new_stats.max_prev_pid = v->prev_pid;
		new_stats.max_next_pid = v->next_pid;
		__builtin_memcpy(new_stats.max_prev_comm, v->prev_comm, TASK_COMM_LEN);
		__builtin_memcpy(new_stats.max_next_comm, v->next_comm, TASK_COMM_LEN);
		bpf_map_update_elem(&stats_map, &key, &new_stats, BPF_ANY);
	}

	// 清空当前CPU缓存快照，标记本条切换事件已处理完成
	v->start_ts = 0;
	return 0;
}

