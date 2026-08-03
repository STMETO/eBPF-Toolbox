#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "preempt.h"

/**
 * @brief BPF程序许可证，Dual BSD/GPL，允许tracepoint、kprobe追踪功能
 */
char LICENSE[] SEC("license") = "Dual BSD/GPL";

/**
 * @brief 全局控制MAP固定KEY，ctrl_map、stats_map、start_map统一使用key=0
 */
const int ctrl_key = 0;

/* ── PERCPU 中间存储 ─────────────────────────────────────── */
/**
 * @brief start_val：单CPU临时缓存抢占切换上下文信息
 * 说明：sched_switch 捕获抢占事件，先保存现场；
 * finish_task_switch kprobe触发后读取本结构体，计算抢占耗时。
 * 使用PERCPU_ARRAY保证每个CPU独立存储，无多核写冲突，无需锁。
 */
struct start_val {
	bpf_s32_t prev_pid, next_pid;      // 让出CPU任务PID、抢占任务PID（内核全局PID，非容器PID）
	bpf_s32_t prev_tgid, next_tgid;    // 让出CPU任务TGID、抢占任务TGID
	bpf_s32_t prev_prio, next_prio;    // 前后任务调度优先级
	bpf_s32_t prev_state;              // prev任务被抢占前的内核__state状态
	bpf_s32_t cpu;                     // 发生上下文切换的CPU编号
	bpf_u64_t start_ts;                // sched_switch触发时刻时间戳(ktime)
	bpf_s8_t  prev_comm[TASK_COMM_LEN];// 被抢占任务进程名
	bpf_s8_t  next_comm[TASK_COMM_LEN];// 发起抢占的任务进程名
};

/**
 * @brief start_map：PERCPU_ARRAY，每个CPU独立一块start_val存储
 * 设计要点：
 * 1. per-cpu存储，不同CPU抢占事件互不干扰，不存在并发写竞争；
 * 2. max_entries=1，仅key=0有效；每个CPU拥有独立副本；
 * 3. 工作流程：sched_switch写入 → finish_task_switch读取 → 使用完毕清空start_ts标记。
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct start_val);
} start_map SEC(".maps");

/**
 * @brief ctrl_map：全局控制参数数组
 * 用户态下发采集开关、目标PID、最小延迟阈值等配置
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Preempt_ctrl);
} ctrl_map SEC(".maps");

/**
 * @brief stats_map：全局统计指标数组
 * 保存抢占事件计数、总耗时、最大耗时现场信息
 * 注意：当前为全局共享MAP，多核写会产生竞争；追求极致性能应改为PERCPU_ARRAY
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Preempt_stats);
} stats_map SEC(".maps");

/**
 * @brief rb：环形缓冲区，内核向用户态推送抢占事件
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
 * @brief 获取全局控制配置结构体
 * @return 成功返回指针；配置不存在返回NULL
 */
static inline struct Preempt_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
}

/**
 * @brief 判断当前事件是否需要跳过（过滤逻辑）
 * @param ctrl 控制参数指针
 * @param prev_pid 被抢占任务PID
 * @param next_pid 抢占任务PID
 * @param delay_ns 抢占耗时
 * @return true=跳过不发送事件；false=正常上报
 */
static inline bool should_skip(struct Preempt_ctrl *ctrl,
			       bpf_s32_t prev_pid, bpf_s32_t next_pid,
			       bpf_u64_t delay_ns)
{
	// 采集未开启，直接丢弃事件
	if (!ctrl || !ctrl->enable)
		return true;

	// 设置目标PID：prev或者next任一匹配目标PID才保留事件
	if (ctrl->target_pid != 0 &&
	    prev_pid != ctrl->target_pid && next_pid != ctrl->target_pid)
		return true;

	// 设置最小延迟阈值，抢占耗时不足阈值则过滤
	if (ctrl->min_delay_ns != 0 && delay_ns < ctrl->min_delay_ns)
		return true;

	return false;
}

/* ── tp_btf/sched_switch：只记录抢占切换 ──────────────────── */
/**
 * @brief tracepoint sched_switch，捕获上下文切换起点
 * BTF tracepoint，参数由内核自动填充
 * @param preempt true：抢占式切换；false：自愿切换
 * @param prev 即将让出CPU的任务
 * @param next 即将抢占CPU运行的任务
 *
 * 原理：
 * sched_switch 是调度切换的入口；
 * 仅当 preempt=true 代表【高优先级任务抢占低优先级任务】；
 * 在这里采集所有上下文信息，存入当前CPU独有的start_map。
 */
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch_preempt, bool preempt,
	     struct task_struct *prev, struct task_struct *next)
{
	struct Preempt_ctrl *ctrl = get_ctrl();
	/*
	 * 过滤条件：采集关闭 OR 非抢占切换，直接返回
	 * 只关注 preempt == true 的抢占场景
	 */
	if (!ctrl || !ctrl->enable || !preempt)
		return 0;

	int key = 0;
	// 获取当前CPU独立的临时存储区域
	struct start_val *v = bpf_map_lookup_elem(&start_map, &key);
	if (!v)
		return 0;

	// 记录切换起始时间戳
	v->start_ts    = bpf_ktime_get_ns();
	// 记录当前CPU编号
	v->cpu         = bpf_get_smp_processor_id();

	// 读取前后任务PID/TGID（内核全局PID，非容器PID）
	v->prev_pid    = BPF_CORE_READ(prev, pid);
	v->next_pid    = BPF_CORE_READ(next, pid);
	v->prev_tgid   = BPF_CORE_READ(prev, tgid);
	v->next_tgid   = BPF_CORE_READ(next, tgid);

	// 读取调度优先级
	v->prev_prio   = BPF_CORE_READ(prev, prio);
	v->next_prio   = BPF_CORE_READ(next, prio);

	// 被抢占任务切换前的状态（RUNNING、INTERRUPTIBLE等）
	v->prev_state  = BPF_CORE_READ(prev, __state);

	// 读取进程名称comm字符串
	bpf_probe_read_kernel_str(&v->prev_comm, sizeof(v->prev_comm), prev->comm);
	bpf_probe_read_kernel_str(&v->next_comm, sizeof(v->next_comm), next->comm);

	return 0;
}

/* ── 计算延迟、过滤、发送 ────────────────────────────────── */
/**
 * @brief kprobe: finish_task_switch.isra.0
 * 触发时机：调度器完成任务切换收尾工作，是上下文切换的终点
 * @param prev 被切走的任务task_struct
 *
 * 整体时序：
 * sched_switch(起点，保存信息) → 内核完成硬件上下文切换 → finish_task_switch(终点)
 * delay_ns = finish时刻 - sched_switch时刻，得到抢占切换耗时
 *
 * 注意：
 * finish_task_switch 存在编译器内联优化，内核符号名带.isra.0后缀，不同内核版本可能存在差异，存在兼容性风险。
 */
SEC("kprobe/finish_task_switch.isra.0")
int BPF_KPROBE(finish_task_switch, struct task_struct *prev)
{
	struct Preempt_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	int key = 0;
	struct start_val *v = bpf_map_lookup_elem(&start_map, &key);
	/*
	 * 两种情况进入返回：
	 * 1. 没有捕获到对应的sched_switch抢占事件；
	 * 2. start_ts=0，表示上一轮事件已经消费完毕，无待处理抢占记录
	 */
	if (!v || v->start_ts == 0)
		return 0;

	// 获取切换完成时间戳，计算抢占耗时
	bpf_u64_t end_ts  = bpf_ktime_get_ns();
	bpf_u64_t delay_ns = end_ts - v->start_ts;

	// 执行过滤；满足跳过条件则清空标记，直接返回
	if (should_skip(ctrl, v->prev_pid, v->next_pid, delay_ns)) {
		v->start_ts = 0;
		return 0;
	}

	// 向ringbuf申请事件内存
	struct Preempt_event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		// ringbuf缓冲区满，丢弃事件，清空临时存储标记
		v->start_ts = 0;
		return 0;
	}

	// 填充事件字段
	e->ts_ns       = end_ts;
	e->delay_ns    = delay_ns;
	e->cpu         = v->cpu;
	e->prev_pid    = v->prev_pid;
	e->next_pid    = v->next_pid;
	e->prev_tgid   = v->prev_tgid;
	e->next_tgid   = v->next_tgid;
	e->prev_prio   = v->prev_prio;
	e->next_prio   = v->next_prio;
	e->prev_state  = v->prev_state;
	__builtin_memcpy(e->prev_comm, v->prev_comm, TASK_COMM_LEN);
	__builtin_memcpy(e->next_comm, v->next_comm, TASK_COMM_LEN);

	// 提交事件给用户态
	bpf_ringbuf_submit(e, 0);

	/* 更新全局统计指标 */
	struct Preempt_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
	if (stats) {
		stats->count++;                  // 成功上报事件计数
		stats->total_ns += delay_ns;     // 累加总抢占耗时
		// 更新最大耗时记录，同时保存现场信息
		if (delay_ns > stats->max_ns) {
			stats->max_ns = delay_ns;
			stats->max_prev_pid = v->prev_pid;
			stats->max_next_pid = v->next_pid;
			__builtin_memcpy(stats->max_prev_comm, v->prev_comm, TASK_COMM_LEN);
			__builtin_memcpy(stats->max_next_comm, v->next_comm, TASK_COMM_LEN);
		}
	} else {
		// 统计条目不存在，新建初始统计结构写入map
		struct Preempt_stats new_stats = {};
		new_stats.count = 1;
		new_stats.total_ns = delay_ns;
		new_stats.max_ns = delay_ns;
		new_stats.max_prev_pid = v->prev_pid;
		new_stats.max_next_pid = v->next_pid;
		__builtin_memcpy(new_stats.max_prev_comm, v->prev_comm, TASK_COMM_LEN);
		__builtin_memcpy(new_stats.max_next_comm, v->next_comm, TASK_COMM_LEN);
		bpf_map_update_elem(&stats_map, &key, &new_stats, BPF_ANY);
	}

	/* 关键：清空start_ts，标记本条抢占记录消费完成，防止下一轮重复处理旧数据 */
	v->start_ts = 0;
	return 0;
}
