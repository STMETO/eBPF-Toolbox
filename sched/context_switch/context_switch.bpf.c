/*
流程：
	线程 A 阻塞睡眠，之后条件满足 → 内核触发 sched_wakeup；
	BPF 捕获 wakeup，保存：task_struct指针、唤醒时间、唤醒CPU 存入 wakeup_map；
	线程 A 进入就绪队列排队等待 CPU；
	一段时间后 CPU 发生上下文切换，调度器选中线程 A 运行，触发 sched_switch；
	在 sched_switch 探针中，通过 next 任务的 task_struct 去 map 查找唤醒记录；
	delay = 当前时间 - 唤醒时间，得到调度延迟（runqueue 排队时长）；
	超过阈值则封装事件发送 Ringbuf 给用户态；
	任务退出时sched_process_exit主动清理 map，防止指针复用 bug。
*/

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "context_switch.h"
#include "common/pid_namespace.bpf.h"

/**
 * @brief BPF程序许可证，Dual BSD/GPL 允许使用tracepoint、kprobe等追踪功能
 */
char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

/**
 * @brief 唤醒记录：保存任务被唤醒时的快照信息
 */
struct wakeup_info {
	bpf_u64_t ts_ns;        // 任务唤醒时刻时间戳(ktime)
	bpf_s32_t wakeup_cpu;   // 任务唤醒时所在CPU（任务后续可能迁移CPU）
};

/**
 * @brief wakeup_map：关联【task_struct指针】与唤醒时间戳
 * MAP类型：LRU_HASH（超出max_entries自动淘汰旧条目，防止内存溢出）
 * key：task_struct* 地址转为u64
 * value：wakeup_info 唤醒快照
 *
 * 【设计理由注释】
 * 1. 任务唤醒后可能发生CPU迁移，因此不能使用per-CPU临时存储；
 * 2. 不使用PID作为key：不同PID Namespace内PID数字会冲突；
 * 3. 使用task_struct指针作为唯一标识；
 * 4. 风险：task_struct地址在内核slab复用；因此注册 sched_process_exit 探针，
 *    进程退出时主动删除map内条目，避免旧数据干扰新复用task_struct。
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, bpf_u64_t);
	__type(value, struct wakeup_info);
} wakeup_map SEC(".maps");

/**
 * @brief ctrl_map：全局控制参数数组
 * 用户态下发配置：采集开关、目标PID、最小延迟阈值、目标pidns inode等
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct ContextSwitch_ctrl);
} ctrl_map SEC(".maps");

/**
 * @brief stats_map：Per-CPU统计数据
 * 使用PERCPU_ARRAY，各个CPU独立写统计值，调度热点路径避免原子操作竞争，提升性能
 * 用户态退出时聚合所有CPU数据输出汇总报表
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct ContextSwitch_stats);
} stats_map SEC(".maps");

/**
 * @brief rb：环形缓冲区，内核向用户态推送调度延迟事件
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
 * @brief 获取全局控制配置结构体
 * @return 成功返回指针；配置不存在/未初始化返回NULL
 */
static __always_inline struct ContextSwitch_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
}

/**
 * @brief 获取当前CPU独立统计指标
 * @return 当前CPU的统计结构体指针
 */
static __always_inline struct ContextSwitch_stats *get_stats(void)
{
	return bpf_map_lookup_elem(&stats_map, &ctrl_key);
}

/**
 * @brief 记录任务唤醒事件，写入wakeup_map
 * @param task 被唤醒的任务task_struct指针
 * @return 固定返回0
 *
 * 执行流程：
 * 1. 判断采集开关是否开启
 * 2. 将task转换为目标namespace内TGID；不在目标ns直接过滤
 * 3. 如果配置target_pid，非目标进程直接过滤
 * 4. 记录唤醒时间戳、唤醒CPU，存入wakeup_map
 */
static __always_inline int record_wakeup(struct task_struct *task)
{
	struct ContextSwitch_ctrl *ctrl = get_ctrl();
	struct ContextSwitch_stats *stats;
	struct wakeup_info info = {};
	bpf_s32_t tgid;
	bpf_u64_t task_key;

	// 未启用采集，直接返回
	if (!ctrl || !ctrl->enable)
		return 0;

	// 转换为目标pidns内TGID；不在目标namespace返回0，丢弃事件
	tgid = app_task_tgid_ns(task, ctrl->pid_ns_ino);
	if (!tgid)
		return 0;
	// 设置了目标进程过滤，当前任务不匹配则丢弃
	if (ctrl->target_pid && tgid != ctrl->target_pid)
		return 0;

	// 使用task_struct地址作为哈希表key
	task_key = (bpf_u64_t)task;
	info.ts_ns = bpf_ktime_get_ns();        // 获取内核单调时钟
	info.wakeup_cpu = bpf_get_smp_processor_id(); // 获取当前CPU编号
	stats = get_stats();

	// 将唤醒信息写入hash表，BPF_ANY：存在则覆盖，不存在新增
	if (bpf_map_update_elem(&wakeup_map, &task_key, &info, BPF_ANY)) {
		if (stats)
			stats->map_update_failed++; // map更新失败计数
		return 0;
	}
	if (stats)
		stats->wakeups++; // 成功记录唤醒次数统计
	return 0;
}

/**
 * @brief tracepoint：sched_wakeup
 * 触发时机：任务被唤醒，进入就绪队列（常规唤醒，磁盘IO、futex唤醒等）
 * BPF_PROG：tp_btf类型tracepoint，依靠BTF自动填充task参数
 */
SEC("tp_btf/sched_wakeup")
int BPF_PROG(trace_sched_wakeup, struct task_struct *task)
{
	return record_wakeup(task);
}

/**
 * @brief tracepoint：sched_wakeup_new
 * 触发时机：新创建进程唤醒（clone创建任务）
 * 需要单独捕获，否则新建任务的唤醒事件会丢失
 */
SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(trace_sched_wakeup_new, struct task_struct *task)
{
	return record_wakeup(task);
}

/**
 * @brief tracepoint：sched_process_exit
 * 触发时机：进程/线程退出销毁
 * 功能：清理wakeup_map残留条目，防止task_struct地址复用造成数据错乱
 */
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx)
{
	/*
	 * tracepoint上下文中 bpf_get_current_task() = 当前正在退出的任务
	 */
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	bpf_u64_t task_key = (bpf_u64_t)task;

	(void)ctx;
	/*
	 * bpf_map_delete_elem 对不存在的key是安全的，不会报错；
	 * 省去一次lookup操作，减少退出路径上的开销
	 */
	bpf_map_delete_elem(&wakeup_map, &task_key);
	return 0;
}

/**
 * @brief tracepoint：sched_switch
 * 触发时机：CPU上下文切换
 * 参数说明：
 * preempt：true=本次切换是抢占触发；false=任务主动放弃CPU/时间片耗尽
 * prev：即将让出CPU的任务
 * next：即将获得CPU运行的任务
 *
 * 核心逻辑：
 * 查找next任务对应的唤醒记录，计算【调度延迟】=切换时刻 - 唤醒时刻
 * 阈值过滤后，组装事件通过ringbuf发给用户态
 */
SEC("tp_btf/sched_switch")
int BPF_PROG(trace_sched_switch, bool preempt,
	     struct task_struct *prev, struct task_struct *next)
{
	struct ContextSwitch_ctrl *ctrl = get_ctrl();
	struct ContextSwitch_stats *stats = get_stats();
	struct wakeup_info *info;
	struct ContextSwitch_event *event;
	bpf_u64_t now, delay_ns;
	bpf_s32_t next_tgid;
	bpf_s32_t next_tid;
	bpf_u64_t next_key;
	bpf_s32_t wakeup_cpu;

	// 采集未开启，直接返回
	if (!ctrl || !ctrl->enable)
		return 0;

	// 把即将运行的next任务PID转换为目标namespace内TID、TGID
	next_tid = app_task_tid_ns(next, ctrl->pid_ns_ino);
	next_tgid = app_task_tgid_ns(next, ctrl->pid_ns_ino);
	// 任务不在目标namespace，丢弃
	if (!next_tid || !next_tgid)
		return 0;
	// 设置目标进程过滤，不匹配直接丢弃
	if (ctrl->target_pid && next_tgid != ctrl->target_pid)
		return 0;

	next_key = (bpf_u64_t)next;
	// 查询该任务是否存在唤醒记录
	info = bpf_map_lookup_elem(&wakeup_map, &next_key);
	if (!info) {
		/*
		 * 两种常见情况：
		 * 1. 任务启动后一直运行，从未睡眠唤醒（无wakeup事件）
		 * 2. wakeup记录被LRU哈希淘汰 / 进程退出提前清理
		 */
		if (stats)
			stats->unmatched_switches++;
		return 0;
	}

	now = bpf_ktime_get_ns();
	// 计算调度延迟：任务从唤醒就绪 → 真正拿到CPU运行的等待时长
	delay_ns = now - info->ts_ns;
	wakeup_cpu = info->wakeup_cpu;

	/*
	 * 【关键设计】找到记录立刻删除
	 * 无论后续是否满足阈值、ringbuf是否满，都清理条目；
	 * 避免条目常驻map，LRU持续占用资源；防止同一条唤醒记录重复匹配多次切换事件
	 */
	bpf_map_delete_elem(&wakeup_map, &next_key);

	// 最小延迟阈值过滤：延迟太短，不向上发送事件
	if (ctrl->min_delay_ns && delay_ns < ctrl->min_delay_ns) {
		if (stats)
			stats->filtered_delay++;
		return 0;
	}

	// 向ringbuf申请一块内存存放事件
	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event) {
		// ringbuf缓冲区满，内核丢弃事件
		if (stats)
			stats->ringbuf_dropped++;
		return 0;
	}

	// 填充事件所有字段
	event->ts_ns = now;                     // 上下文切换发生时间
	event->delay_ns = delay_ns;             // 调度延迟（核心指标）
	event->cpu = bpf_get_smp_processor_id();// 当前执行上下文切换的CPU
	event->wakeup_cpu = wakeup_cpu;         // 任务当初被唤醒的CPU（可观察跨核迁移）

	// prev：让出CPU的进程；next：获得CPU的进程，全部转换容器内PID
	event->prev_pid = app_task_tid_ns(prev, ctrl->pid_ns_ino);
	event->next_pid = next_tid;
	event->prev_tgid = app_task_tgid_ns(prev, ctrl->pid_ns_ino);
	event->next_tgid = next_tgid;

	event->prev_prio = BPF_CORE_READ(prev, prio); // 旧任务调度优先级
	event->next_prio = BPF_CORE_READ(next, prio); // 新任务调度优先级
	event->prev_state = BPF_CORE_READ(prev, __state); // prev任务切换前状态
	event->preempt = preempt;                     // 是否抢占式切换

	// 读取进程名称 comm
	bpf_probe_read_kernel_str(event->prev_comm, sizeof(event->prev_comm), prev->comm);
	bpf_probe_read_kernel_str(event->next_comm, sizeof(event->next_comm), next->comm);

	if (stats) {
		stats->count++;                // 成功上报事件计数
		stats->total_ns += delay_ns;   // 累计总调度延迟，用于计算平均值
		// 更新全局最大延迟记录，保存现场信息，用于用户态统计面板
		if (delay_ns > stats->max_ns) {
			stats->max_ns = delay_ns;
			stats->max_prev_pid = event->prev_pid;
			stats->max_next_pid = event->next_pid;
			__builtin_memcpy(stats->max_prev_comm, event->prev_comm, TASK_COMM_LEN);
			__builtin_memcpy(stats->max_next_comm, event->next_comm, TASK_COMM_LEN);
		}
	}

	// 将事件提交ringbuf，用户态程序可以读取
	bpf_ringbuf_submit(event, 0);
	return 0;
}
