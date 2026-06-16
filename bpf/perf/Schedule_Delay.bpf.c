// eBPF程序必须包含的内核类型定义
#include <vmlinux.h>

// eBPF核心帮助函数库
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// 包含我们自己定义的共用结构体
#include "Schedule_Delay.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ========================== 全局常量定义 ==========================
const int ctrl_key = 0;

// ========================== 内部结构体定义 ==========================

/*
 * 进程调度事件结构体（内部使用）
 * 记录进程进入就绪队列时的信息
 */
struct schedule_event {
	bpf_s32_t pid;           // 进程 PID
	bpf_s32_t count;         // 调度次数
	bpf_u64_t enter_time;    // 进入就绪队列的时间戳（纳秒）
};

// ========================== eBPF MAP 定义 ==========================

/*
 * 1. 进程是否已调度过 map
 * key：proc_id  value：bool
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct Schedule_Delay_proc_id);
	__type(value, bpf_bool_t);
} has_scheduled SEC(".maps");

/*
 * 2. 进程进入就绪队列时间 map
 * key：proc_id  value：struct schedule_event
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct Schedule_Delay_proc_id);
	__type(value, struct schedule_event);
} enter_schedule SEC(".maps");

/*
 * 3. 系统全局调度统计 map
 * key：固定 0  value：struct Schedule_Delay_sum_schedule
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Schedule_Delay_sum_schedule);
} sys_schedule SEC(".maps");

/*
 * 4. 最近一次调度延迟信息 map
 * key：固定 0  value：struct Schedule_Delay_proc_schedule
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Schedule_Delay_proc_schedule);
} threshold_schedule SEC(".maps");

/*
 * 5. 进程调度历史 map
 * key：proc_id  value：struct Schedule_Delay_proc_history
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct Schedule_Delay_proc_id);
	__type(value, struct Schedule_Delay_proc_history);
} proc_histories SEC(".maps");

/*
 * 6. 全局控制 map
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Schedule_Delay_ctrl);
} ctrl_map SEC(".maps");

// ========================== 工具函数 ==========================

static inline struct Schedule_Delay_ctrl *get_ctrl(void)
{
	struct Schedule_Delay_ctrl *ctrl;
	ctrl = bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
	if (!ctrl || !ctrl->enable)
		return NULL;
	return ctrl;
}

// ========================== 挂载点 ==========================

/*
 * tp_btf/sched_wakeup
 * 触发时机：进程被唤醒（从睡眠→就绪）
 * 作用：记录进程进入调度队列的时间
 */
SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup_trace, struct task_struct *p)
{
	struct Schedule_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	bpf_s32_t pid = (bpf_s32_t)BPF_CORE_READ(p, pid);
	int cpu = bpf_get_smp_processor_id();
	bpf_u64_t current_time = bpf_ktime_get_ns();

	struct Schedule_Delay_proc_id id = {};
	id.pid = pid;
	if (pid == 0)
		id.cpu_id = cpu;

	struct schedule_event *event;
	event = bpf_map_lookup_elem(&enter_schedule, &id);
	if (!event) {
		struct schedule_event new_event;
		bpf_bool_t issched = false;
		new_event.pid = pid;
		new_event.count = 1;
		new_event.enter_time = current_time;
		bpf_map_update_elem(&has_scheduled, &id, &issched, BPF_ANY);
		bpf_map_update_elem(&enter_schedule, &id, &new_event, BPF_ANY);
	} else {
		event->enter_time = current_time;
	}
	return 0;
}

/*
 * tp_btf/sched_wakeup_new
 * 触发时机：新进程第一次被唤醒
 * 作用：记录新进程进入就绪队列的时间
 */
SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new_trace, struct task_struct *p)
{
	struct Schedule_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	bpf_s32_t pid = (bpf_s32_t)BPF_CORE_READ(p, pid);
	int cpu = bpf_get_smp_processor_id();
	bpf_u64_t current_time = bpf_ktime_get_ns();

	struct Schedule_Delay_proc_id id = {};
	id.pid = pid;
	if (pid == 0)
		id.cpu_id = cpu;

	struct schedule_event new_event;
	bpf_bool_t issched = false;
	new_event.pid = pid;
	new_event.count = 1;
	new_event.enter_time = current_time;
	bpf_map_update_elem(&has_scheduled, &id, &issched, BPF_ANY);
	bpf_map_update_elem(&enter_schedule, &id, &new_event, BPF_ANY);
	return 0;
}

/*
 * tp_btf/sched_switch
 * 触发时机：CPU 发生进程切换
 * 作用：计算调度延迟 + 统计系统调度数据 + 记录切换上下文
 */
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch_trace, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	struct Schedule_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	bpf_u64_t current_time = bpf_ktime_get_ns();
	bpf_s32_t prev_pid = (bpf_s32_t)BPF_CORE_READ(prev, pid);
	unsigned int prev_state = BPF_CORE_READ(prev, __state);
	int prev_cpu = bpf_get_smp_processor_id();
	bpf_s32_t next_pid = (bpf_s32_t)BPF_CORE_READ(next, pid);
	int key = 0;

	// --- 处理被换下的进程 prev ---
	// prev 还是 TASK_RUNNING → 被抢占 → 重新记录入队时间
	if (prev_state == TASK_RUNNING) {
		struct Schedule_Delay_proc_id prev_pd = {};
		prev_pd.pid = prev_pid;
		if (prev_pid == 0)
			prev_pd.cpu_id = prev_cpu;

		struct schedule_event *event;
		event = bpf_map_lookup_elem(&enter_schedule, &prev_pd);
		if (!event) {
			struct schedule_event new_event;
			bpf_bool_t issched = false;
			new_event.pid = prev_pid;
			new_event.count = 1;
			new_event.enter_time = current_time;
			bpf_map_update_elem(&has_scheduled, &prev_pd, &issched, BPF_ANY);
			bpf_map_update_elem(&enter_schedule, &prev_pd, &new_event, BPF_ANY);
		} else {
			event->enter_time = current_time;
		}
	}

	// --- 处理即将运行的进程 next ---
	struct Schedule_Delay_proc_id next_id = {};
	next_id.pid = next_pid;
	if (next_pid == 0)
		next_id.cpu_id = prev_cpu;

	struct schedule_event *event;
	event = bpf_map_lookup_elem(&enter_schedule, &next_id);
	if (!event)
		return 0;

	bpf_bool_t *issched = bpf_map_lookup_elem(&has_scheduled, &next_id);
	if (!issched)
		return 0;

	if (*issched) {
		event->count++;
	} else {
		*issched = true;
	}

	// --- 计算调度延迟 ---
	bpf_u64_t delay = current_time - event->enter_time;

	// --- 更新最近一次调度延迟信息 ---
	struct Schedule_Delay_proc_schedule proc_schedule;
	proc_schedule.delay = delay;
	proc_schedule.id = next_id;
	bpf_probe_read_kernel_str(&proc_schedule.proc_name,
				  sizeof(proc_schedule.proc_name), next->comm);
	bpf_map_update_elem(&threshold_schedule, &key, &proc_schedule, BPF_ANY);

	// --- 统计全局系统调度数据 ---
	struct Schedule_Delay_sum_schedule *sum;
	sum = bpf_map_lookup_elem(&sys_schedule, &key);
	if (!sum) {
		struct Schedule_Delay_sum_schedule new_sum = {};
		new_sum.sum_count = 1;
		new_sum.sum_delay = delay;
		new_sum.max_delay = delay;
		if (next_pid != 0) {
			bpf_probe_read_kernel_str(&new_sum.proc_name_max,
				sizeof(new_sum.proc_name_max), next->comm);
		}
		if (delay < new_sum.min_delay || new_sum.min_delay == 0) {
			new_sum.min_delay = delay;
			if (next_pid != 0) {
				bpf_probe_read_kernel_str(&new_sum.proc_name_min,
					sizeof(new_sum.proc_name_min), next->comm);
			}
		}
		bpf_map_update_elem(&sys_schedule, &key, &new_sum, BPF_ANY);
	} else {
		sum->sum_count++;
		sum->sum_delay += delay;
		if (delay > sum->max_delay) {
			sum->max_delay = delay;
			bpf_probe_read_kernel_str(&sum->proc_name_max,
				sizeof(sum->proc_name_max), next->comm);
		} else if (sum->min_delay == 0 || delay < sum->min_delay) {
			sum->min_delay = delay;
			if (next_pid != 0) {
				bpf_probe_read_kernel_str(&sum->proc_name_min,
					sizeof(sum->proc_name_min), next->comm);
			}
		}
	}

	// --- 记录进程切换历史 ---
	struct Schedule_Delay_proc_history new_history;
	struct Schedule_Delay_proc_history *history;
	history = bpf_map_lookup_elem(&proc_histories, &next_id);
	if (history) {
		new_history.last[0] = history->last[1];
		new_history.last[1].pid = prev_pid;
		bpf_probe_read_kernel_str(&new_history.last[1].comm,
			sizeof(new_history.last[1].comm), prev->comm);
		bpf_map_update_elem(&proc_histories, &next_id, &new_history, BPF_ANY);
	} else {
		new_history.last[0].pid = 0;
		new_history.last[0].comm[0] = '\0';
		new_history.last[1].pid = prev_pid;
		bpf_probe_read_kernel_str(&new_history.last[1].comm,
			sizeof(new_history.last[1].comm), prev->comm);
		bpf_map_update_elem(&proc_histories, &next_id, &new_history, BPF_ANY);
	}
	return 0;
}

/*
 * tracepoint/sched/sched_process_exit
 * 触发时机：进程退出时
 * 作用：清理该进程在 BPF map 中的监控数据
 */
SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit_trace(void *ctx)
{
	struct Schedule_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	struct task_struct *p = (struct task_struct *)bpf_get_current_task();
	bpf_s32_t pid = (bpf_s32_t)BPF_CORE_READ(p, pid);
	int cpu = bpf_get_smp_processor_id();

	struct Schedule_Delay_proc_id id = {};
	id.pid = pid;
	if (pid == 0)
		id.cpu_id = cpu;

	bpf_map_delete_elem(&enter_schedule, &id);
	bpf_map_delete_elem(&has_scheduled, &id);
	return 0;
}
