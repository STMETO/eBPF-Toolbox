#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "context_switch.h"
#include "common/pid_namespace.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

struct wakeup_info {
	bpf_u64_t ts_ns;
	bpf_s32_t wakeup_cpu;
};

/* 任务可能在 wakeup 后迁移 CPU，因此必须以 TID 关联，而不能使用 per-CPU 槽。 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, bpf_u64_t);
	__type(value, struct wakeup_info);
} wakeup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct ContextSwitch_ctrl);
} ctrl_map SEC(".maps");

/* 每个 CPU 独立累计，避免热点调度路径上的共享写竞争。 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct ContextSwitch_stats);
} stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline struct ContextSwitch_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
}

static __always_inline struct ContextSwitch_stats *get_stats(void)
{
	return bpf_map_lookup_elem(&stats_map, &ctrl_key);
}

static __always_inline int record_wakeup(struct task_struct *task)
{
	struct ContextSwitch_ctrl *ctrl = get_ctrl();
	struct ContextSwitch_stats *stats;
	struct wakeup_info info = {};
	bpf_s32_t tgid;
	bpf_u64_t task_key;

	if (!ctrl || !ctrl->enable)
		return 0;

	tgid = app_task_tgid_ns(task, ctrl->pid_ns_ino);
	if (!tgid)
		return 0;
	if (ctrl->target_pid && tgid != ctrl->target_pid)
		return 0;

	task_key = (bpf_u64_t)task;
	info.ts_ns = bpf_ktime_get_ns();
	info.wakeup_cpu = bpf_get_smp_processor_id();
	stats = get_stats();
	if (bpf_map_update_elem(&wakeup_map, &task_key, &info, BPF_ANY)) {
		if (stats)
			stats->map_update_failed++;
		return 0;
	}
	if (stats)
		stats->wakeups++;
	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(trace_sched_wakeup, struct task_struct *task)
{
	return record_wakeup(task);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(trace_sched_wakeup_new, struct task_struct *task)
{
	return record_wakeup(task);
}

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

	if (!ctrl || !ctrl->enable)
		return 0;

	next_tid = app_task_tid_ns(next, ctrl->pid_ns_ino);
	next_tgid = app_task_tgid_ns(next, ctrl->pid_ns_ino);
	if (!next_tid || !next_tgid)
		return 0;
	if (ctrl->target_pid && next_tgid != ctrl->target_pid)
		return 0;

	next_key = (bpf_u64_t)next;
	info = bpf_map_lookup_elem(&wakeup_map, &next_key);
	if (!info) {
		if (stats)
			stats->unmatched_switches++;
		return 0;
	}

	now = bpf_ktime_get_ns();
	delay_ns = now - info->ts_ns;
	wakeup_cpu = info->wakeup_cpu;
	bpf_map_delete_elem(&wakeup_map, &next_key);

	if (ctrl->min_delay_ns && delay_ns < ctrl->min_delay_ns) {
		if (stats)
			stats->filtered_delay++;
		return 0;
	}

	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event) {
		if (stats)
			stats->ringbuf_dropped++;
		return 0;
	}

	event->ts_ns = now;
	event->delay_ns = delay_ns;
	event->cpu = bpf_get_smp_processor_id();
	event->wakeup_cpu = wakeup_cpu;
	event->prev_pid = app_task_tid_ns(prev, ctrl->pid_ns_ino);
	event->next_pid = next_tid;
	event->prev_tgid = app_task_tgid_ns(prev, ctrl->pid_ns_ino);
	event->next_tgid = next_tgid;
	event->prev_prio = BPF_CORE_READ(prev, prio);
	event->next_prio = BPF_CORE_READ(next, prio);
	event->prev_state = BPF_CORE_READ(prev, __state);
	event->preempt = preempt;
	bpf_probe_read_kernel_str(event->prev_comm, sizeof(event->prev_comm), prev->comm);
	bpf_probe_read_kernel_str(event->next_comm, sizeof(event->next_comm), next->comm);

	if (stats) {
		stats->count++;
		stats->total_ns += delay_ns;
		if (delay_ns > stats->max_ns) {
			stats->max_ns = delay_ns;
			stats->max_prev_pid = event->prev_pid;
			stats->max_next_pid = event->next_pid;
			__builtin_memcpy(stats->max_prev_comm, event->prev_comm, TASK_COMM_LEN);
			__builtin_memcpy(stats->max_next_comm, event->next_comm, TASK_COMM_LEN);
		}
	}

	bpf_ringbuf_submit(event, 0);
	return 0;
}
