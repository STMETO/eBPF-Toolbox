#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "preempt.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

/* ── PERCPU 中间存储 ─────────────────────────────────────── */
struct start_val {
	bpf_s32_t prev_pid, next_pid;
	bpf_s32_t prev_tgid, next_tgid;
	bpf_s32_t prev_prio, next_prio;
	bpf_s32_t prev_state, cpu;
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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Preempt_ctrl);
} ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Preempt_stats);
} stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static inline struct Preempt_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
}

static inline bool should_skip(struct Preempt_ctrl *ctrl,
			       bpf_s32_t prev_pid, bpf_s32_t next_pid,
			       bpf_u64_t delay_ns)
{
	if (!ctrl || !ctrl->enable) return true;
	if (ctrl->target_pid != 0 &&
	    prev_pid != ctrl->target_pid && next_pid != ctrl->target_pid)
		return true;
	if (ctrl->min_delay_ns != 0 && delay_ns < ctrl->min_delay_ns)
		return true;
	return false;
}

/* ── tp_btf/sched_switch：只记录抢占切换 ──────────────────── */
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch_preempt, bool preempt,
	     struct task_struct *prev, struct task_struct *next)
{
	struct Preempt_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable || !preempt)	// 只监控preempt = true的情况，即抢占情况
		return 0;

	int key = 0;
	struct start_val *v = bpf_map_lookup_elem(&start_map, &key);
	if (!v) return 0;

	v->start_ts    = bpf_ktime_get_ns();
	v->cpu         = bpf_get_smp_processor_id();

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

/* ── 计算延迟、过滤、发送 ────────────────────────────────── */
SEC("kprobe/finish_task_switch.isra.0")
int BPF_KPROBE(finish_task_switch, struct task_struct *prev)
{
	struct Preempt_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable) return 0;

	int key = 0;
	struct start_val *v = bpf_map_lookup_elem(&start_map, &key);
	if (!v || v->start_ts == 0) return 0;

	bpf_u64_t end_ts  = bpf_ktime_get_ns();
	bpf_u64_t delay_ns = end_ts - v->start_ts;

	if (should_skip(ctrl, v->prev_pid, v->next_pid, delay_ns)) {
		v->start_ts = 0;
		return 0;
	}

	struct Preempt_event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) { v->start_ts = 0; return 0; }

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

	bpf_ringbuf_submit(e, 0);

	/* 统计 */
	struct Preempt_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
	if (stats) {
		stats->count++;
		stats->total_ns += delay_ns;
		if (delay_ns > stats->max_ns) {
			stats->max_ns = delay_ns;
			stats->max_prev_pid = v->prev_pid;
			stats->max_next_pid = v->next_pid;
			__builtin_memcpy(stats->max_prev_comm, v->prev_comm, TASK_COMM_LEN);
			__builtin_memcpy(stats->max_next_comm, v->next_comm, TASK_COMM_LEN);
		}
	} else {
		struct Preempt_stats new_stats = {};
		new_stats.count = 1; new_stats.total_ns = delay_ns;
		new_stats.max_ns = delay_ns;
		new_stats.max_prev_pid = v->prev_pid;
		new_stats.max_next_pid = v->next_pid;
		__builtin_memcpy(new_stats.max_prev_comm, v->prev_comm, TASK_COMM_LEN);
		__builtin_memcpy(new_stats.max_next_comm, v->next_comm, TASK_COMM_LEN);
		bpf_map_update_elem(&stats_map, &key, &new_stats, BPF_ANY);
	}

	v->start_ts = 0;
	return 0;
}
