#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "syscall.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
const int ctrl_key = 0;

struct start_val { bpf_u64_t start_ts; bpf_s32_t syscall_id; };

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
	__type(key, int); __type(value, struct start_val);
} enter_map SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
	__type(key, int); __type(value, struct Syscall_ctrl);
} ctrl_map SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
	__type(key, int); __type(value, struct Syscall_stats);
} stats_map SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static inline struct Syscall_ctrl *get_ctrl(void)
{ return bpf_map_lookup_elem(&ctrl_map, &ctrl_key); }

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_enter(struct trace_event_raw_sys_enter *args)
{
	struct Syscall_ctrl *c = get_ctrl();
	if (!c || !c->enable) return 0;
	struct start_val *v = bpf_map_lookup_elem(&enter_map, &ctrl_key);
	if (!v) return 0;
	v->start_ts   = bpf_ktime_get_ns() / 1000;
	v->syscall_id = (bpf_s32_t)args->id;
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_exit(struct trace_event_raw_sys_exit *args)
{
	struct Syscall_ctrl *c = get_ctrl();
	if (!c || !c->enable) return 0;
	struct start_val *v = bpf_map_lookup_elem(&enter_map, &ctrl_key);
	if (!v || v->start_ts == 0) return 0;

	bpf_u64_t now   = bpf_ktime_get_ns() / 1000;
	bpf_u64_t delay = now - v->start_ts;
	v->start_ts = 0;

	u64 pt      = bpf_get_current_pid_tgid();
	bpf_s32_t pid = (bpf_s32_t)(pt >> 32);
	bpf_s32_t tid = (bpf_s32_t)(pt & 0xFFFFFFFF);

	if (c->target_pid != 0 && pid != c->target_pid) return 0;
	if (c->min_delay_ns && delay * 1000 < c->min_delay_ns) return 0;

	struct Syscall_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;
	e->ts_ns      = now;
	e->delay_ns   = delay;
	e->pid        = pid;
	e->tid        = tid;
	e->syscall_id = v->syscall_id;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* 统计：在 ringbuf_submit 前读 e->comm */
	struct Syscall_stats *st = bpf_map_lookup_elem(&stats_map, &ctrl_key);
	if (!st) {
		struct Syscall_stats z = {};
		bpf_map_update_elem(&stats_map, &ctrl_key, &z, BPF_ANY);
		st = bpf_map_lookup_elem(&stats_map, &ctrl_key);
	}
	if (st) {
		st->count++;
		st->total_ns += delay;
		if (delay > st->max_ns) {
			st->max_ns        = delay;
			st->max_pid       = pid;
			st->max_syscall_id = v->syscall_id;
			__builtin_memcpy(st->max_comm, e->comm, TASK_COMM_LEN);
		}
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}
