#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "dr_snoop.h"
#include "common/pid_namespace.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
const int ctrl_key = 0;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, bpf_u64_t);
	__type(value, struct val_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct DrSnoop_ctrl);
} ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct DrSnoop_stats);
} stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct trace_event_raw_mm_vmscan_direct_reclaim_end_template___local {
	unsigned long nr_reclaimed;
} __attribute__((preserve_access_index));

static __always_inline struct DrSnoop_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
}

static __always_inline struct DrSnoop_stats *get_stats(void)
{
	return bpf_map_lookup_elem(&stats_map, &ctrl_key);
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin")
int trace_direct_reclaim_begin(void *ctx)
{
	struct DrSnoop_ctrl *ctrl = get_ctrl();
	struct DrSnoop_stats *stats;
	struct val_t val = {};
	bpf_u64_t id;
	bpf_s32_t tgid;

	(void)ctx;
	if (!ctrl || !ctrl->enable)
		return 0;
	id = app_current_pid_tgid_ns(ctrl->pid_ns_dev, ctrl->pid_ns_ino);
	if (!id)
		return 0;
	tgid = (bpf_s32_t)(id >> 32);
	if (ctrl->target_pid && ctrl->target_pid != tgid)
		return 0;

	stats = get_stats();
	if (stats)
		stats->attempted++;
	val.id = id;
	val.ts = bpf_ktime_get_ns();
	bpf_get_current_comm(val.name, sizeof(val.name));
	if (bpf_map_update_elem(&start, &id, &val, BPF_ANY) && stats)
		stats->map_update_failed++;
	return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_end")
int trace_direct_reclaim_end(void *ctx)
{
	struct trace_event_raw_mm_vmscan_direct_reclaim_end_template___local *args = ctx;
	struct DrSnoop_ctrl *ctrl = get_ctrl();
	struct DrSnoop_stats *stats = get_stats();
	struct val_t *val;
	struct data_t *event;
	bpf_u64_t id;
	bpf_u64_t now, delay_ns, reclaimed;
	bpf_s32_t tgid;

	if (!ctrl)
		return 0;
	id = app_current_pid_tgid_ns(ctrl->pid_ns_dev, ctrl->pid_ns_ino);
	if (!id)
		return 0;
	tgid = (bpf_s32_t)(id >> 32);

	val = bpf_map_lookup_elem(&start, &id);
	if (!val) {
		if (ctrl && ctrl->enable && stats &&
		    (!ctrl->target_pid || ctrl->target_pid == tgid))
			stats->lookup_missed++;
		return 0;
	}

	if (!ctrl || !ctrl->enable ||
	    (ctrl->target_pid && ctrl->target_pid != tgid)) {
		bpf_map_delete_elem(&start, &id);
		return 0;
	}

	now = bpf_ktime_get_ns();
	delay_ns = now - val->ts;
	reclaimed = BPF_CORE_READ(args, nr_reclaimed);
	if (stats) {
		stats->completed++;
		stats->total_ns += delay_ns;
		stats->total_reclaimed += reclaimed;
		if (delay_ns > stats->max_ns) {
			stats->max_ns = delay_ns;
			stats->max_pid = tgid;
			__builtin_memcpy(stats->max_comm, val->name, TASK_COMM_LEN);
		}
	}

	if (ctrl->min_delay_ns && delay_ns < ctrl->min_delay_ns) {
		if (stats)
			stats->filtered_delay++;
		bpf_map_delete_elem(&start, &id);
		return 0;
	}

	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event) {
		if (stats)
			stats->ringbuf_dropped++;
		bpf_map_delete_elem(&start, &id);
		return 0;
	}
	event->id = val->id;
	event->delta = delay_ns;
	event->ts_ns = now;
	event->nr_reclaimed = reclaimed;
	__builtin_memcpy(event->name, val->name, TASK_COMM_LEN);
	bpf_ringbuf_submit(event, 0);
	bpf_map_delete_elem(&start, &id);
	return 0;
}
