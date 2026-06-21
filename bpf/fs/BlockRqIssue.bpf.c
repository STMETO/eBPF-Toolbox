#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "BlockRqIssue.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct BlockRqIssue_ctrl);
} ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, u64);
} io_size_map SEC(".maps");

static __always_inline struct BlockRqIssue_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
}

SEC("tracepoint/block/block_rq_issue")
int tracepoint_block_rq_issue(struct trace_event_raw_block_rq_completion *ctx)
{
	struct BlockRqIssue_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	struct BlockRqIssue_event *e;
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u64 *size, total_size;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	bpf_get_current_comm(e->comm, sizeof(e->comm));

	e->timestamp = bpf_ktime_get_ns();
	e->dev = ctx->dev;
	e->sector = ctx->sector;
	e->nr_sectors = ctx->nr_sector;

	size = bpf_map_lookup_elem(&io_size_map, &pid);
	total_size = size ? *size : 0;

	const u64 sector_size = 512;
	total_size += ctx->nr_sector * sector_size;
	bpf_map_update_elem(&io_size_map, &pid, &total_size, BPF_ANY);

	e->total_io = total_size;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
