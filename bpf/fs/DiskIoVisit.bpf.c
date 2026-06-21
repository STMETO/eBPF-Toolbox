#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "DiskIoVisit.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct DiskIoVisit_ctrl);
} ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, char[TASK_COMM_LEN]);
	__type(value, u32);
} io_count_map SEC(".maps");

static __always_inline struct DiskIoVisit_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
}

SEC("tracepoint/block/block_rq_complete")
int tracepoint_block_visit(struct trace_event_raw_block_rq_completion *ctx)
{
	struct DiskIoVisit_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	struct DiskIoVisit_event *e;
	u32 *count, new_count;
	char comm[TASK_COMM_LEN];

	bpf_get_current_comm(comm, sizeof(comm));

	count = bpf_map_lookup_elem(&io_count_map, comm);
	if (count)
		new_count = *count + 1;
	else
		new_count = 1;
	bpf_map_update_elem(&io_count_map, comm, &new_count, BPF_ANY);

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->timestamp = bpf_ktime_get_ns();
	e->blk_dev = ctx->dev;
	e->sectors = ctx->nr_sector;
	e->rwbs = (ctx->rwbs[0] == 'R') ? 1 : 0;
	e->count = new_count;
	__builtin_memcpy(e->comm, comm, sizeof(comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
