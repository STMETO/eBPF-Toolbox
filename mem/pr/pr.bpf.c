#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "pr.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Pr_ctrl);
} ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline struct Pr_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
}

SEC("kprobe/shrink_page_list")
int BPF_KPROBE(shrink_page_list, struct list_head *page_list,
	       struct pglist_data *pgdat, struct scan_control *sc)
{
	struct Pr_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	struct Pr_event *e;
	unsigned long y;
	unsigned int *a;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->reclaim = BPF_CORE_READ(sc, nr_to_reclaim);
	y = BPF_CORE_READ(sc, nr_reclaimed);
	e->reclaimed = y;
	a = (unsigned int *)(&y + 1);
	e->unqueued_dirty = *(a + 1);
	e->congested = *(a + 2);
	e->writeback = *(a + 3);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
