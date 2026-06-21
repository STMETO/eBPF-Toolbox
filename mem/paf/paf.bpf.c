#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "paf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Paf_ctrl);
} ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline struct Paf_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
}

SEC("kprobe/get_page_from_freelist")
int BPF_KPROBE(get_page_from_freelist, gfp_t gfp_mask, unsigned int order,
	       int alloc_flags, const struct alloc_context *ac)
{
	struct Paf_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	struct Paf_event *e;
	unsigned long boost, min, low, high;

	boost = BPF_CORE_READ(ac, preferred_zoneref, zone, watermark_boost);
	min = BPF_CORE_READ(ac, preferred_zoneref, zone, _watermark[0]);
	low = BPF_CORE_READ(ac, preferred_zoneref, zone, _watermark[1]);
	high = BPF_CORE_READ(ac, preferred_zoneref, zone, _watermark[2]);

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->present = BPF_CORE_READ(ac, preferred_zoneref, zone, present_pages);
	e->min = min + boost;
	e->low = low + boost;
	e->high = high + boost;
	e->flag = (int)gfp_mask;

	bpf_ringbuf_submit(e, 0);
	return 0;
}
