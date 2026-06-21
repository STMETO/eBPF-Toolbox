#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "SysStat.h"
char LICENSE[] SEC("license") = "Dual BSD/GPL";
const int ctrl_key = 0;
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
	__type(key, int); __type(value, struct SysStat_ctrl);
} ctrl_map SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256 * 1024);
} rb SEC(".maps");
static __always_inline struct SysStat_ctrl *get_ctrl(void)
{ return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key); }

SEC("kprobe/get_page_from_freelist")
int BPF_KPROBE(get_page_from_freelist_second, gfp_t gfp_mask, unsigned int order,
	       int alloc_flags, const struct alloc_context *ac)
{
	struct SysStat_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable) return 0;
	struct SysStat_event *e;
	unsigned long *t = (unsigned long *)BPF_CORE_READ(ac, preferred_zoneref, zone, zone_pgdat, vm_stat);

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;

	e->anon_inactive = t[0] * 4;  e->anon_active = t[1] * 4;
	e->file_inactive = t[2] * 4;  e->file_active = t[3] * 4;
	e->unevictable = t[4] * 4;
	e->slab_reclaimable = t[5] * 4; e->slab_unreclaimable = t[6] * 4;
	e->file_dirty = t[20] * 4;  e->writeback = t[21] * 4;
	e->writeback_temp = t[22] * 4; e->shmem = t[23] * 4;
	e->shmem_thps = t[24] * 4;  e->pmdmapped = t[25] * 4;
	e->anon_thps = t[26] * 4;   e->unstable_nfs = t[27] * 4;
	e->anon_mapped = t[17] * 4; e->file_mapped = t[18] * 4;
	e->kernel_misc_reclaimable = t[29] * 4;

	bpf_ringbuf_submit(e, 0);
	return 0;
}
