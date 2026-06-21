#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "slab_rate.h"
#define MAX_ENTRIES 10240
char LICENSE[] SEC("license") = "Dual BSD/GPL";
const int ctrl_key = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct SlabRate_ctrl);
} ctrl_map SEC(".maps");

static struct SlabRate_info zero_value = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, char *);
	__type(value, struct SlabRate_info);
} slab_entries SEC(".maps");

static __always_inline struct SlabRate_ctrl *get_ctrl(void)
{ return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key); }

static int probe_entry(struct kmem_cache *cachep)
{
	struct SlabRate_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable) return 0;

	struct SlabRate_info *vp;
	const char *name = BPF_CORE_READ(cachep, name);

	vp = bpf_map_lookup_elem(&slab_entries, &name);
	if (!vp) {
		bpf_map_update_elem(&slab_entries, &name, &zero_value, BPF_ANY);
		vp = bpf_map_lookup_elem(&slab_entries, &name);
		if (!vp) return 0;
		bpf_probe_read_kernel(&vp->name, sizeof(vp->name), name);
	}
	vp->count++;
	vp->size += BPF_CORE_READ(cachep, size);
	return 0;
}

SEC("kprobe/kmem_cache_alloc")
int BPF_KPROBE(kmem_cache_alloc, struct kmem_cache *cachep)
{ return probe_entry(cachep); }
