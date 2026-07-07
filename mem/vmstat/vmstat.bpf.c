#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "vmstat.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
const int ck = 0;

/* PERCPU 采样计数器 */
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, int); __type(value, u32); } sample_cnt SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, int); __type(value, struct Vmstat_ctrl); } ctrl_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, int); __type(value, struct Vmstat_stats); } stats_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256 * 1024); } rb SEC(".maps");

static inline struct Vmstat_ctrl *get_ctrl(void) { return bpf_map_lookup_elem(&ctrl_map, &ck); }

/* 读 zone 的 vm_stat 数组项 (NR_FREE_PAGES, NR_ACTIVE_ANON 等) */
static u64 read_vmstat(struct zone *zone, int idx) {
	struct pglist_data *pgdat = BPF_CORE_READ(zone, zone_pgdat);
	unsigned long *arr = (unsigned long *)BPF_CORE_READ(pgdat, vm_stat);
	if (!arr) return 0;
	unsigned long val;
	bpf_probe_read_kernel(&val, sizeof(val), &arr[idx]);
	return val;
}

SEC("kprobe/get_page_from_freelist")
int BPF_KPROBE(vmstat_trace, gfp_t gfp_mask, unsigned int order,
	       struct alloc_context *ac, nodemask_t *nodemask)
{
	struct Vmstat_ctrl *c = get_ctrl();
	if (!c || !c->enable) return 0;
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (c->target_pid != 0 && (u32)c->target_pid != pid) return 0;

	/* 采样率控制 */
	if (c->sample_rate > 1) {
		u32 *cnt = bpf_map_lookup_elem(&sample_cnt, &ck);
		if (!cnt) return 0;
		if (++(*cnt) % c->sample_rate != 0) return 0;
	}

	struct zone *zone = BPF_CORE_READ(ac, preferred_zoneref, zone);
	if (!zone) return 0;

	struct Vmstat_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;

	e->ts_ns    = bpf_ktime_get_ns();
	e->cpu      = bpf_get_smp_processor_id();
	e->gfp_flags = gfp_mask;
	e->node_id  = (s32)BPF_CORE_READ(zone, zone_pgdat, node_id);

	/* 水位线 */
	e->min     = BPF_CORE_READ(zone, _watermark[0]);
	e->low     = BPF_CORE_READ(zone, _watermark[1]);
	e->high    = BPF_CORE_READ(zone, _watermark[2]);
	e->present = BPF_CORE_READ(zone, spanned_pages);

	/* LRU / Slab 统计 (vm_stat 数组索引) */
	/* NR_FREE_PAGES=4, NR_ACTIVE_ANON=0, NR_INACTIVE_ANON=1,
	   NR_ACTIVE_FILE=2, NR_INACTIVE_FILE=3, NR_UNEVICTABLE=5,
	   NR_SLAB_RECLAIMABLE_B=18, NR_SLAB_UNRECLAIMABLE_B=19 */
	e->nr_free             = read_vmstat(zone, 4);
	e->nr_anon_active      = read_vmstat(zone, 0);
	e->nr_anon_inactive    = read_vmstat(zone, 1);
	e->nr_file_active      = read_vmstat(zone, 2);
	e->nr_file_inactive    = read_vmstat(zone, 3);
	e->nr_unevictable      = read_vmstat(zone, 5);
	e->nr_slab_reclaimable = read_vmstat(zone, 18);
	e->nr_slab_unreclaimable = read_vmstat(zone, 19);

	/* 碎片指数: order 0-3 的空闲块数 */
#pragma unroll
	for (int i = 0; i < 4; i++)
		e->free_order[i] = BPF_CORE_READ(&zone->free_area[i], nr_free);

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);

	struct Vmstat_stats *st = bpf_map_lookup_elem(&stats_map, &ck);
	if (!st) { struct Vmstat_stats z = {}; bpf_map_update_elem(&stats_map, &ck, &z, BPF_ANY); st = bpf_map_lookup_elem(&stats_map, &ck); }
	if (st) { st->count++; st->total_free += e->nr_free; if (e->nr_free < st->min_free || st->min_free == 0) st->min_free = e->nr_free; if (e->nr_free > st->max_free) st->max_free = e->nr_free; }
	return 0;
}
