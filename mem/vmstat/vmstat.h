#ifndef __VMSTAT_H
#define __VMSTAT_H
#include "common/types.h"

/* 合并 paf + sys_stat + frag_info + numa_frag
 * 单探针 kprobe/get_page_from_freelist，一次采集全部内存指标
 */

struct Vmstat_ctrl {
	bpf_bool_t enable;
	bpf_s32_t  target_pid;
	bpf_u32_t  sample_rate;    // 每 N 次调用采样一次，0=全部
};

/* 单次事件涵盖：水位线 + LRU + Slab + 碎片指数 + NUMA */
struct Vmstat_event {
	bpf_u64_t ts_ns;
	/* 水位线 (ex-paf) */
	bpf_u64_t min, low, high, present;
	bpf_u32_t gfp_flags;
	/* LRU (ex-sys_stat) */
	bpf_u64_t nr_free, nr_anon_active, nr_anon_inactive;
	bpf_u64_t nr_file_active, nr_file_inactive;
	bpf_u64_t nr_slab_reclaimable, nr_slab_unreclaimable;
	bpf_u64_t nr_unevictable;
	/* 碎片指数: order 0,1,2,3 的空闲页数 (ex-frag_info) */
	bpf_u64_t free_order[4];
	/* NUMA (ex-numa_frag) */
	bpf_s32_t node_id;
	bpf_s32_t cpu;
	bpf_s8_t  comm[TASK_COMM_LEN];
};

struct Vmstat_stats {
	bpf_u64_t count;
	bpf_u64_t min_free, max_free, total_free;
};

#ifndef __BPF__
#include <stdbool.h>
int vmstat_run(int poll_timeout_ms, bool enable,
	       bpf_s32_t target_pid, bpf_u64_t min_delay_ns);
#endif
#endif
