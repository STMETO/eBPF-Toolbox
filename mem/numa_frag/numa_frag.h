#ifndef __FRAG_INFO_H
#define __FRAG_INFO_H
#include "common/types.h"
#define MAX_ORDER 10

typedef bpf_u64_t u64;

/* Keep original struct names for BPF code compatibility */
struct order_zone {
	unsigned int order;
	u64 zone_ptr;
};

struct ctg_info {
	unsigned long free_pages;
	unsigned long free_blocks_total;
	unsigned long free_blocks_suitable;
};

struct zone_info {
	u64 zone_ptr;
	u64 zone_start_pfn;
	u64 spanned_pages;
	u64 present_pages;
	char comm[32];
	unsigned int order;
};

struct pgdat_info {
	u64 pgdat_ptr;
	int nr_zones;
	int node_id;
};

struct FragInfo_ctrl { bpf_bool_t enable; };
/* 用户态入口 */
#ifndef __BPF__
#include <stdbool.h>
int numa_frag_info_run(int poll_timeout_ms, bool enable);
#endif

#endif
