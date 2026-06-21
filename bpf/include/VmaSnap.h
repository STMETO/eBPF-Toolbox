#ifndef __VMA_SNAP_H
#define __VMA_SNAP_H
#include "common.h"

struct VmaSnap_ctrl { bpf_bool_t enable; };

/* struct names preserved from original for BPF compatibility */
struct insert_event_t {
	bpf_u64_t timestamp;
	bpf_u64_t duration;
	bpf_s32_t inserted_to_list;
	bpf_s32_t inserted_to_rb;
	bpf_s32_t inserted_to_interval_tree;
	bpf_u64_t link_list_start_time;
	bpf_u64_t link_rb_start_time;
	bpf_u64_t interval_tree_start_time;
	bpf_u64_t link_list_duration;
	bpf_u64_t link_rb_duration;
	bpf_u64_t interval_tree_duration;
};

struct find_event_t {
	bpf_u64_t timestamp;
	bpf_u64_t duration;
	bpf_u64_t addr;
	bpf_s32_t vmacache_hit;
	bpf_u64_t rb_subtree_last;
	bpf_u64_t vm_start;
	bpf_u64_t vm_end;
};
#endif
