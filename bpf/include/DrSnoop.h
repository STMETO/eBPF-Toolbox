#ifndef __DR_SNOOP_H
#define __DR_SNOOP_H
#include "common.h"
#define NR_VM_ZONE_STAT_ITEMS 5
#define NR_FREE_PAGES 0

struct DrSnoop_ctrl { bpf_bool_t enable; };

/* struct names preserved from original for BPF compatibility */
struct val_t {
	bpf_u64_t id;
	bpf_u64_t ts;
	char name[TASK_COMM_LEN];
	bpf_u64_t vm_stat[NR_VM_ZONE_STAT_ITEMS];
};

struct data_t {
	bpf_u64_t id;
	bpf_u32_t uid;
	bpf_u64_t nr_reclaimed;
	bpf_u64_t delta;
	bpf_u64_t ts;
	char name[TASK_COMM_LEN];
	bpf_u64_t vm_stat[NR_VM_ZONE_STAT_ITEMS];
};
#endif
