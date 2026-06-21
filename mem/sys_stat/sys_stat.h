#ifndef __SYS_STAT_H
#define __SYS_STAT_H
#include "common/types.h"
struct SysStat_ctrl { bpf_bool_t enable; };
struct SysStat_event {
	bpf_u64_t present, anon_inactive, anon_active, file_inactive, file_active, unevictable;
	bpf_u64_t slab_reclaimable, slab_unreclaimable, anon_isolated, file_isolated;
	bpf_u64_t working_nodes, working_refault, working_activate, working_restore, working_nodereclaim;
	bpf_u64_t anon_mapped, file_mapped, file_pages, file_dirty, writeback, writeback_temp;
	bpf_u64_t shmem, shmem_thps, pmdmapped, anon_thps, unstable_nfs, vmscan_write, vmscan_immediate;
	bpf_u64_t diried, written, kernel_misc_reclaimable;
};
#endif
