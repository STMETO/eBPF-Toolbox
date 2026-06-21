#ifndef __PR_H
#define __PR_H

#include "common/types.h"

struct Pr_ctrl { bpf_bool_t enable; };

struct Pr_event {
	bpf_u64_t reclaim;
	bpf_u64_t reclaimed;
	bpf_u32_t unqueued_dirty;
	bpf_u32_t congested;
	bpf_u32_t writeback;
};

#endif
