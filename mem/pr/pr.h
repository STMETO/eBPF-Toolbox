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

/* 用户态入口 */
#ifndef __BPF__
#include <stdbool.h>
int pr_run(int poll_timeout_ms, bool enable);
#endif

#endif
