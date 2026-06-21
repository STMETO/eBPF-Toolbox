#ifndef __PAF_H
#define __PAF_H

#include "common/types.h"

struct Paf_ctrl {
	bpf_bool_t enable;
};

struct Paf_event {
	bpf_u64_t min;
	bpf_u64_t low;
	bpf_u64_t high;
	bpf_u64_t present;
	bpf_u64_t protection;
	bpf_s32_t flag;
};

/* 用户态入口 */
#ifndef __BPF__
#include <stdbool.h>
int paf_run(int poll_timeout_ms, bool enable);
#endif

#endif
