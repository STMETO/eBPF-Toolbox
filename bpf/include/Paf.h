#ifndef __PAF_H
#define __PAF_H

#include "common.h"

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

#endif
