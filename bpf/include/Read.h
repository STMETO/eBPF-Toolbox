#ifndef __READ_H
#define __READ_H

#include "common.h"

struct Read_ctrl {
	bpf_bool_t enable;
};

struct Read_event {
	bpf_s32_t pid;
	bpf_u64_t duration_ns;
};

#endif /* __READ_H */
