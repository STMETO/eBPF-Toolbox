#ifndef __WRITE_H
#define __WRITE_H

#include "common/types.h"

struct Write_ctrl {
	bpf_bool_t enable;
};

struct Write_event {
	bpf_s32_t fd;
	bpf_s32_t pid;
	bpf_u64_t real_count;
	bpf_u64_t count;
};

#endif /* __WRITE_H */
