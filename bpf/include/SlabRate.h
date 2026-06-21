#ifndef __SLAB_RATE_H
#define __SLAB_RATE_H
#include "common.h"
#define CACHE_NAME_SIZE 32
struct SlabRate_ctrl { bpf_bool_t enable; };
struct SlabRate_info {
	char name[CACHE_NAME_SIZE];
	bpf_u64_t count;
	bpf_u64_t size;
};
#endif
