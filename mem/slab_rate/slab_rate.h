#ifndef __SLAB_RATE_H
#define __SLAB_RATE_H
#include "common/types.h"
#define CACHE_NAME_SIZE 32
struct SlabRate_ctrl { bpf_bool_t enable; };
struct SlabRate_info {
	char name[CACHE_NAME_SIZE];
	bpf_u64_t count;
	bpf_u64_t size;
};
/* 用户态入口 */
#ifndef __BPF__
#include <stdbool.h>
int slab_rate_run(int poll_timeout_ms, bool enable);
#endif

#endif
