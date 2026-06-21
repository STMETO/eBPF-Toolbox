#ifndef __MEM_LEAK_H
#define __MEM_LEAK_H
#include "common/types.h"
#define ALLOCS_MAX_ENTRIES 1000000
#define COMBINED_ALLOCS_MAX_ENTRIES 10240

struct MemLeak_ctrl { bpf_bool_t enable; };

struct alloc_info {
	bpf_u64_t size;
	int stack_id;
};

union combined_alloc_info {
	struct {
		bpf_u64_t total_size : 40;
		bpf_u64_t number_of_allocs : 24;
	};
	bpf_u64_t bits;
};
#endif
