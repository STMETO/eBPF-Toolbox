#ifndef __MUTEXLOCK_H
#define __MUTEXLOCK_H
#include "common/types.h"

struct Mutexlock_ctrl {
	bpf_bool_t enable;
	bpf_u64_t  min_delay_ns;
	bpf_s32_t  target_pid;
};

/* 竞争事件（不变） */
struct Mutexlock_event {
	bpf_u64_t ptr;
	bpf_s32_t owner_pid, contender_pid;
	bpf_s32_t owner_prio, contender_prio;
	bpf_s8_t  contender_name[TASK_COMM_LEN];
	bpf_s8_t  owner_name[TASK_COMM_LEN];
};

struct Mutexlock_stats {
	bpf_u64_t contention_count;
	bpf_u64_t lock_total_ns, lock_max_ns;
	bpf_s32_t max_owner_pid, max_contender_pid;
	bpf_s8_t  max_owner_name[TASK_COMM_LEN], max_contender_name[TASK_COMM_LEN];
};

#ifndef __BPF__
#include <stdbool.h>
int mutexlock_run(int poll_timeout_ms, bool enable,
		  bpf_s32_t target_pid, bpf_u64_t min_delay_ns);
#endif
#endif
