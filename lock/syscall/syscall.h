#ifndef __SYSCALL_H
#define __SYSCALL_H
#include "common/types.h"

struct Syscall_ctrl {
	bpf_bool_t enable;
	bpf_u64_t  min_delay_ns;
	bpf_s32_t  target_pid;
};

struct Syscall_event {
	bpf_u64_t ts_ns, delay_ns;
	bpf_s32_t pid, tid, syscall_id;
	bpf_s8_t  comm[TASK_COMM_LEN];
};

struct Syscall_stats {
	bpf_u64_t count, total_ns, max_ns;
	bpf_s32_t max_pid, max_syscall_id;
	bpf_s8_t  max_comm[TASK_COMM_LEN];
};

#ifndef __BPF__
#include <stdbool.h>
int syscall_run(int poll_timeout_ms, bool enable,
		bpf_s32_t target_pid, bpf_u64_t min_delay_ns);
#endif
#endif
