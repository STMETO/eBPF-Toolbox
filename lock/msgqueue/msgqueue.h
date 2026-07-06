#ifndef __MSGQUEUE_H
#define __MSGQUEUE_H
#include "common/types.h"

#define MQ_EV_SEND 0
#define MQ_EV_RECV 1

struct Msgqueue_ctrl {
	bpf_bool_t enable;
	bpf_u64_t  min_delay_ns;
	bpf_s32_t  target_pid;
};

struct Msgqueue_event {
	bpf_u32_t type;
	bpf_u64_t ts_ns, delay_ns;
	bpf_s32_t pid, mqdes;
	bpf_u64_t msg_len;
	bpf_u32_t msg_prio;
	bpf_s8_t  comm[TASK_COMM_LEN];
};

struct Msgqueue_stats {
	bpf_u64_t send_count, send_total_ns, send_max_ns;
	bpf_u64_t recv_count, recv_total_ns, recv_max_ns;
};

#ifndef __BPF__
#include <stdbool.h>
int msgqueue_run(int poll_timeout_ms, bool enable,
		 bpf_s32_t target_pid, bpf_u64_t min_delay_ns);
#endif
#endif
