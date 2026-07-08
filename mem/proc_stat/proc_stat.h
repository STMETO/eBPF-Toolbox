#ifndef __PROC_STAT_H
#define __PROC_STAT_H
#include "common/types.h"

struct ProcStat_ctrl {
	bpf_bool_t enable;
	bpf_u64_t  min_delay_ns;
	bpf_s32_t  target_pid;
};

struct ProcStat_event {
	bpf_s32_t pid;
	bpf_s64_t nvcsw, nivcsw;
	bpf_s64_t vsize, size;
	bpf_s64_t rssanon, rssfile, rssshmem, vswap;
	bpf_s64_t Vdata, Vstk;
	bpf_s8_t  comm[TASK_COMM_LEN];
};

struct ProcStat_stats {
	bpf_u64_t count;
	bpf_s32_t max_pid;
	bpf_s8_t  max_comm[TASK_COMM_LEN];
};

#ifndef __BPF__
#include <stdbool.h>
int proc_stat_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid, bpf_u64_t min_delay_ns);
#endif
#endif
