#ifndef __BLOCK_IO_H
#define __BLOCK_IO_H
#include "common/types.h"

#define BLOCK_IO_EV_ISSUE    0
#define BLOCK_IO_EV_COMPLETE 1

struct BlockIo_ctrl {
	bpf_bool_t enable;
	bpf_u64_t  min_latency_ns;
	bpf_s32_t  target_pid;
};

struct BlockIo_event {
	bpf_u32_t type;          // ISSUE or COMPLETE
	bpf_u64_t ts_ns;
	bpf_u64_t latency_ns;    // COMPLETE: issue→complete 延迟
	bpf_s32_t pid, dev;
	bpf_u64_t sector;
	bpf_u32_t nr_sectors;
	bpf_s32_t rwbs;          // 1=Read 2=Write 3=Discard 4=Flush
	bpf_u64_t bytes;
	bpf_s8_t  comm[TASK_COMM_LEN];
};

struct BlockIo_stats {
	bpf_u64_t issue_cnt, complete_cnt;
	bpf_u64_t total_lat_ns, max_lat_ns;
};

#ifndef __BPF__
#include <stdbool.h>
int block_io_run(int poll_timeout_ms, bool enable,
		 bpf_s32_t target_pid, bpf_u64_t min_latency_ns);
#endif
#endif
