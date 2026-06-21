#ifndef __BLOCK_RQ_ISSUE_H
#define __BLOCK_RQ_ISSUE_H

#include "common.h"

struct BlockRqIssue_ctrl {
	bpf_bool_t enable;
};

struct BlockRqIssue_event {
	bpf_s64_t timestamp;
	bpf_s32_t dev;
	bpf_s32_t sector;
	bpf_s32_t nr_sectors;
	char comm[TASK_COMM_LEN];
	bpf_u64_t total_io;
};

#endif /* __BLOCK_RQ_ISSUE_H */
