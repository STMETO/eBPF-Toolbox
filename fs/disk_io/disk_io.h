#ifndef __DISK_IO_VISIT_H
#define __DISK_IO_VISIT_H

#include "common/types.h"

struct DiskIoVisit_ctrl {
	bpf_bool_t enable;
};

struct DiskIoVisit_event {
	bpf_s64_t timestamp;
	bpf_s32_t blk_dev;
	bpf_s32_t sectors;
	bpf_s32_t rwbs;
	bpf_s32_t count;
	char comm[TASK_COMM_LEN];
};

#endif /* __DISK_IO_VISIT_H */
