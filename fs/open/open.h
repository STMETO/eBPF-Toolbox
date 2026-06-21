#ifndef __OPEN_H
#define __OPEN_H

#include "common/types.h"

#define FS_OPEN_PATH_SIZE 256

struct Open_ctrl {
	bpf_bool_t enable;
};

struct Open_event {
	bpf_s32_t pid_;
	char path_name_[FS_OPEN_PATH_SIZE];
	bpf_s32_t n_;
	char comm[TASK_COMM_LEN];
};

#endif /* __OPEN_H */
