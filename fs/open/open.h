#ifndef __OPEN_H
#define __OPEN_H

#include "common/types.h"

#define FS_OPEN_PATH_SIZE 256

struct Open_ctrl {
	bpf_bool_t enable;
};

struct Open_event {
	bpf_s32_t pid_;			// 当前调用 openat 的进程 PID
	char path_name_[FS_OPEN_PATH_SIZE];	 // openat 要打开的文件路径字符串（自动带 \0 结尾）
	bpf_s32_t n_;			// 该进程 fdtable->max_fds：进程允许打开的最大文件描述符数量
	char comm[TASK_COMM_LEN];
};


/* 用户态入口 */
#ifndef __BPF__
#include <stdbool.h>
int open_run(int poll_timeout_ms, bool enable);
#endif

#endif /* __OPEN_H */
