#ifndef __OPEN_H
#define __OPEN_H

#include "common/types.h"

#define FS_OPEN_PATH_SIZE 256

struct Open_ctrl {
	bpf_bool_t enable;
};

/*
 * Open_event — 完整描述一次 openat 系统调用事件
 *
 * 数据来源：
 *   sys_enter_openat: 进程PID、打开文件路径
 *   sys_exit_openat:  分配到的文件描述符 fd
 */
struct Open_event {
	bpf_s32_t pid;                        // 进程 PID（内核态 bpf_get_current_pid_tgid 高 32 位）
	bpf_s32_t fd;                         // openat 返回的文件描述符（0=stdin,1=stdout,2=stderr…）
	bpf_u64_t timestamp_ns;               // 事件时间戳（纳秒，bpf_ktime_get_ns）
	char path_name_[FS_OPEN_PATH_SIZE];   // 打开的文件绝对路径（如 /etc/passwd）
	char comm[TASK_COMM_LEN];             // 进程名称（如 bash、cat、nginx）
};

/* 用户态入口 */
#ifndef __BPF__
#include <stdbool.h>
int open_run(int poll_timeout_ms, bool enable);
#endif

#endif /* __OPEN_H */
