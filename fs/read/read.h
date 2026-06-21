#ifndef __READ_H
#define __READ_H

#include "common/types.h"

#define FS_READ_PATH_SIZE 256

struct Read_ctrl {
	bpf_bool_t enable;
};

/*
 * Read_event — 完整描述一次 read 系统调用事件
 *
 * 数据来源：
 *   sys_enter_read:  PID、fd、进程名、文件路径（从内核 fd 表反查）
 *   sys_exit_read :  实际读取字节数（ctx->ret）
 *
 * 与旧版区别：
 *   - 新增 fd、comm、bytes_read、path_name 字段
 *   - 进程名由内核态 bpf_get_current_comm 直接获取，不绕路
 *   - fd 从 tracepoint args[0] 直接拿到，不需要用户态查 /proc
 */
struct Read_event {
	bpf_s32_t pid;                        // 进程 PID
	bpf_s32_t fd;                         // read 操作的文件描述符
	bpf_s64_t bytes_read;                 // 实际读取字节数（返回 -1 表示读失败）
	bpf_u64_t timestamp_ns;               // 事件时间戳（纳秒）
	char path_name_[FS_READ_PATH_SIZE];   // 文件路径（从内核 fd 表反查，可能为空）
	char comm[TASK_COMM_LEN];             // 进程名称
};

/* 用户态入口 */
#ifndef __BPF__
#include <stdbool.h>
int read_run(int poll_timeout_ms, bool enable);
#endif

#endif /* __READ_H */
