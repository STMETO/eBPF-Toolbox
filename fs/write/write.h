#ifndef __WRITE_H
#define __WRITE_H

#include "common/types.h"

#define FS_WRITE_PATH_SIZE 256

struct Write_ctrl {
	bpf_bool_t enable;
	bpf_u64_t  min_delay_ns;
	bpf_s32_t  target_pid;
};

/*
 * Write_event — 完整描述一次 write 系统调用事件
 *
 * 数据来源：
 *   sys_enter_write: PID、fd、预期写入字节数 count、进程名、文件路径
 *   sys_exit_write : 实际写入字节数（ctx->ret）
 *
 * 与旧版区别：
 *   - fd 直接从 write(fd, buf, count) 第一个参数获取，不再依赖 do_sys_openat2 缓存
 *   - real_count 由出口返回值填充，不再是固定 0
 *   - 新增 comm、path_name、timestamp 字段
 */
struct Write_event {
	bpf_s32_t pid;                        // 进程 PID
	bpf_s32_t fd;                         // write 操作的文件描述符
	bpf_s64_t count;                      // 用户请求写入的字节数（write 第三个参数）
	bpf_s64_t real_count;                 // 实际写入字节数（write 返回值，-1 表示失败）
	bpf_u64_t timestamp_ns;               // 事件时间戳（纳秒）
	char path_name_[FS_WRITE_PATH_SIZE];  // 文件路径（内核 fd 表反查，可能为空）
	char comm[TASK_COMM_LEN];             // 进程名称
};

/* 用户态入口 */
struct Write_stats {
	bpf_u64_t count, total_ns, max_ns;
	bpf_s32_t max_pid;
	bpf_s8_t  max_comm[TASK_COMM_LEN];
};

#ifndef __BPF__
#include <stdbool.h>
int write_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid, bpf_u64_t min_delay_ns);
#endif

#endif /* __WRITE_H */
