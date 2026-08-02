#ifndef __OPEN_H
#define __OPEN_H

#include "common/types.h"

#define FS_OPEN_PATH_SIZE 256

struct Open_ctrl {
	bpf_bool_t enable;
	bpf_u64_t  min_delay_ns;
	bpf_s32_t  target_pid;
	bpf_u64_t  pid_ns_dev;     // 当前 PID namespace 对应的 nsfs st_dev
	bpf_u64_t  pid_ns_ino;     // 当前 PID namespace 对应的 nsfs st_ino
};

/*
 * Open_event — 完整描述一次 openat 系统调用事件
 *
 * 数据来源：
 *   sys_enter_openat: 进程PID、打开文件路径
 *   sys_exit_openat:  分配到的文件描述符 fd
 */
struct Open_event {
	bpf_s32_t pid;                        // TGID（用户态进程 PID）
	bpf_s32_t tid;                        // 线程 ID
	bpf_s32_t dirfd;                      // openat 的 dirfd
	bpf_s32_t fd;                         // 成功时返回的文件描述符，失败时为 -1
	bpf_s64_t ret;                        // 原始返回值；负数为 -errno
	bpf_u64_t flags;                      // openat flags
	bpf_u64_t timestamp_ns;               // 事件完成时间（单调时钟纳秒）
	bpf_u64_t latency_ns;                 // openat 系统调用耗时（纳秒）
	char path_name_[FS_OPEN_PATH_SIZE];   // 用户传入的路径，可能是相对路径或被截断
	char comm[TASK_COMM_LEN];             // 进程名称（如 bash、cat、nginx）
};


/**
 * @struct Open_stats
 * 文件打开系统调用全局汇总统计结构体，存储在 stats_map 数组Map
 * 持久累加所有符合过滤条件的 openat 调用指标，程序退出时用户态读取打印汇总报表
 * 同时记录入口、完成、上报、过滤、失败、丢弃以及延迟汇总。
 */
struct Open_stats {
	bpf_u64_t attempted;        // PID 过滤后进入 openat 的调用数
	bpf_u64_t completed;        // 成功关联入口/出口的调用数
	bpf_u64_t submitted;        // 最终提交到 ringbuf 的明细数
	bpf_u64_t failed;           // 内核返回负 errno 的调用数
	bpf_u64_t filtered_pid;     // 在入口被 TGID 过滤的调用数
	bpf_u64_t filtered_delay;   // 低于耗时阈值、未输出明细的调用数
	bpf_u64_t ringbuf_dropped;  // ringbuf reserve 失败数
	bpf_u64_t map_update_failed; // 入口上下文写入 tid_map 失败数
	bpf_u64_t lookup_missed;    // 出口没有对应入口上下文的次数
	bpf_u64_t path_read_failed;  // 用户 pathname 指针不可读的次数
	bpf_u64_t path_truncated;    // pathname 超过事件固定缓冲区的次数
	bpf_u64_t total_ns;         // 所有 completed 调用的总耗时
	bpf_u64_t max_ns;           // 所有 completed 调用的最大耗时
	bpf_s32_t max_pid;
	bpf_s8_t  max_comm[TASK_COMM_LEN];
};

#ifndef __BPF__
#include <stdbool.h>
int open_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid, bpf_u64_t min_delay_ns);
#endif

#endif /* __OPEN_H */
