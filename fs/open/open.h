#ifndef __OPEN_H
#define __OPEN_H

#include "common/types.h"

#define FS_OPEN_PATH_SIZE 256

struct Open_ctrl {
	bpf_bool_t enable;
	bpf_u64_t  min_delay_ns;
	bpf_s32_t  target_pid;
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


/**
 * @struct Open_stats
 * 文件打开系统调用全局汇总统计结构体，存储在 stats_map 数组Map
 * 持久累加所有符合过滤条件的 openat 调用指标，程序退出时用户态读取打印汇总报表
 * @field count 捕获到的 openat 系统调用总次数
 * @field total_ns 所有openat调用耗时累加总纳秒，用于计算平均打开耗时
 * @field max_ns 单次openat系统调用最大耗时纳秒，定位文件打开卡顿
 * @field max_pid 产生最长打开耗时的进程PID
 * @field max_comm 最长耗时打开操作对应的进程名称
 */
 struct Open_stats {
	bpf_u64_t count, total_ns, max_ns;
	bpf_s32_t max_pid;
	bpf_s8_t  max_comm[TASK_COMM_LEN];
};

#ifndef __BPF__
#include <stdbool.h>
int open_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid, bpf_u64_t min_delay_ns);
#endif

#endif /* __OPEN_H */
