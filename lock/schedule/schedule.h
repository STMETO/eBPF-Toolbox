#ifndef __SCHEDULE_DELAY_H
#define __SCHEDULE_DELAY_H

#include "common/types.h"

/*
 * 调度延迟监控 - 通用头文件
 * 作用：定义 内核态eBPF <-> 用户态程序 共用的结构体
 * 两边包含同一个头文件，保证数据结构完全一致
 */

#ifndef TASK_RUNNING
#define TASK_RUNNING 0x0000
#endif

/*
 * 控制结构体
 * 用户态通过修改这个结构体，控制eBPF程序的开关
 */
struct Schedule_Delay_ctrl {
    bpf_bool_t enable;    // 监控开关：true=开启监控  false=关闭监控
};

/*
 * 进程标识结构体
 * 同时用 PID + CPU ID 组合作为 map key
 * PID=0（idle进程）时加上 CPU ID 来区分
 */
struct Schedule_Delay_proc_id {
    bpf_s32_t pid;
    bpf_s32_t cpu_id;
};

/*
 * 进程过期信息结构体
 * 记录进程切换历史中上一个进程的信息
 */
struct Schedule_Delay_proc_info {
    bpf_s32_t pid;
    bpf_s8_t  comm[TASK_COMM_LEN];
};

/*
 * 进程调度历史结构体
 * 记录每个进程运行前的最后两个进程是谁
 */
struct Schedule_Delay_proc_history {
    struct Schedule_Delay_proc_info last[2];
};

/*
 * 系统全局调度统计结构体
 * 累计整个系统的调度延迟数据
 */
struct Schedule_Delay_sum_schedule {
    bpf_u64_t sum_count;                              // 总调度次数
    bpf_u64_t sum_delay;                              // 总调度延迟（纳秒）
    bpf_u64_t max_delay;                              // 最大调度延迟（纳秒）
    bpf_u64_t min_delay;                              // 最小调度延迟（纳秒）
    bpf_s8_t  proc_name_max[TASK_COMM_LEN];           // 最大延迟的进程名
    bpf_s8_t  proc_name_min[TASK_COMM_LEN];           // 最小延迟的进程名
};

/*
 * 最近一次调度延迟的进程信息
 */
struct Schedule_Delay_proc_schedule {
    struct Schedule_Delay_proc_id id;                  // 进程标识
    bpf_u64_t delay;                                   // 调度延迟（纳秒）
    bpf_s8_t  proc_name[TASK_COMM_LEN];               // 进程名
};

#endif
