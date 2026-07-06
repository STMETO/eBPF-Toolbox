#ifndef __PREEMPT_DELAY_H
#define __PREEMPT_DELAY_H

#include "common/types.h"

/*
 * 抢占延迟监控 - 通用头文件
 * 作用：定义 内核态eBPF <-> 用户态程序 共用的结构体
 * 两边包含同一个头文件，保证数据结构完全一致
 */

/*
 * 控制结构体
 * 用户态通过修改这个结构体，控制eBPF程序的开关
 */
struct Preempt_Delay_ctrl {
    bpf_bool_t enable;    // 监控开关：true=开启监控  false=关闭监控
};

/*
 * 抢占事件结构体
 * eBPF采集到进程被强制抢占的延迟后，通过ringbuf发送给用户态
 */
struct Preempt_Delay_event {
    bpf_s32_t prev_pid;                // 被抢占的进程 PID
    bpf_s32_t next_pid;                // 抢占后运行的进程 PID
    bpf_u64_t duration;                // 抢占延迟（纳秒）
    bpf_s8_t  comm[TASK_COMM_LEN];     // 抢占后运行的进程名
};

/* 用户态入口 */
#ifndef __BPF__
#include <stdbool.h>
int preempt_run(int poll_timeout_ms, bool enable);
#endif

#endif
