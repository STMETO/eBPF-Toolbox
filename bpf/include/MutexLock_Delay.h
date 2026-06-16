#ifndef __MUTEX_LOCK_DELAY_H
#define __MUTEX_LOCK_DELAY_H

#include "common.h"

/*
 * 互斥锁延迟监控 - 通用头文件
 * 作用：定义 内核态eBPF <-> 用户态程序 共用的结构体
 * 两边包含同一个头文件，保证数据结构完全一致
 */

/*
 * 控制结构体
 * 用户态通过修改这个结构体，控制eBPF程序的开关
 */
struct MutexLock_Delay_ctrl {
    bpf_bool_t enable;    // 监控开关：true=开启监控  false=关闭监控
};

/*
 * 互斥锁竞争事件结构体
 * 当内核/用户态互斥锁发生竞争时，通过ringbuf发送给用户态
 */
struct MutexLock_Delay_event {
    bpf_u64_t ptr;                     // 锁地址
    bpf_s32_t owner_pid;               // 持有者 PID
    bpf_s32_t contender_pid;           // 抢占者 PID
    bpf_s8_t  contender_name[TASK_COMM_LEN]; // 抢占者进程名
    bpf_s8_t  owner_name[TASK_COMM_LEN];     // 持有者进程名
    bpf_s32_t owner_prio;              // 持有者优先级
    bpf_s32_t contender_prio;          // 抢占者优先级
};

#endif
