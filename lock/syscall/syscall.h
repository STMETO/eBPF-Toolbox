#ifndef __SYSTEM_CALL_DELAY_H
#define __SYSTEM_CALL_DELAY_H

#include "common/types.h"
/*
 * 系统调用延迟监控 - 通用头文件    
 * 作用：定义 内核态eBPF <-> 用户态程序 共用的结构体
 * 两边包含同一个头文件，保证数据结构完全一致
 */

/*
 * 控制结构体
 * 用户态通过修改这个结构体，控制eBPF程序的开关
 */
struct SystemCall_Delay_ctrl {
    bpf_bool_t enable;    // 监控开关：true=开启监控  false=关闭监控
};


/*
 * 输出事件结构体
 * 与 bpf_ringbuf 输出完全对应
 *
 * pid = 64 位 ID：高32位进程号，低32位线程号
 */
struct SystemCall_Delay_event {
    bpf_u64_t pid;         // 全局唯一 64 位 ID
    bpf_u64_t delay;       // 耗时
    bpf_u32_t syscall_id;  // 系统调用号
    bpf_s8_t  comm[TASK_COMM_LEN]; // 进程名
};
/* 用户态入口 */
#ifndef __BPF__
#include <stdbool.h>
int syscall_run(int poll_timeout_ms, bool enable);
#endif

#endif
