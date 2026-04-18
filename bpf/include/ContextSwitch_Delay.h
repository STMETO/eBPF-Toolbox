#ifndef __CONTEXT_SWITCH_DELAY_H
#define __CONTEXT_SWITCH_DELAY_H

#include "common.h"
/*
 * 进程切换延迟监控 - 通用头文件
 * 作用：定义 内核态eBPF <-> 用户态程序 共用的结构体
 * 两边包含同一个头文件，保证数据结构完全一致
 */

/*
 * 控制结构体
 * 用户态通过修改这个结构体，控制eBPF程序的开关
 */
struct ContextSwitch_Delay_ctrl {
    bpf_bool_t enable;    // 监控开关：true=开启监控  false=关闭监控
};

/*
 * 事件数据结构体
 * eBPF采集到进程切换延迟后，通过ringbuf发给用户态
 */
struct ContextSwitch_Delay_event {
    bpf_u64_t start_time; // 进程切换开始时间（微秒）
    bpf_u64_t end_time;   // 进程切换结束时间（微秒）
    bpf_u64_t delay;      // 切换耗时 = end_time - start_time
};

#endif
