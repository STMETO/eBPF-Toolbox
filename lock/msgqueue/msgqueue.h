#ifndef __MSG_QUEUE_DELAY_H
#define __MSG_QUEUE_DELAY_H

#include "common/types.h"

/*
 * 消息队列延迟监控 - 通用头文件
 * 作用：定义 内核态eBPF <-> 用户态程序 共用的结构体
 * 两边包含同一个头文件，保证数据结构完全一致
 */

/*
 * 控制结构体
 * 用户态通过修改这个结构体，控制eBPF程序的开关
 */
struct MsgQueue_Delay_ctrl {
    bpf_bool_t enable;    // 监控开关：true=开启监控  false=关闭监控
};

/*
 * 输出事件结构体
 * eBPF采集到消息队列收发延迟后，通过ringbuf发给用户态
 * 包含一次完整消息传递的发送端和接收端信息
 */
struct MsgQueue_Delay_event {
    bpf_s32_t send_pid;         // 发送消息的进程 PID
    bpf_s32_t rcv_pid;          // 接收消息的进程 PID
    bpf_s32_t mqdes;            // 消息队列描述符
    bpf_u64_t msg_len;          // 消息长度
    bpf_u32_t msg_prio;         // 消息优先级
    bpf_u64_t send_enter_time;  // 发送端进入内核时间戳（纳秒）
    bpf_u64_t send_exit_time;   // 发送端离开内核时间戳（纳秒）
    bpf_u64_t rcv_enter_time;   // 接收端进入内核时间戳（纳秒）
    bpf_u64_t rcv_exit_time;    // 接收端离开内核时间戳（纳秒）
};

/* 用户态入口 */
#ifndef __BPF__
#include <stdbool.h>
int msgqueue_run(int poll_timeout_ms, bool enable);
#endif

#endif
