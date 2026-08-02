#ifndef __SYSCALL_H
#define __SYSCALL_H

#include "common/types.h"

struct Syscall_ctrl {
	bpf_bool_t enable;
	bpf_u64_t  min_latency_ns;
	bpf_s32_t  target_pid;
};

/**
 * @struct Syscall_event
 * @brief BPF通过ringbuf推送给用户态的系统调用耗时事件结构体
 * @field ts_ns sys_exit触发时刻微秒时间戳（代码内部统一除以1000存储us）
 * @field delay_ns 本次系统调用完整耗时（单位微秒，最终对外换算ns做判断）
 * @field pid 线程组TGID，用户态ps展示的进程PID
 * @field tid 内核线程LWP ID
 * @field syscall_id 系统调用号，标识read/write/open/mq_send等具体syscall
 * @field comm 发起系统调用的进程名称，固定TASK_COMM_LEN长度
 */
struct Syscall_event {
	bpf_u64_t ts_ns, delay_ns;
	bpf_s32_t pid, tid, syscall_id;
	bpf_s8_t  comm[TASK_COMM_LEN];
};

/**
 * @struct Syscall_stats
 * @brief 全局系统调用汇总统计，持久化在stats_map，程序退出用户态读取打印
 * @field count 捕获到的系统调用总次数
 * @field total_ns 所有syscall耗时累加总纳秒，用于计算平均调用耗时
 * @field max_ns 单次系统调用最大耗时（微秒，内核存储单位）
 * @field max_pid 产生最长耗时系统调用的进程PID
 * @field max_syscall_id 最长耗时对应的系统调用号
 * @field max_comm 产生最大延迟的进程名称
 */
struct Syscall_stats {
	bpf_u64_t count, total_ns, max_ns;
	bpf_s32_t max_pid, max_syscall_id;
	bpf_s8_t  max_comm[TASK_COMM_LEN];
};

/* 用户态对外运行入口API，仅非BPF编译环境生效 */
#ifndef __BPF__
#include <stdbool.h>
/**
 * @brief 系统调用耗时监控主函数
 * @param poll_timeout_ms ringbuf阻塞读取超时毫秒
 * @param enable 下发内核的监控总开关
 * @param target_pid 过滤指定进程PID，0为全量采集
 * @param min_latency_ns 最小耗时过滤阈值，低于该值不上报事件
 * @return 0正常退出，非0为异常错误码
 */
int syscall_run(int poll_timeout_ms, bool enable,
		bpf_s32_t target_pid, bpf_u64_t min_latency_ns);
#endif

#endif
