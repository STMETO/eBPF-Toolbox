#ifndef __MSGQUEUE_H
#define __MSGQUEUE_H
#include "common/types.h"

// 消息队列事件类型标识
#define MQ_EV_SEND 0    // mq_timedsend 发送消息事件
#define MQ_EV_RECV 1    // mq_timedreceive 接收消息事件

/**
 * @struct Msgqueue_ctrl
 * @brief 消息队列监控全局控制配置，存储在 ctrl_map 数组Map
 * @field enable 监控总开关：true开启采集，false丢弃所有mq收发事件
 * @field min_delay_ns 延迟过滤阈值(纳秒)，mq系统调用耗时低于该值不上报事件
 * @field target_pid PID过滤：0=监控全部进程；非0仅采集对应TGID进程
 */
struct Msgqueue_ctrl {
	bpf_bool_t enable;
	bpf_u64_t  min_delay_ns;
	bpf_s32_t  target_pid;
};

/**
 * @struct Msgqueue_event
 * @brief BPF通过ringbuf推送给用户态的消息队列收发事件载体
 * @field ts_ns 内核单调时钟纳秒时间戳，系统调用返回时刻
 * @field delay_ns mq_timedsend/mq_timedreceive 完整调用耗时(纳秒)
 * @field mqdes 消息队列文件描述符，区分不同消息队列实例
 * @field msg_len 本次发送/接收消息的数据长度
 * @field msg_prio 消息优先级，mq发送时指定、接收时读出的优先级值
 */
struct Msgqueue_event {
	bpf_u32_t type;				// 事件类型，MQ_EV_SEND / MQ_EV_RECV
	bpf_u64_t ts_ns, delay_ns;
	bpf_s32_t pid, mqdes;
	bpf_u64_t msg_len;
	bpf_u32_t msg_prio;
	bpf_s8_t  comm[TASK_COMM_LEN];
};

/**
 * @struct Msgqueue_stats
 * @brief 全局mq收发汇总统计结构体，存储在stats_map，程序退出用户态读取打印
 * @field send_count 捕获到的mq_timedsend发送总次数
 * @field send_total_ns 所有发送调用延迟累加总纳秒，可计算平均发送耗时
 * @field send_max_ns 单次发送最大耗时纳秒值
 * @field recv_count 捕获到的mq_timedreceive接收总次数
 * @field recv_total_ns 所有接收调用延迟累加总纳秒，可计算平均接收耗时
 * @field recv_max_ns 单次接收最大耗时纳秒值
 */
struct Msgqueue_stats {
	bpf_u64_t send_count, send_total_ns, send_max_ns;
	bpf_u64_t recv_count, recv_total_ns, recv_max_ns;
};

/* 用户态对外运行API，仅非BPF编译环境生效 */
#ifndef __BPF__
#include <stdbool.h>
/**
 * @brief 消息队列监控主业务入口函数
 * @param poll_timeout_ms ringbuf用户态阻塞读取超时毫秒
 * @param enable 下发内核的监控总开关
 * @param target_pid 过滤指定进程PID，0代表全量采集
 * @param min_delay_ns 延迟过滤阈值，低于该耗时不推送事件
 * @return int 程序执行退出码，0正常，非0为错误
 */
int msgqueue_run(int poll_timeout_ms, bool enable,
		 bpf_s32_t target_pid, bpf_u64_t min_delay_ns);
#endif

#endif
