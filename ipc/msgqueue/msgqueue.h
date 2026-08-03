#ifndef __MSGQUEUE_H
#define __MSGQUEUE_H

#include "common/types.h"

/*
 * delivery_type 描述消息是怎样到达接收者的：
 *
 * QUEUED：消息真正进入 POSIX mqueue 的红黑树，随后被接收路径取出。
 *         residence_ns 是“成功入队 -> 开始向接收缓冲区交付”的时间；
 *         结束探针位于 store_msg() 入口，不包含用户缓冲区复制耗时。
 * DIRECT：发送时已有接收者睡眠等待，内核绕过队列直接交付消息。
 *         这种消息没有进入队列，因此驻留时间按定义为 0。
 */
#define MQ_DELIVERY_QUEUED 0
#define MQ_DELIVERY_DIRECT 1

/**
 * @struct Msgqueue_ctrl
 * @brief 用户态下发给 BPF 程序的运行时配置。
 *
 * min_delay_ns 只控制 ringbuf 明细事件；退出统计仍包含所有符合 PID
 * 条件的驻留样本，避免阈值过滤后平均值失去代表性。
 * target_pid 为 0 时监控全部进程；非 0 时，发送者或接收者任一方匹配
 * 即保留该消息。pidns_dev/pidns_ino 用于把 PID 转换为工具所在命名空间
 * 中可见的 TGID，使容器内使用 -p 时语义保持正确。
 */
struct Msgqueue_ctrl {
	bpf_bool_t enable;
	bpf_u64_t min_delay_ns;
	bpf_s32_t target_pid;
	bpf_u32_t _pad;
	bpf_u64_t pidns_dev;
	bpf_u64_t pidns_ino;
};

/**
 * @struct Msgqueue_event
 * @brief 一条 POSIX 消息从入队到被接收的驻留事件。
 *
 * send_mqdes 和 recv_mqdes 分别是发送、接收进程中的文件描述符。文件
 * 描述符只在各自进程内有意义，因此不能假定两个值相同。QUEUED 事件
 * 同时具备发送者和接收者信息；DIRECT 事件通过消息对象在发送、接收
 * 两个 CPU 间关联，也会给出真实接收者及其文件描述符。
 */
struct Msgqueue_event {
	bpf_u64_t ts_ns;
	bpf_u64_t residence_ns;
	bpf_u64_t msg_len;
	bpf_s32_t sender_pid;
	bpf_s32_t receiver_pid;
	bpf_s32_t send_mqdes;
	bpf_s32_t recv_mqdes;
	bpf_u32_t msg_prio;
	bpf_u32_t delivery_type;
	bpf_s8_t sender_comm[TASK_COMM_LEN];
	bpf_s8_t receiver_comm[TASK_COMM_LEN];
};

/**
 * @struct Msgqueue_stats
 * @brief 程序退出时展示的驻留时间汇总。
 *
 * queued_count/total/max 只统计真正进入队列并被接收的消息；direct_count
 * 单独统计绕过队列的直接交付。unmatched_count 表示取出消息时未找到
 * 入队记录，通常是工具启动前已存在的消息或 LRU 容量不足导致的淘汰。
 * tracking_drop_count 表示内部关联 Map 写入失败，ringbuf_drop_count 表示
 * 明细事件因 ringbuf 满而丢失；二者不会被悄悄计入正常驻留样本。
 */
struct Msgqueue_stats {
	bpf_u64_t queued_count;
	bpf_u64_t queued_total_ns;
	bpf_u64_t queued_max_ns;
	bpf_u64_t direct_count;
	bpf_u64_t unmatched_count;
	bpf_u64_t tracking_drop_count;
	bpf_u64_t ringbuf_drop_count;
};

#ifndef __BPF__
#include <stdbool.h>

/**
 * @brief 启动 POSIX 消息队列驻留时间监控。
 * @param poll_timeout_ms ringbuf 轮询超时，单位毫秒。
 * @param enable 是否启用采集。
 * @param target_pid 目标 TGID；0 表示全部进程。
 * @param min_delay_ns ringbuf 明细事件的最小驻留时间阈值。
 */
int msgqueue_run(int poll_timeout_ms, bool enable,
		 bpf_s32_t target_pid, bpf_u64_t min_delay_ns);
#endif

#endif
