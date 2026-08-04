/**
* @file msgqueue.h
* @brief POSIX mqueue（POSIX消息队列）BPF监控模块头文件
*
* @details
* 本模块基于eBPF kprobe/kretprobe探针，追踪Linux内核POSIX消息队列(mq_open/mq_send/mq_receive)消息完整生命周期，
* 统计消息在内核队列中的驻留时延，区分【入队排队交付(QUEUED)】与【pipelined_send直接交付(DIRECT)】两种内核路径。
* 支持PID过滤、容器PID命名空间解析、ringbuf明细事件输出、全局统计汇总；同时兼容BPF内核态编译与用户态应用编译。
*
* 内核行为背景：当mq_send执行时，如果已经存在正在阻塞等待消息的接收进程，内核不走红黑树队列，
* 通过pipelined_send直接把msg_msg对象交给等待方，跳过入队逻辑，即DIRECT模式；否则消息插入红黑树等待消费，为QUEUED模式。
*
* @note
* 1. 探针挂载点：store_msg() 消息入队、mq_timedreceive 消息取出；驻留时间不包含用户态copy_to_user拷贝开销。
* 2. 字段对齐：所有结构体严格兼容BPF CO-RE，填充字段用于消除不同架构下内存对齐间隙。
* 3. 编译宏 __BPF__：defined代表BPF内核侧编译；未defined代表用户态应用侧，引入stdbool.h并对外暴露运行API。
*/
#ifndef __MSGQUEUE_H
#define __MSGQUEUE_H

#include "common/types.h"

/**
* @defgroup delivery_type 消息交付类型宏定义
* @brief 标记一条POSIX消息采用哪一条内核交付路径，对应内核pipelined_send逻辑分支
* @{
*/

/**
* @brief QUEUED：消息真正进入POSIX mqueue内核红黑树消息队列
*
* @details
* 发送消息时，当前没有睡眠等待的接收者，消息插入mqueue_inode_info->msg_tree_rb红黑树中排队等待消费。
* residence_ns 定义：【store_msg消息成功入队时刻】→【接收方开始取出消息时刻】的纳秒间隔；
* 统计起点探针位于store_msg入口，**不包含mq_receive内部向用户缓冲区copy_to_user拷贝耗时**。
*/
#define MQ_DELIVERY_QUEUED 0

/**
* @brief DIRECT：发送时已有阻塞等待的接收进程，内核绕过队列直接交付消息
*
* @details
* mq_send执行瞬间，接收进程已经阻塞在mq_timedreceive等待消息；内核调用pipelined_send直接转交msg_msg对象，
* 消息**不会插入红黑树队列**，没有队列驻留过程，因此驻留时间residence_ns按业务定义填0。
*/
#define MQ_DELIVERY_DIRECT 1
/** @} */

/**
* @struct Msgqueue_ctrl
* @brief 用户态下发给BPF程序的运行时控制配置，通过BPF map传给内核探针
*
* @note
* 阈值min_delay_ns仅过滤ringbuf输出的明细事件；模块退出输出的汇总统计**不受该阈值过滤**。
* 目的：防止过滤掉慢消息之后，queued的平均驻留时间统计失真丢失样本。
*
* 容器PID场景：target_pid是工具所在PID命名空间的TGID；容器内部传入的PID需要做跨命名空间转换。
* 通过pidns_dev/pidns_ino标记目标进程所属pid命名空间，在内核中将捕获到的task_struct转换成工具命名空间下可见TGID。
*/
struct Msgqueue_ctrl {
	bpf_bool_t enable;          ///< true=开启消息队列追踪；false=关闭全部探针采集
	bpf_u64_t min_delay_ns;    ///< ringbuf明细事件输出阈值：仅驻留时间>=该值才投递ringbuf；单位纳秒
	bpf_s32_t target_pid;       ///< 过滤TGID；0代表监控系统全部进程；非0开启PID过滤
	bpf_u32_t _pad;             ///< 内存对齐填充，消除结构体字段间隙，保证BPF CO‑RE跨架构兼容
	bpf_u64_t pidns_dev;        ///< PID命名空间的dev设备号，来自/proc/<pid>/ns/pid的stat()结果
	bpf_u64_t pidns_ino;        ///< PID命名空间的inode号，用于在内核定位目标pid namespace，做PID翻译
};

/**
* @struct Msgqueue_event
* @brief 单条POSIX消息驻留事件，BPF通过ringbuf推送到用户态的明细数据结构
*
* @warning
* send_mqdes / recv_mqdes 是各自进程上下文内的文件描述符；
* 文件描述符编号仅对本进程有效，发送者fd与接收者fd不保证相等，不可直接对比。
*
* @note
* QUEUED事件：同时捕获发送进程、接收进程完整信息；
* DIRECT事件：虽然消息不走队列，BPF通过msg_msg对象做跨CPU上下文关联，同样回填sender/receiver pid、comm、fd。
*/
struct Msgqueue_event {
	bpf_u64_t ts_ns;                ///< 事件时间戳(CLOCK_MONOTONIC), 单位纳秒
	bpf_u64_t residence_ns;         ///< 消息内核队列驻留纳秒；DIRECT类型固定为0
	bpf_u64_t msg_len;              ///< POSIX消息有效载荷字节长度
	bpf_s32_t sender_pid;           ///< 发送方TGID（已经翻译到工具PID命名空间）
	bpf_s32_t receiver_pid;         ///< 接收方TGID（已经翻译到工具PID命名空间）
	bpf_s32_t send_mqdes;           ///< 发送进程调用mq_send使用的mq_open返回文件描述符
	bpf_s32_t recv_mqdes;           ///< 接收进程调用mq_receive使用的mq_open返回文件描述符
	bpf_u32_t msg_prio;             ///< POSIX消息优先级，0~MQ_PRIO_MAX
	bpf_u32_t delivery_type;        ///< 交付类型，取值 MQ_DELIVERY_QUEUED / MQ_DELIVERY_DIRECT
	bpf_s8_t sender_comm[TASK_COMM_LEN];    ///< 发送进程task_struct->comm进程名
	bpf_s8_t receiver_comm[TASK_COMM_LEN];  ///< 接收进程task_struct->comm进程名
};

/**
* @struct Msgqueue_stats
* @brief 全局聚合统计结构体；BPF程序退出时导出给用户态打印汇总报告
*
* @details
* 所有计数字段含义：
* - queued_*：只统计真正进入内核红黑树队列，之后被正常接收消费的消息；包含计数、总驻留纳秒、最大驻留纳秒
* - direct_count：统计pipelined_send直接交付，没有入队列的消息数量
* - unmatched_count：取出消息时，BPF追踪Map找不到对应的入队记录
*     诱因：1）工具启动前队列已存在存量消息；2）BPF跟踪Map LRU容量不足，旧记录被淘汰
* - tracking_drop_count：内部追踪哈希Map更新/插入失败；内存压力、map容量打满会触发；代表丢失消息关联跟踪
* - ringbuf_drop_count：ringbuf环形缓冲区满，明细事件被丢弃；仅影响明细输出，统计计数不受丢弃影响
*/
struct Msgqueue_stats {
	bpf_u64_t queued_count;         ///< QUEUED模式总消息条数
	bpf_u64_t queued_total_ns;      ///< QUEUED消息驻留时间累加总和(ns)
	bpf_u64_t queued_max_ns;        ///< QUEUED消息观测到最大驻留时延(ns)
	bpf_u64_t direct_count;         ///< DIRECT直接交付模式消息总条数
	bpf_u64_t unmatched_count;      ///< 消息出队但是找不到入队追踪记录的样本数
	bpf_u64_t tracking_drop_count; ///< 内部跟踪map写入失败计数
	bpf_u64_t ringbuf_drop_count;   ///< ringbuf缓冲区满，丢弃明细事件计数
};

#ifndef __BPF__
#include <stdbool.h>

/**
* @brief 启动POSIX消息队列驻留时间监控主入口（用户态API）
*
* @param[in] poll_timeout_ms ringbuf轮询等待超时时间，单位毫秒；0为非阻塞，>0阻塞等待事件到达
* @param[in] enable true启用探针采集；false关闭采集
* @param[in] target_pid 待过滤TGID，0代表监控全部进程；容器场景需要传入翻译后宿主机命名空间TGID
* @param[in] min_delay_ns ringbuf明细事件最小驻留阈值，小于该值不会向ringbuf输出明细；单位纳秒
*
* @return int
* @retval 0 执行成功
* @retval <0 错误码，包含bpf加载、map创建、探针挂载、ringbuf初始化失败
*
* @note
* 调用后内部完成bpf骨架加载、Ctrl下发Msgqueue_ctrl配置、ringbuf事件循环；
* 函数返回时会自动导出Msgqueue_stats统计数据，做资源清理。
*/
int msgqueue_run(int poll_timeout_ms, bool enable,
		bpf_s32_t target_pid, bpf_u64_t min_delay_ns);

#endif /* __BPF__ */

#endif /* __MSGQUEUE_H */
