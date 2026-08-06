/**
* @file msgqueue.bpf.c
* @brief POSIX mqueue eBPF内核探针实现，追踪mq_send/mq_receive消息驻留时延
*
* @details
* 本BPF程序基于fentry/fexit trampoline探针，观测Linux POSIX消息队列完整生命周期；
* 区分两种内核交付路径：
* 1. QUEUED：无等待接收者，消息插入红黑树队列排队；统计消息在内核队列驻留纳秒。
* 2. DIRECT(pipelined_send)：发送瞬间已有阻塞等待接收者，消息直接转交接收方，不入队列，驻留时间置0。
*
* 关键内核函数链路：
* do_mq_timedsend -> load_msg(分配msg_msg内核消息对象) -> msg_insert(插入红黑树队列)
* do_mq_timedreceive -> msg_get取出消息 -> store_msg(拷贝消息到用户缓冲区) -> free_msg释放msg_msg
*
* 竞态说明：
* 发送线程执行mq_send队列满会发生睡眠，唤醒后线程可能发生CPU迁移；因此不能用PER‑CPU_ARRAY保存线程上下文，
* 全部使用HASH map，key采用全局pid_tgid(高32bit TGID，低32bit TID)唯一标识线程。
* 消息对象key使用struct msg_msg*指针值，作为全生命周期唯一句柄，贯穿load_msg/msg_insert/store_msg/free_msg。
*
* 兜底逻辑：
* free_msg探针兜底清理map残留项；LRU_HASH限制最大条目防止内存泄露；CAS循环更新最大值解决多CPU并发写；
* 支持PID命名空间翻译，容器内进程PID转为宿主机工具命名空间TGID；ringbuf输出明细事件，全局统计保存在stats_map。
*
* @license Dual BSD/GPL
*/

/*
================================================================================
说明：
1. TX线程：执行 mq_send()；RX线程：执行 mq_receive()，两个是完全独立线程。
2. RX线程有两种时序：
   - DIRECT路径：RX先执行 fentry do_mq_timedreceive，线程在内核睡眠阻塞；之后TX才发送消息。
   - QUEUED路径：TX发送完毕，消息驻留在BPF Map；之后RX才调用mq_receive取消息。
3. store_msg / consume_message 运行在【RX接收线程上下文】，不属于TX发送流程。
4. free_msg 兜底路径：异常、拷贝失败、mq_unlink销毁队列，不走store_msg，仅做map清理。
================================================================================

【TX线程】应用层：mq_send()
    │
    ▼
┌────────────────────────┐
│ fentry do_mq_timedsend │
└──────────┬─────────────┘
           │ 1.采集发送元数据：sender_pid / mqdes / msg_prio / msg_len / sender_comm
           │ 2.key=pid_tgid，写入 active_sends(HASH)
           ▼
      内核执行 do_mq_timedsend 内部逻辑
           │
           ▼
      load_msg() 分配 struct msg_msg、拷贝用户消息
           │
      ┌──────────────┐
      │ fexit load_msg│
      └──────┬───────┘
             │ 过滤：仅处理当前线程存在 active_sends 的调用，过滤System‑V消息队列
             │ msg_key = (bpf_u64_t)ret;  // ret为struct msg_msg*
             │ if (!valid_msg_ptr(ret)) 直接返回，丢弃追踪
             │ 1.组装 mq_pending_msg，写入 pending_messages(LRU_HASH, key=msg_key)
             │ 2.回填 active_sends[pid_tgid]->msg_key = msg_key
             ▼
      ├────────────────────────────────────────────┐
      │ 内核运行时二分支                           │
      │ A. 无正在阻塞等待的接收者 → 调用msg_insert  │ B.已有阻塞接收者 → pipelined_send，不调用msg_insert(DIRECT路径)
      ▼(A分支 QUEUED)                              ▼(B分支 DIRECT)
┌────────────────┐                     do_mq_timedsend 继续向下执行
│ fexit msg_insert│
└───────┬────────┘
        │ ret == 0 入队成功：
        │   1.查询 pending_messages[msg_key]
        │   2.记录 enqueue_ns = bpf_ktime_get_ns()
        │   3.组装 mq_queued_msg，写入 queued_messages(LRU_HASH, key=msg_key)
        │   4.bpf_map_delete_elem(&pending_messages, &msg_key)
        │ ret != 0：入队失败，不继续追踪
        ▼
do_mq_timedsend 继续向下执行
        │
┌───────────────────────┐
│ fexit do_mq_timedsend │   // TX系统调用返回探针
└──────────┬────────────┘
           │ 查询 active_sends[pid_tgid]
           │ if (send->msg_key 有效) {
           │     查询 pending_messages[msg_key]
           │     ├─存在 && ret == 0：DIRECT路径
           │     │    拷贝 mq_pending_msg 到栈；写入 direct_messages(LRU_HASH, key=msg_key)
           │     │    bpf_map_delete_elem(&pending_messages, &msg_key)
           │     └─不存在：已经被msg_insert删除，QUEUED路径，不做操作
           │ }
           │ bpf_map_delete_elem(&active_sends, &pid_tgid); // 清理TX线程上下文
           ▼
TX线程 mq_send() 返回应用层
           │
           ▼
【消息驻留阶段，消息元数据保存在BPF LRU Map中】
    QUEUED路径：queued_messages[msg_key]
    DIRECT路径：direct_messages[msg_key]
--------------------------------------------------------------------------------

【RX线程】应用层：mq_receive()
    │
    ▼
┌──────────────────────────┐
│ fentry do_mq_timedreceive│
└────────────┬─────────────┘
             │ 1.采集接收元数据：receiver_pid / mqdes / receiver_comm
             │ 2.key=pid_tgid，写入 active_receives(HASH)
             ▼
     内核执行 do_mq_timedreceive 内部逻辑
             │
             ▼
     此处RX线程可能内核睡眠阻塞，等待消息到来 
             │ 消息到达，RX线程被唤醒继续执行
             ▼
     ┌──────────────────┐
     │ fentry store_msg │  // 消息取出后、copy_to_user之前；正常消费路径
     └────────┬─────────┘
              │ consume_message(msg, count_unmatched=true);
              ▼
     ┌────────────────────────────┐
     │ fexit do_mq_timedreceive   │
     └────────────┬───────────────┘
                  │ bpf_map_delete_elem(&active_receives, &pid_tgid); //清理RX线程上下文
                  ▼
RX线程 mq_receive() 返回应用层

--------------------------------------------------------------------------------
【兜底异常路径：不走store_msg】
内核直接执行 free_msg(msg)  // 用户拷贝出错 / mq_unlink销毁队列 / 发送失败释放消息
    │
    ▼
fentry free_msg
    │ consume_message(msg, count_unmatched=false); //仅清理map，不计unmatched_count
    ▼
return

--------------------------------------------------------------------------------
consume_message(msg, count_unmatched)
    msg_key = (bpf_u64_t)msg;
    pid_tgid = bpf_get_current_pid_tgid();
    receiver = bpf_map_lookup_elem(&active_receives, &pid_tgid);

    ├─分支1：queued_messages[msg_key] 存在  // QUEUED排队消息
    │   拷贝map值到栈 queued_copy
    │   bpf_map_delete_elem(&queued_messages, &msg_key)
    │   if(receiver) submit_queued(&queued_copy, receiver);
    │       ▶ residence_ns = bpf_ktime_get_ns() - queued_copy.enqueue_ns
    │       ▶ 更新 stats queued_count / queued_total_ns / queued_max_ns
    │       ▶ ctrl->min_delay_ns过滤，满足条件向ringbuf提交MQ_DELIVERY_QUEUED事件
    │
    ├─分支2：direct_messages[msg_key] 存在  // DIRECT：发送fexit已经完成迁移
    │   拷贝map值到栈 direct_copy
    │   bpf_map_delete_elem(&direct_messages, &msg_key)
    │   if(receiver) submit_direct(&direct_copy, receiver);
    │       ▶ residence_ns = 0，stats direct_count++
    │       ▶ min_delay_ns>0时，不输出ringbuf事件
    │
    ├─分支3：pending_messages[msg_key] 存在 // 多核竞态：store_msg先执行，send_exit还未执行
    │   拷贝map值到栈 direct_copy
    │   bpf_map_delete_elem(&pending_messages, &msg_key)
    │   if(receiver) submit_direct(&direct_copy, receiver);
    │
    └─分支4：以上全部查找失败 → unmatched
        if(receiver && count_unmatched == true) {
            stats->unmatched_count ++;
        }
        // count_unmatched==false(free_msg兜底)：不统计unmatched_count
================================================================================
*/

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "msgqueue.h"
#include "common/pid_namespace.bpf.h"

/**
* @brief BPF程序许可证，Dual BSD/GPL，允许使用GPL限定的内核helper、trampoline fentry/fexit探针
*/
char LICENSE[] SEC("license") = "Dual BSD/GPL";

/**
* @def MQ_MAX_INFLIGHT_CALLS
* @brief 最大并发正在执行mq_send/mq_receive系统调用的线程数上限
*/
#define MQ_MAX_INFLIGHT_CALLS 8192
/**
* @def MQ_MAX_TRACKED_MESSAGES
* @brief 全局最多同时追踪的msg_msg消息对象上限；pending/queued/direct三个LRU map均使用该值
*/
#define MQ_MAX_TRACKED_MESSAGES 16384

/**
* @struct mq_send_ctx
* @brief 发送线程上下文，保存do_mq_timedsend入口采集到发送元数据
* @note key为全局pid_tgid(TGID<<32 | TID)；线程睡眠发生CPU迁移，HASH不受CPU变更影响
*/
struct mq_send_ctx {
	bpf_u64_t msg_key;        ///< 保存load_msg返回的struct msg_msg*指针值，消息对象唯一key
	bpf_u64_t msg_len;        ///< 消息有效载荷字节长度
	bpf_s32_t sender_pid;     ///< 发送进程TGID(已翻译到工具PID命名空间)
	bpf_s32_t mqdes;          ///< mq_open返回的消息队列fd，发送进程上下文内有效
	bpf_u32_t msg_prio;       ///< POSIX消息优先级
	bpf_s8_t sender_comm[TASK_COMM_LEN]; ///< 发送进程comm名字
};

/**
* @struct mq_recv_ctx
* @brief 接收线程上下文，do_mq_timedreceive入口记录接收方信息
* @note DIRECT模式发送路径拿不到接收者信息，必须在接收线程入口预先保存，消息消费时回填事件
*/
struct mq_recv_ctx {
	bpf_s32_t receiver_pid;   ///< 接收进程TGID(已翻译工具PID命名空间)
	bpf_s32_t mqdes;          ///< 接收进程使用的mqdes fd，仅接收进程内有效
	bpf_s8_t receiver_comm[TASK_COMM_LEN]; ///< 接收进程comm名字
};

/**
* @struct mq_pending_msg
* @brief load_msg执行完毕、msg_insert尚未执行阶段的消息元数据
*
* @details
* 状态：内核已经分配struct msg_msg消息对象，但是尚未插入mqueue红黑树。
* 两种去向：
* 1. msg_insert执行成功：转移元数据到queued_messages map；
* 2. 触发pipelined_send直接交付：发送fexit把元数据迁移到direct_messages map；
* 队列满场景发送线程会长时间睡眠，所以不能用per‑cpu，以msg_msg*作为key保存。
*/
struct mq_pending_msg {
	bpf_u64_t msg_len;
	bpf_s32_t sender_pid;
	bpf_s32_t mqdes;
	bpf_u32_t msg_prio;
	bpf_s8_t sender_comm[TASK_COMM_LEN];
};

/**
* @struct mq_queued_msg
* @brief 已经调用msg_insert成功插入mqueue红黑树队列的消息元数据
* @note enqueue_ns：msg_insert返回0时刻的时间戳，作为消息入队起点；
* store_msg入口时刻作为消息出队消费终点，residence_ns = now - enqueue_ns；
* 该时延不包含store_msg内部copy_to_user拷贝到用户缓冲区耗时。
*/
struct mq_queued_msg {
	bpf_u64_t enqueue_ns;     ///< 消息成功入队时间戳 CLOCK_MONOTONIC 纳秒
	bpf_u64_t msg_len;
	bpf_s32_t sender_pid;
	bpf_s32_t mqdes;
	bpf_u32_t msg_prio;
	bpf_s8_t sender_comm[TASK_COMM_LEN];
};

/**
* @map active_sends
* @brief 保存正在执行do_mq_timedsend系统调用的线程上下文
* @type BPF_MAP_TYPE_HASH
* @key pid_tgid 全局线程ID
* @value struct mq_send_ctx
* @max_entries MQ_MAX_INFLIGHT_CALLS
*/
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MQ_MAX_INFLIGHT_CALLS);
	__type(key, bpf_u64_t);       /* 全局 pid_tgid，唯一标识线程 */
	__type(value, struct mq_send_ctx);
} active_sends SEC(".maps");

/**
* @map active_receives
* @brief 保存正在执行do_mq_timedreceive系统调用的线程上下文
* @type BPF_MAP_TYPE_HASH
* @key pid_tgid 全局线程ID
* @value struct mq_recv_ctx
*/
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MQ_MAX_INFLIGHT_CALLS);
	__type(key, bpf_u64_t);       /* 全局 pid_tgid，唯一标识线程 */
	__type(value, struct mq_recv_ctx);
} active_receives SEC(".maps");

/**
* @map pending_messages
* @brief load_msg完成后，msg_insert尚未完成的消息对象；key = struct msg_msg*
* @type BPF_MAP_TYPE_LRU_HASH
* @note LRU自动淘汰，防止极端高并发或者异常路径导致map无限膨胀。
* 存放刚创建完成还未确认入队的消息对象元数据。
*/
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MQ_MAX_TRACKED_MESSAGES);
	__type(key, bpf_u64_t);       /* struct msg_msg * */
	__type(value, struct mq_pending_msg);
} pending_messages SEC(".maps");

/**
* @map queued_messages
* @brief 成功msg_insert，已经进入mqueue红黑树，等待接收消费的消息对象
* @type BPF_MAP_TYPE_LRU_HASH
*/
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MQ_MAX_TRACKED_MESSAGES);
	__type(key, bpf_u64_t);       /* struct msg_msg * */
	__type(value, struct mq_queued_msg);
} queued_messages SEC(".maps");

/**
* @map direct_messages
* @brief pipelined_send直接交付消息；发送fexit识别直接交付路径，把pending迁移到此map。
* @details 发送线程返回时接收线程可能还未执行store_msg；接收消费时从本map拿到发送方元数据，
* 用来组装DIRECT事件，补全sender信息。
* @type BPF_MAP_TYPE_LRU_HASH
*/
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MQ_MAX_TRACKED_MESSAGES);
	__type(key, bpf_u64_t);       /* struct msg_msg * */
	__type(value, struct mq_pending_msg);
} direct_messages SEC(".maps");

/**
* @map ctrl_map
* @brief 用户态下发BPF运行配置，Msgqueue_ctrl；array只有index=0一条记录
*/
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Msgqueue_ctrl);
} ctrl_map SEC(".maps");

/**
* @map stats_map
* @brief 全局统计数据Msgqueue_stats；所有计数字段使用原子操作多CPU安全累加
*/
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Msgqueue_stats);
} stats_map SEC(".maps");

/**
* @map rb
* @brief ringbuf环形缓冲区，向用户态推送Msgqueue_event明细事件；大小256KB
*/
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
* @brief 获取BPF运行控制配置ctrl_map[0]
* @return 指针；NULL代表查找失败
*/
static __always_inline struct Msgqueue_ctrl *get_ctrl(void)
{
	int key = 0;

	return bpf_map_lookup_elem(&ctrl_map, &key);
}

/**
* @brief 获取全局统计结构体stats_map[0]
* @return 指针；NULL代表查找失败
*/
static __always_inline struct Msgqueue_stats *get_stats(void)
{
	int key = 0;

	return bpf_map_lookup_elem(&stats_map, &key);
}

/**
* @brief 获取当前进程在工具PID命名空间下可见TGID，调用pid_namespace.bpf.h提供的helper
* @param ctrl 指向Msgqueue_ctrl，携带pidns_dev/pidns_ino用于跨命名空间转换
* @return 转换完成TGID，0表示转换失败
*/
static __always_inline bpf_s32_t current_tgid(const struct Msgqueue_ctrl *ctrl)
{
	bpf_u64_t pid_tgid;

	/* 将current task_struct转换到指定pidns的tgid */
	pid_tgid = app_current_pid_tgid_ns(ctrl->pidns_dev, ctrl->pidns_ino);
	return (bpf_s32_t)(pid_tgid >> 32);
}

/**
* @brief 校验struct msg_msg*指针有效性，过滤ERR_PTR错误返回值
* @param msg 内核返回msg_msg对象指针
* @return true 指针有效；false是ERR_PTR错误或者NULL
* @note Linux内核ERR_PTR错误码落在地址空间最后4095个地址。
*/
static __always_inline bool valid_msg_ptr(const struct msg_msg *msg)
{
	bpf_u64_t addr = (bpf_u64_t)msg;

	return addr != 0 && addr < (bpf_u64_t)-4095;
}

/**
* @brief 原子加法，多CPU安全更新统计计数
* @param value 统计变量指针
* @param delta 累加增量
*/
static __always_inline void stats_add(bpf_u64_t *value, bpf_u64_t delta)
{
	__sync_fetch_and_add(value, delta);
}

/**
* @brief 带CAS循环更新最大值；解决多CPU并发写max_ns竞争问题
* @param max_value 最大值字段指针
* @param candidate 新观测到候选时延
*
* @note
* BPF verifier禁止无界循环；#pragma unroll完全展开循环固定最多16次重试。
* 如果candidate小于等于旧值直接break无需更新；CAS成功也break；
* CAS失败说明其它CPU已经更新更大值，下一轮继续比较。
*/
static __always_inline void stats_update_max(bpf_u64_t *max_value,
						bpf_u64_t candidate)
{
#pragma unroll
	for (int i = 0; i < 16; i++) {
		bpf_u64_t old = *max_value;

		/* 候选值不大于已保存最大值，不需要更新 */
		if (candidate <= old)
			break;
		/* CAS：旧值匹配才写入candidate；返回等于old代表更新成功 */
		if (__sync_val_compare_and_swap(max_value, old, candidate) == old)
			break;
	}
}

/**
* @brief PID过滤匹配逻辑；target_pid=0全部放行；发送方或接收方任一匹配即命中
* @param ctrl 运行时配置
* @param sender_pid 发送方TGID
* @param receiver_pid 接收方TGID
* @return true匹配，false跳过该消息事件
*/
static __always_inline bool pid_matches(const struct Msgqueue_ctrl *ctrl,
					bpf_s32_t sender_pid,
					bpf_s32_t receiver_pid)
{
	return ctrl->target_pid == 0 || ctrl->target_pid == sender_pid ||
		ctrl->target_pid == receiver_pid;
}

/**
* @brief 提交QUEUED类型消息事件，消息真实进入内核红黑树队列
*
* @param queued 来自queued_messages map，消息入队元数据
* @param receiver 当前接收线程上下文active_receives取出
*
* @note 业务规则：汇总统计统计**所有pid匹配样本，不受min_delay_ns阈值过滤**；
* ringbuf明细事件才会判断min_delay_ns，避免过滤慢消息后平均值失真。
*/
static __always_inline void submit_queued(const struct mq_queued_msg *queued,
					const struct mq_recv_ctx *receiver)
{
	struct Msgqueue_stats *stats;
	struct Msgqueue_event *event;
	struct Msgqueue_ctrl *ctrl;
	bpf_u64_t now;
	bpf_u64_t residence_ns;

	ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return;
	if (!pid_matches(ctrl, queued->sender_pid, receiver->receiver_pid))
		return;

	now = bpf_ktime_get_ns();
	/* 驻留时间：msg_insert成功入队 -> store_msg入口时刻；不含copy_to_user耗时 */
	residence_ns = now - queued->enqueue_ns;

	/* ===== 全局统计：全部样本计入，不受min_delay_ns影响 ===== */
	stats = get_stats();
	if (stats) {
		stats_add(&stats->queued_count, 1);
		stats_add(&stats->queued_total_ns, residence_ns);
		stats_update_max(&stats->queued_max_ns, residence_ns);
	}

	/* ===== ringbuf明细事件：小于阈值直接返回，不上报用户态 ===== */
	if (ctrl->min_delay_ns && residence_ns < ctrl->min_delay_ns)
		return;

	/* 向ringbuf预留事件内存 */
	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event) {
		/* ringbuf缓冲区满，明细丢弃；统计计数不受丢弃影响 */
		if (stats)
			stats_add(&stats->ringbuf_drop_count, 1);
		return;
	}

	/* 填充事件字段 */
	event->ts_ns = now;
	event->residence_ns = residence_ns;
	event->msg_len = queued->msg_len;
	event->sender_pid = queued->sender_pid;
	event->receiver_pid = receiver->receiver_pid;
	event->send_mqdes = queued->mqdes;
	event->recv_mqdes = receiver->mqdes;
	event->msg_prio = queued->msg_prio;
	event->delivery_type = MQ_DELIVERY_QUEUED;
	__builtin_memcpy(event->sender_comm, queued->sender_comm, TASK_COMM_LEN);
	__builtin_memcpy(event->receiver_comm, receiver->receiver_comm, TASK_COMM_LEN);
	bpf_ringbuf_submit(event, 0);
}

/**
* @brief 提交DIRECT直接交付事件，pipelined_send不走红黑树队列
* @param pending 消息发送方元数据
* @param receiver 当前接收线程上下文
* @note residence_ns固定填0；当min_delay_ns>0，DIRECT事件会被自然过滤不输出ringbuf。
*/
static __always_inline void submit_direct(const struct mq_pending_msg *pending,
					const struct mq_recv_ctx *receiver)
{
	struct Msgqueue_stats *stats;
	struct Msgqueue_event *event;
	struct Msgqueue_ctrl *ctrl;

	ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable ||
		!pid_matches(ctrl, pending->sender_pid, receiver->receiver_pid))
		return;

	/* direct计数始终统计 */
	stats = get_stats();
	if (stats)
		stats_add(&stats->direct_count, 1);

	/* min_delay_ns>0，residence_ns=0必然小于阈值，直接跳过ringbuf输出 */
	if (ctrl->min_delay_ns)
		return;

	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event) {
		if (stats)
			stats_add(&stats->ringbuf_drop_count, 1);
		return;
	}

	event->ts_ns = bpf_ktime_get_ns();
	event->residence_ns = 0;
	event->msg_len = pending->msg_len;
	event->sender_pid = pending->sender_pid;
	event->receiver_pid = receiver->receiver_pid;
	event->send_mqdes = pending->mqdes;
	event->recv_mqdes = receiver->mqdes;
	event->msg_prio = pending->msg_prio;
	event->delivery_type = MQ_DELIVERY_DIRECT;
	__builtin_memcpy(event->sender_comm, pending->sender_comm, TASK_COMM_LEN);
	__builtin_memcpy(event->receiver_comm, receiver->receiver_comm, TASK_COMM_LEN);
	bpf_ringbuf_submit(event, 0);
}

/**
* @brief fentry探针：do_mq_timedsend系统调用内核入口
*
* @param mqdes 用户态mq_open返回消息队列描述符
* @param u_msg_ptr 用户空间消息buffer指针
* @param msg_len 消息长度
* @param msg_prio 消息优先级
* @param ts 超时timespec64指针
*
* @note do_mq_timedsend入口只能拿到系统调用参数；此时struct msg_msg对象还没有分配；
* 将发送线程元数据存入active_sends，key=pid_tgid；等待后续fexit/load_msg探针使用。
*/
SEC("fentry/do_mq_timedsend")
int BPF_PROG(mq_send_enter, mqd_t mqdes, const char *u_msg_ptr,
		size_t msg_len, unsigned int msg_prio, struct timespec64 *ts)
{
	struct mq_send_ctx send = {};
	struct Msgqueue_ctrl *ctrl;
	bpf_u64_t pid_tgid;

	(void)u_msg_ptr;
	(void)ts;
	ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	/* 获取全局pid_tgid，高32bit TGID，低32bit TID */
	pid_tgid = bpf_get_current_pid_tgid();
	send.sender_pid = current_tgid(ctrl);
	if (!send.sender_pid)
		return 0;
	send.mqdes = (bpf_s32_t)mqdes;
	send.msg_len = msg_len;
	send.msg_prio = msg_prio;
	bpf_get_current_comm(send.sender_comm, sizeof(send.sender_comm));

	/* 将发送上下文存入active_sends map；BPF_ANY存在就覆盖 */
	if (bpf_map_update_elem(&active_sends, &pid_tgid, &send, BPF_ANY)) {
		struct Msgqueue_stats *stats = get_stats();

		if (stats)
			stats_add(&stats->tracking_drop_count, 1);
	}
	return 0;
}

/**
* @brief fexit探针：load_msg函数返回；load_msg负责把用户态消息拷贝、分配struct msg_msg内核对象
*
* @param src 用户源地址
* @param len 消息字节长度
* @param ret 返回值：成功返回有效struct msg_msg*，失败返回ERR_PTR
*
* @note load_msg会被System‑V消息队列也调用；通过active_sends存在与否过滤，只处理POSIX mq_timedsend线程；
* 将msg_msg*作为msg_key存入pending_messages map，保存发送方元数据；同时回填active_sends的msg_key，
* 留给do_mq_timedsend fexit探针识别DIRECT交付路径。
*/
SEC("fexit/load_msg")
int BPF_PROG(mq_load_msg_exit, const void *src, size_t len,
		struct msg_msg *ret)
{
	struct mq_pending_msg pending = {};
	struct mq_send_ctx *send;
	bpf_u64_t pid_tgid;
	bpf_u64_t msg_key;

	(void)src;
	(void)len;
	/* 过滤load_msg返回错误指针 */
	if (!valid_msg_ptr(ret))
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	/* 当前线程是否属于POSIX mq_timedsend调用；过滤System‑V消息队列load_msg调用 */
	send = bpf_map_lookup_elem(&active_sends, &pid_tgid);
	if (!send)
		return 0;

	msg_key = (bpf_u64_t)ret;
	pending.msg_len = send->msg_len;
	pending.sender_pid = send->sender_pid;
	pending.mqdes = send->mqdes;
	pending.msg_prio = send->msg_prio;
	__builtin_memcpy(pending.sender_comm, send->sender_comm, TASK_COMM_LEN);

	/* pending_messages保存刚创建未入队消息元数据 */
	if (bpf_map_update_elem(&pending_messages, &msg_key, &pending, BPF_ANY)) {
		struct Msgqueue_stats *stats = get_stats();

		if (stats)
			stats_add(&stats->tracking_drop_count, 1);
		return 0;
	}

	/* 将msg_msg对象key回填到发送线程上下文；send exit探针需要 */
	send->msg_key = msg_key;
	return 0;
}

/**
* @brief fexit探针：msg_insert返回；msg_insert把msg_msg插入mqueue_inode_info红黑树消息队列
*
* @param msg 待插入消息对象
* @param info mqueue_inode_info队列内核实例
* @param ret 返回值，0代表入队成功，负数失败
*
* @note 重要：pipelined_receive路径下，接收线程唤醒阻塞发送者，msg_insert运行在接收线程上下文！
* 所以不能使用current拿发送者信息，必须从pending_messages按msg_msg*取出发送元数据。
* ret ==0代表消息真正进入队列；此时记录enqueue_ns时间戳，迁移元数据至queued_messages；
* 同时删除pending_messages条目，防止send exit误判为DIRECT直接交付。
*/
SEC("fexit/msg_insert")
int BPF_PROG(mq_msg_insert_exit, struct msg_msg *msg,
		struct mqueue_inode_info *info, int ret)
{
	struct mq_pending_msg *pending;
	struct mq_queued_msg queued = {};
	bpf_u64_t msg_key;

	(void)info;
	/* ret!=0代表入队失败，队列满等情况，不追踪 */
	if (ret != 0 || !msg)
		return 0;

	msg_key = (bpf_u64_t)msg;
	pending = bpf_map_lookup_elem(&pending_messages, &msg_key);
	if (!pending)
		return 0;

	/* 记录消息成功入队时刻时间戳 */
	queued.enqueue_ns = bpf_ktime_get_ns();
	queued.msg_len = pending->msg_len;
	queued.sender_pid = pending->sender_pid;
	queued.mqdes = pending->mqdes;
	queued.msg_prio = pending->msg_prio;
	__builtin_memcpy(queued.sender_comm, pending->sender_comm, TASK_COMM_LEN);

	/* 迁移元数据到queued_messages map */
	if (bpf_map_update_elem(&queued_messages, &msg_key, &queued, BPF_ANY)) {
		struct Msgqueue_stats *stats = get_stats();

		if (stats)
			stats_add(&stats->tracking_drop_count, 1);
	}

	/* 必须删除pending；否则do_mq_timedsend fexit会错误识别为DIRECT消息 */
	bpf_map_delete_elem(&pending_messages, &msg_key);
	return 0;
}

/**
* @brief fentry探针：do_mq_timedreceive内核入口，接收系统调用
*
* @param mqdes 接收方消息队列fd
* @param u_msg_ptr 用户态接收缓冲区
* @param msg_len 缓冲区最大长度
* @param u_msg_prio 用户态保存优先级指针
* @param ts 超时时间指针
*
* @note DIRECT模式消息发送路径拿不到接收进程信息，因此接收入口预先保存receiver上下文；
* 消费消息store_msg探针的时候取出，填充事件receiver_pid/receiver_comm/recv_mqdes。
*/
SEC("fentry/do_mq_timedreceive")
int BPF_PROG(mq_recv_enter, mqd_t mqdes, char *u_msg_ptr,
		size_t msg_len, unsigned int *u_msg_prio, struct timespec64 *ts)
{
	struct mq_recv_ctx receiver = {};
	struct Msgqueue_ctrl *ctrl;
	bpf_u64_t pid_tgid;

	(void)u_msg_ptr;
	(void)msg_len;
	(void)u_msg_prio;
	(void)ts;
	ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	receiver.receiver_pid = current_tgid(ctrl);
	if (!receiver.receiver_pid)
		return 0;
	receiver.mqdes = (bpf_s32_t)mqdes;
	bpf_get_current_comm(receiver.receiver_comm, sizeof(receiver.receiver_comm));

	if (bpf_map_update_elem(&active_receives, &pid_tgid, &receiver, BPF_ANY)) {
		struct Msgqueue_stats *stats = get_stats();

		if (stats)
			stats_add(&stats->tracking_drop_count, 1);
	}
	return 0;
}

/**
* @brief consume_message 消息消费公共处理函数；store_msg / free_msg 都会调用
*
* @param msg 内核msg_msg消息对象指针
* @param count_unmatched true：本次是真正接收消费路径，允许统计unmatched_count；
*        false：free_msg兜底清理（队列销毁、发送失败释放），不计unmatched。
*
* @details 竞态场景说明：DIRECT模式发送fexit与接收store_msg运行在不同CPU，存在两种时序：
* 时序A：发送fexit先执行 → 将pending_messages迁移到direct_messages；消费时命中direct_messages；
* 时序B：接收store_msg先执行，发送fexit还没跑 → 元数据还停留在pending_messages；消费直接读取pending_messages；
* 两个分支全部覆盖，解决多核并发时序竞争。
*
* map值在bpf_map_delete_elem之后失效，必须先拷贝到BPF栈内存，再调用submit_xxx上报事件。
*/
static __always_inline void consume_message(struct msg_msg *msg,
						bool count_unmatched)
{
	struct mq_queued_msg *queued;
	struct mq_pending_msg *direct;
	struct mq_recv_ctx *receiver;
	struct mq_queued_msg queued_copy;
	struct mq_pending_msg direct_copy;
	bpf_u64_t pid_tgid;
	bpf_u64_t msg_key;

	if (!msg)
		return;

	msg_key = (bpf_u64_t)msg;
	queued = bpf_map_lookup_elem(&queued_messages, &msg_key);
	/* 获取当前接收线程上下文 */
	pid_tgid = bpf_get_current_pid_tgid();
	receiver = bpf_map_lookup_elem(&active_receives, &pid_tgid);

	/* ==========分支1：消息来自真实队列QUEUED模式========== */
	if (queued) {
		/* 拷贝map值到栈，delete之后map内存失效 */
		__builtin_memcpy(&queued_copy, queued, sizeof(queued_copy));
		bpf_map_delete_elem(&queued_messages, &msg_key);
		if (receiver)
			submit_queued(&queued_copy, receiver);
		return;
	}

	/* ==========分支2：DIRECT，发送fexit已经迁移元数据到direct_messages========== */
	direct = bpf_map_lookup_elem(&direct_messages, &msg_key);
	if (direct) {
		__builtin_memcpy(&direct_copy, direct, sizeof(direct_copy));
		bpf_map_delete_elem(&direct_messages, &msg_key);
		if (receiver)
			submit_direct(&direct_copy, receiver);
		return;
	}

	/* ==========分支3：接收CPU跑的更快，发送fexit尚未执行，元数据还在pending_messages========== */
	direct = bpf_map_lookup_elem(&pending_messages, &msg_key);
	if (direct && receiver) {
		__builtin_memcpy(&direct_copy, direct, sizeof(direct_copy));
		bpf_map_delete_elem(&pending_messages, &msg_key);
		submit_direct(&direct_copy, receiver);
		return;
	}

	/* ==========没有找到任何追踪记录，unmatched========== */
	/* count_unmatched=false的时候是队列销毁、发送失败释放，不计unmatched_count */
	if (receiver && count_unmatched) {
		struct Msgqueue_stats *stats = get_stats();
		struct Msgqueue_ctrl *ctrl = get_ctrl();

		if (stats && ctrl && ctrl->enable &&
			(!ctrl->target_pid || ctrl->target_pid == receiver->receiver_pid))
			stats_add(&stats->unmatched_count, 1);
	}
	return;
}

/**
* @brief fentry探针 store_msg入口；作为消息消费完成观测点
*
* @param dest 用户态目标缓冲区
* @param msg 待拷贝msg_msg消息对象
* @param len 消息长度
*
* @note msg_get内核函数部分版本会被编译器完全内联，无法挂载fentry/fexit探针；
* store_msg是接收路径稳定的探针点，位于取出消息之后，copy_to_user拷贝消息内容之前；
* 驻留时延统计到此为止，**不包含拷贝消息到用户缓冲区耗时**。
* 调用consume_message，count_unmatched=true，真正接收消费，可以统计unmatched。
*/
SEC("fentry/store_msg")
int BPF_PROG(mq_store_msg_enter, void *dest, struct msg_msg *msg, size_t len)
{
	(void)dest;
	(void)len;
	consume_message(msg, true);
	return 0;
}

/**
* @brief fentry探针 free_msg入口，兜底清理map残留记录
*
* @param msg 需要释放的msg_msg对象
*
* @note 边界case：内核某些分支会跳过store_msg，例如拷贝用户优先级地址出错短路返回；
* 消息直接进入free_msg释放；此时store_msg探针不会触发。
* 队列销毁mq_unlink，内核批量free_msg残留消息；
* 这里调用consume_message，count_unmatched=false，不会统计unmatched_count；只做map清理，不会重复上报事件。
*/
SEC("fentry/free_msg")
int BPF_PROG(mq_free_msg_enter, struct msg_msg *msg)
{
	consume_message(msg, false);
	return 0;
}

/**
* @brief fexit探针 do_mq_timedsend返回；区分DIRECT直接交付路径
*
* @param mqdes mq描述符
* @param u_msg_ptr 用户消息指针
* @param msg_len 消息长度
* @param msg_prio 优先级
* @param ts 超时
* @param ret 系统调用返回值，0发送成功，负数失败
*
* @note 判断DIRECT核心逻辑：ret==0发送成功，pending_messages中msg_key记录仍然存在；
* 说明消息没有走msg_insert入队，触发内核pipelined_send直接交付给等待接收者。
* 将pending_messages的元数据迁移至direct_messages map，留给接收store_msg探针消费。
* 最后清理active_sends发送线程上下文。
*/
SEC("fexit/do_mq_timedsend")
int BPF_PROG(mq_send_exit, mqd_t mqdes, const char *u_msg_ptr,
		size_t msg_len, unsigned int msg_prio, struct timespec64 *ts,
		int ret)
{
	struct mq_pending_msg *pending;
	struct mq_send_ctx *send;
	struct mq_pending_msg pending_copy;
	bpf_u64_t pid_tgid;

	(void)mqdes;
	(void)u_msg_ptr;
	(void)msg_len;
	(void)msg_prio;
	(void)ts;
	pid_tgid = bpf_get_current_pid_tgid();
	send = bpf_map_lookup_elem(&active_sends, &pid_tgid);
	if (!send)
		return 0;

	if (send->msg_key) {
		pending = bpf_map_lookup_elem(&pending_messages, &send->msg_key);
		if (pending) {
			/* 栈拷贝，delete之后map内存失效 */
			__builtin_memcpy(&pending_copy, pending, sizeof(pending_copy));
			if (ret == 0) {
				/* 发送成功，但是pending还存在：没有执行msg_insert，DIRECT直接交付 */
				if (bpf_map_update_elem(&direct_messages, &send->msg_key,
							&pending_copy, BPF_ANY)) {
					struct Msgqueue_stats *stats = get_stats();

					if (stats)
						stats_add(&stats->tracking_drop_count, 1);
				}
			}
			/* 删除pending_messages条目；无论DIRECT或者发送失败都清理 */
			bpf_map_delete_elem(&pending_messages, &send->msg_key);
		}
	}
	/* 清除发送线程上下文map项 */
	bpf_map_delete_elem(&active_sends, &pid_tgid);
	return 0;
}

/**
* @brief fexit探针 do_mq_timedreceive返回，清理接收线程上下文
*
* @note 接收系统调用完成，删除active_receives中pid_tgid对应的条目；
* 阻塞等待的场景：fentry提前存入active_receives，线程睡眠唤醒执行fexit，此时清理。
*/
SEC("fexit/do_mq_timedreceive")
int BPF_PROG(mq_recv_exit, mqd_t mqdes, char *u_msg_ptr,
		size_t msg_len, unsigned int *u_msg_prio, struct timespec64 *ts,
		int ret)
{
	bpf_u64_t pid_tgid = bpf_get_current_pid_tgid();

	(void)mqdes;
	(void)u_msg_ptr;
	(void)msg_len;
	(void)u_msg_prio;
	(void)ts;
	(void)ret;
	bpf_map_delete_elem(&active_receives, &pid_tgid);
	return 0;
}
