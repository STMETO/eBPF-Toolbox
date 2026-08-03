#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "msgqueue.h"
#include "common/pid_namespace.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MQ_MAX_INFLIGHT_CALLS 8192
#define MQ_MAX_TRACKED_MESSAGES 16384

/*
 * 发送调用的线程上下文。key 使用全局 pid_tgid，而不是 CPU：
 * mq_timedsend() 在队列满时会睡眠，任务醒来后可能已经迁移到另一 CPU，
 * PERCPU_ARRAY 无法保证入口和后续探针读到同一槽位。
 */
struct mq_send_ctx {
	bpf_u64_t msg_key;
	bpf_u64_t msg_len;
	bpf_s32_t sender_pid;
	bpf_s32_t mqdes;
	bpf_u32_t msg_prio;
	bpf_s8_t sender_comm[TASK_COMM_LEN];
};

/* 接收调用上下文，用于给接收路径交付的消息补充实际接收者信息。 */
struct mq_recv_ctx {
	bpf_s32_t receiver_pid;
	bpf_s32_t mqdes;
	bpf_s8_t receiver_comm[TASK_COMM_LEN];
};

/*
 * load_msg() 已创建内核消息对象、但对象尚未确认入队时的元数据。
 * 队列满时发送线程可以长时间睡眠，因此这里也必须按消息对象而非 CPU
 * 保存。msg_insert() 成功后，元数据会被移入 queued_messages。
 */
struct mq_pending_msg {
	bpf_u64_t msg_len;
	bpf_s32_t sender_pid;
	bpf_s32_t mqdes;
	bpf_u32_t msg_prio;
	bpf_s8_t sender_comm[TASK_COMM_LEN];
};

/* 一条已经成功进入 mqueue 红黑树、正在等待接收者取出的消息。 */
struct mq_queued_msg {
	bpf_u64_t enqueue_ns;
	bpf_u64_t msg_len;
	bpf_s32_t sender_pid;
	bpf_s32_t mqdes;
	bpf_u32_t msg_prio;
	bpf_s8_t sender_comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MQ_MAX_INFLIGHT_CALLS);
	__type(key, bpf_u64_t);       /* 全局 pid_tgid，唯一标识线程 */
	__type(value, struct mq_send_ctx);
} active_sends SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MQ_MAX_INFLIGHT_CALLS);
	__type(key, bpf_u64_t);       /* 全局 pid_tgid，唯一标识线程 */
	__type(value, struct mq_recv_ctx);
} active_receives SEC(".maps");

/*
 * LRU_HASH 给异常退出或极端高并发留下有界兜底，避免关联项无限增长。
 * key 是 struct msg_msg * 转成的无符号值；同一对象会贯穿装载、入队和
 * 出队路径，因此比消息内容哈希更准确，也不存在相同消息内容碰撞。
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MQ_MAX_TRACKED_MESSAGES);
	__type(key, bpf_u64_t);       /* struct msg_msg * */
	__type(value, struct mq_pending_msg);
} pending_messages SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MQ_MAX_TRACKED_MESSAGES);
	__type(key, bpf_u64_t);       /* struct msg_msg * */
	__type(value, struct mq_queued_msg);
} queued_messages SEC(".maps");

/*
 * 发送端已确认走直接交付、但接收端尚未开始复制消息时的短生命周期记录。
 * 单独保留它可以让接收端补全真实 receiver_pid，而不是只在发送返回时
 * 上报一个接收者未知的 DIRECT 事件。
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MQ_MAX_TRACKED_MESSAGES);
	__type(key, bpf_u64_t);       /* struct msg_msg * */
	__type(value, struct mq_pending_msg);
} direct_messages SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Msgqueue_ctrl);
} ctrl_map SEC(".maps");

/*
 * 统计 Map 是全局 ARRAY。所有并发累加均使用 BPF 原子指令，最大值使用
 * 有界 CAS 重试，避免原实现直接 ++ 在多 CPU 下丢计数。
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Msgqueue_stats);
} stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline struct Msgqueue_ctrl *get_ctrl(void)
{
	int key = 0;

	return bpf_map_lookup_elem(&ctrl_map, &key);
}

static __always_inline struct Msgqueue_stats *get_stats(void)
{
	int key = 0;

	return bpf_map_lookup_elem(&stats_map, &key);
}

/* 当前进程在工具所在 PID namespace 中可见的 TGID。 */
static __always_inline bpf_s32_t current_tgid(const struct Msgqueue_ctrl *ctrl)
{
	bpf_u64_t pid_tgid;

	pid_tgid = app_current_pid_tgid_ns(ctrl->pidns_dev, ctrl->pidns_ino);
	return (bpf_s32_t)(pid_tgid >> 32);
}

/* Linux ERR_PTR 的错误值位于无符号地址空间最后 4095 个值。 */
static __always_inline bool valid_msg_ptr(const struct msg_msg *msg)
{
	bpf_u64_t addr = (bpf_u64_t)msg;

	return addr != 0 && addr < (bpf_u64_t)-4095;
}

static __always_inline void stats_add(bpf_u64_t *value, bpf_u64_t delta)
{
	__sync_fetch_and_add(value, delta);
}

/*
 * CAS 可能因另一 CPU 同时更新而失败；固定十六次重试让 verifier 能证明
 * 循环有界。若竞争者已经写入更大值，则无需继续更新。
 */
static __always_inline void stats_update_max(bpf_u64_t *max_value,
					      bpf_u64_t candidate)
{
#pragma unroll
	for (int i = 0; i < 16; i++) {
		bpf_u64_t old = *max_value;

		if (candidate <= old)
			break;
		if (__sync_val_compare_and_swap(max_value, old, candidate) == old)
			break;
	}
}

static __always_inline bool pid_matches(const struct Msgqueue_ctrl *ctrl,
					 bpf_s32_t sender_pid,
					 bpf_s32_t receiver_pid)
{
	return ctrl->target_pid == 0 || ctrl->target_pid == sender_pid ||
	       ctrl->target_pid == receiver_pid;
}

/* 填充并提交一条已排队消息的驻留事件。 */
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
	residence_ns = now - queued->enqueue_ns;

	/* 汇总统计覆盖所有 PID 匹配样本；明细事件才受阈值控制。 */
	stats = get_stats();
	if (stats) {
		stats_add(&stats->queued_count, 1);
		stats_add(&stats->queued_total_ns, residence_ns);
		stats_update_max(&stats->queued_max_ns, residence_ns);
	}

	if (ctrl->min_delay_ns && residence_ns < ctrl->min_delay_ns)
		return;

	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event) {
		if (stats)
			stats_add(&stats->ringbuf_drop_count, 1);
		return;
	}

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
	__builtin_memcpy(event->receiver_comm, receiver->receiver_comm,
			 TASK_COMM_LEN);
	bpf_ringbuf_submit(event, 0);
}

/*
 * 当发送时已经有接收线程等待，Linux 会绕过队列直接把消息指针交给
 * 接收者。此时不存在 msg_insert/msg_get 配对，驻留时间按定义记录为 0。
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

	stats = get_stats();
	if (stats)
		stats_add(&stats->direct_count, 1);

	/* residence_ns=0，配置任何正阈值时 DIRECT 明细自然被过滤。 */
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
	__builtin_memcpy(event->receiver_comm, receiver->receiver_comm,
			 TASK_COMM_LEN);
	bpf_ringbuf_submit(event, 0);
}

/*
 * do_mq_timedsend 入口只记录调用元数据。真正的 struct msg_msg * 要等
 * load_msg() 返回后才能取得，所以发送上下文先以线程 pid_tgid 暂存。
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

	pid_tgid = bpf_get_current_pid_tgid();
	send.sender_pid = current_tgid(ctrl);
	if (!send.sender_pid)
		return 0;
	send.mqdes = (bpf_s32_t)mqdes;
	send.msg_len = msg_len;
	send.msg_prio = msg_prio;
	bpf_get_current_comm(send.sender_comm, sizeof(send.sender_comm));
	if (bpf_map_update_elem(&active_sends, &pid_tgid, &send, BPF_ANY)) {
		struct Msgqueue_stats *stats = get_stats();

		if (stats)
			stats_add(&stats->tracking_drop_count, 1);
	}
	return 0;
}

/*
 * load_msg() 完成用户数据到内核 struct msg_msg 的复制。只处理当前正处于
 * POSIX mq_timedsend 的线程，避免把 System V 消息队列的 load_msg 调用
 * 混入本模块。
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
	if (!valid_msg_ptr(ret))
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	send = bpf_map_lookup_elem(&active_sends, &pid_tgid);
	if (!send)
		return 0;

	msg_key = (bpf_u64_t)ret;
	pending.msg_len = send->msg_len;
	pending.sender_pid = send->sender_pid;
	pending.mqdes = send->mqdes;
	pending.msg_prio = send->msg_prio;
	__builtin_memcpy(pending.sender_comm, send->sender_comm, TASK_COMM_LEN);

	if (bpf_map_update_elem(&pending_messages, &msg_key, &pending, BPF_ANY)) {
		struct Msgqueue_stats *stats = get_stats();

		if (stats)
			stats_add(&stats->tracking_drop_count, 1);
		return 0;
	}

	/* 保存对象 key，供 do_mq_timedsend 返回时识别直接交付或失败路径。 */
	send->msg_key = msg_key;
	return 0;
}

/*
 * msg_insert 返回 0 的时刻就是消息成功进入队列的时刻。该函数既覆盖
 * 普通发送，也覆盖“队列原来已满，接收一条后把阻塞发送者消息补入队列”
 * 的 pipelined_receive 路径；后者当前线程是接收者，因此必须从以消息
 * 对象为 key 的 pending_messages 取回真正发送者，而不能使用 current。
 */
SEC("fexit/msg_insert")
int BPF_PROG(mq_msg_insert_exit, struct msg_msg *msg,
	     struct mqueue_inode_info *info, int ret)
{
	struct mq_pending_msg *pending;
	struct mq_queued_msg queued = {};
	bpf_u64_t msg_key;

	(void)info;
	if (ret != 0 || !msg)
		return 0;

	msg_key = (bpf_u64_t)msg;
	pending = bpf_map_lookup_elem(&pending_messages, &msg_key);
	if (!pending)
		return 0;

	queued.enqueue_ns = bpf_ktime_get_ns();
	queued.msg_len = pending->msg_len;
	queued.sender_pid = pending->sender_pid;
	queued.mqdes = pending->mqdes;
	queued.msg_prio = pending->msg_prio;
	__builtin_memcpy(queued.sender_comm, pending->sender_comm, TASK_COMM_LEN);

	if (bpf_map_update_elem(&queued_messages, &msg_key, &queued, BPF_ANY)) {
		struct Msgqueue_stats *stats = get_stats();

		if (stats)
			stats_add(&stats->tracking_drop_count, 1);
	}

	/* 成功或失败都删除 pending，防止 send 返回时误判为 DIRECT。 */
	bpf_map_delete_elem(&pending_messages, &msg_key);
	return 0;
}

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

/*
 * 统一处理接收端观察到的消息对象。
 *
 * queued_messages 命中表示消息真正排过队；direct_messages 命中表示发送
 * 返回先于接收端；pending_messages 命中表示接收端跑得更快、发送 fexit
 * 尚未来得及把记录移入 direct_messages。三个分支共同解决直接交付路径
 * 中发送/接收线程在不同 CPU 上并发执行的竞态。
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
	pid_tgid = bpf_get_current_pid_tgid();
	receiver = bpf_map_lookup_elem(&active_receives, &pid_tgid);

	if (queued) {
		/* Map value 在删除后失效，因此先复制到 BPF 栈上。 */
		__builtin_memcpy(&queued_copy, queued, sizeof(queued_copy));
		bpf_map_delete_elem(&queued_messages, &msg_key);
		if (receiver)
			submit_queued(&queued_copy, receiver);
		return;
	}

	/* 发送 fexit 已经把 DIRECT 元数据从 pending 移到 direct。 */
	direct = bpf_map_lookup_elem(&direct_messages, &msg_key);
	if (direct) {
		__builtin_memcpy(&direct_copy, direct, sizeof(direct_copy));
		bpf_map_delete_elem(&direct_messages, &msg_key);
		if (receiver)
			submit_direct(&direct_copy, receiver);
		return;
	}

	/* 接收端可能抢在发送 fexit 前运行，此时 DIRECT 元数据仍在 pending。 */
	direct = bpf_map_lookup_elem(&pending_messages, &msg_key);
	if (direct && receiver) {
		__builtin_memcpy(&direct_copy, direct, sizeof(direct_copy));
		bpf_map_delete_elem(&pending_messages, &msg_key);
		submit_direct(&direct_copy, receiver);
		return;
	}

	/*
	 * store_msg 只会对真实接收调用执行，因此可以统计未关联消息。free_msg
	 * 还用于队列销毁和发送失败，不能把那些路径计为接收缺失。
	 */
	if (receiver && count_unmatched) {
		struct Msgqueue_stats *stats = get_stats();
		struct Msgqueue_ctrl *ctrl = get_ctrl();

		if (stats && ctrl && ctrl->enable &&
		    (!ctrl->target_pid || ctrl->target_pid == receiver->receiver_pid))
			stats_add(&stats->unmatched_count, 1);
	}
	return;
}

/*
 * msg_get() 在部分内核中被编译器内联，虽然 BTF/kallsyms 仍有同名实体，
 * 却无法稳定建立 trampoline 或 kretprobe。store_msg() 是接收路径中紧随
 * 取出消息之后、开始复制到用户缓冲区之前的稳定边界；以其入口作为
 * “消息交付给接收者”的结束时刻，不包含用户缓冲区复制耗时。
 */
SEC("fentry/store_msg")
int BPF_PROG(mq_store_msg_enter, void *dest, struct msg_msg *msg, size_t len)
{
	(void)dest;
	(void)len;
	consume_message(msg, true);
	return 0;
}

/*
 * 若优先级写回用户地址失败，内核会因短路判断跳过 store_msg()，但仍会
 * free_msg()。此探针作为兜底，同时负责清理队列销毁时残留的关联记录。
 * 正常路径已在 store_msg 删除记录，因此这里不会重复上报。
 */
SEC("fentry/free_msg")
int BPF_PROG(mq_free_msg_enter, struct msg_msg *msg)
{
	consume_message(msg, false);
	return 0;
}

/*
 * send 返回时 pending 仍存在且 ret==0，说明消息没有经过 msg_insert，
 * 即被直接交给了已经等待的接收者；失败返回则只清理关联状态。
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
			__builtin_memcpy(&pending_copy, pending, sizeof(pending_copy));
			if (ret == 0) {
				/*
				 * 接收者尚未消费 pending 时，把它转移到 direct Map。
				 * 若接收者更早消费，pending 已不存在，不会重复上报。
				 */
				if (bpf_map_update_elem(&direct_messages, &send->msg_key,
							&pending_copy, BPF_ANY)) {
					struct Msgqueue_stats *stats = get_stats();

					if (stats)
						stats_add(&stats->tracking_drop_count, 1);
				}
			}
			bpf_map_delete_elem(&pending_messages, &send->msg_key);
		}
	}
	bpf_map_delete_elem(&active_sends, &pid_tgid);
	return 0;
}

/* 接收返回后删除线程上下文；阻塞期间保留，供后续消息交付探针使用。 */
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
