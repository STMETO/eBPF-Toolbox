// eBPF程序必须包含的内核类型定义
#include <vmlinux.h>

// eBPF核心帮助函数库
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// 包含我们自己定义的共用结构体
#include "MsgQueue_Delay.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ========================== 全局常量定义 ==========================
// 控制map的key值，固定为0（因为我们只需要一个全局控制块）
const int ctrl_key = 0;

// ========================== 内部结构体定义 ==========================
// 仅在内核态使用，不需要与用户态共享

/*
 * 发送端中间事件结构体
 * 用于跨 kprobe/kretprobe 暂存发送流程的完整信息
 * u_msg_ptr/src 为用户态指针，BPF中仅存储/比较，不解引用
 */
struct send_events {
	bpf_s32_t send_pid;         // 发送消息的进程 PID
	bpf_u64_t Key_msg_ptr;      // 内核消息块指针（作为唯一 KEY，关联接收端）
	bpf_s32_t mqdes;            // 消息队列描述符
	bpf_u64_t msg_len;          // 发送的消息长度
	bpf_u32_t msg_prio;         // 消息优先级
	bpf_u64_t u_msg_ptr;        // 用户态传入的消息缓冲区指针（入参）
	bpf_u64_t src;              // 内核态读取消息时的源地址（load_msg 使用）
	bpf_u64_t send_enter_time;  // 进入 do_mq_timedsend 内核函数的时间戳
	bpf_u64_t send_exit_time;   // 离开 do_mq_timedsend 内核函数的时间戳
};

/*
 * 接收端中间事件结构体
 * 用于跨 kprobe/kretprobe 暂存接收流程的完整信息
 */
struct rcv_events {
	bpf_s32_t rcv_pid;          // 接收消息的进程 PID
	bpf_u64_t Key_msg_ptr;      // 内核消息块指针（与发送端 KEY 一一对应）
	bpf_s32_t mqdes;            // 消息队列描述符
	bpf_u64_t msg_len;          // 接收的消息长度
	bpf_u32_t msg_prio;         // 接收消息的优先级
	bpf_u64_t u_msg_ptr;        // 用户态传入的接收缓冲区指针（入参）
	bpf_u64_t dest;             // 内核态写入消息时的目标地址（store_msg 使用）
	bpf_u64_t rcv_enter_time;   // 进入 do_mq_timedreceive 内核函数的时间戳
	bpf_u64_t rcv_exit_time;    // 离开 do_mq_timedreceive 内核函数的时间戳
};

// ========================== eBPF MAP 定义 ==========================

/*
 * 1. 发送端第一阶段 map
 * 作用：记录 pid → 发送事件 的关系
 * key：进程 PID
 * value：struct send_events
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, bpf_s32_t);
	__type(value, struct send_events);
} send_msg1 SEC(".maps");

/*
 * 2. 发送端第二阶段 map
 * 作用：记录 内核消息块地址 → 发送事件 的关系
 * key：内核消息块指针（u64）
 * value：struct send_events
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, bpf_u64_t);
	__type(value, struct send_events);
} send_msg2 SEC(".maps");

/*
 * 3. 接收端第一阶段 map
 * 作用：记录 pid → 接收事件 的关系
 * key：进程 PID
 * value：struct rcv_events
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, bpf_s32_t);
	__type(value, struct rcv_events);
} rcv_msg1 SEC(".maps");

/*
 * 4. 全局控制 map
 * 作用：用户态设置 enable=true/false，控制 eBPF 是否采集数据
 * key：固定 0
 * value：struct MsgQueue_Delay_ctrl
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct MsgQueue_Delay_ctrl);
} ctrl_map SEC(".maps");

/*
 * 5. 环形缓冲区（ringbuf）
 * 作用：eBPF -> 用户态 传递采集到的事件数据
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);  // 256KB 缓冲区大小
} rb SEC(".maps");

// ========================== 工具函数 ==========================

/*
 * 获取监控开关状态
 * 返回值：
 *   NULL = 未初始化 或 监控关闭
 *   非NULL = 可以开始采集数据
 */
static inline struct MsgQueue_Delay_ctrl *get_ctrl(void)
{
	struct MsgQueue_Delay_ctrl *ctrl;
	ctrl = bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
	if (!ctrl || !ctrl->enable)
		return NULL;
	return ctrl;
}

// ========================== 挂载点：发送端 ==========================

/*
 * kprobe/do_mq_timedsend
 * 触发时机：进程调用 mq_send 进入内核时
 * 作用：记录发送进程的 PID、进入时间、用户态缓冲区地址
 */
SEC("kprobe/do_mq_timedsend")
int BPF_KPROBE(mq_timedsend,
		mqd_t mqdes,
		const char *u_msg_ptr,
		size_t msg_len,
		unsigned int msg_prio,
		struct timespec64 *ts)
{
	struct MsgQueue_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	u64 send_enter_time = bpf_ktime_get_ns();
	bpf_s32_t pid = (bpf_s32_t)bpf_get_current_pid_tgid();

	/* 将消息暂存至 send_events 结构体中 */
	struct send_events mq_send_info = {};
	mq_send_info.send_pid = pid;
	mq_send_info.send_enter_time = send_enter_time;
	mq_send_info.mqdes = (bpf_s32_t)mqdes;
	mq_send_info.msg_len = (bpf_u64_t)msg_len;
	mq_send_info.msg_prio = msg_prio;
	mq_send_info.u_msg_ptr = (bpf_u64_t)u_msg_ptr;

	bpf_map_update_elem(&send_msg1, &pid, &mq_send_info, BPF_ANY);
	return 0;
}

/*
 * kprobe/load_msg
 * 触发时机：内核执行 load_msg 函数，从用户态拷贝消息时
 * 作用：记录内核读取消息的源地址 src，补全发送事件信息
 */
SEC("kprobe/load_msg")
int BPF_KPROBE(load_msg_enter, const void *src, size_t len)
{
	struct MsgQueue_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	bpf_s32_t pid = (bpf_s32_t)bpf_get_current_pid_tgid();

	/* 记录 load_msg 入参 src */
	struct send_events *mq_send_info = bpf_map_lookup_elem(&send_msg1, &pid);
	if (!mq_send_info)
		return 0;

	mq_send_info->src = (bpf_u64_t)src;
	return 0;
}

/*
 * kretprobe/load_msg
 * 触发时机：load_msg 函数返回时
 * 作用：获取内核消息块地址作为 key，建立 message → mq_send_info 的哈希表
 */
SEC("kretprobe/load_msg")
int BPF_KRETPROBE(load_msg_exit, void *ret)
{
	struct MsgQueue_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	bpf_s32_t pid = (bpf_s32_t)bpf_get_current_pid_tgid();

	/* 获取发送端第一阶段信息 */
	struct send_events *mq_send_info = bpf_map_lookup_elem(&send_msg1, &pid);
	if (!mq_send_info)
		return 0;

	/*
	 * 确认这次 load_msg 确实是当前进程的发送操作：
	 * 用户态传入的指针 == 内核读取的源地址，且 PID 匹配
	 */
	bpf_u64_t Key_msg_ptr;
	if (mq_send_info->u_msg_ptr == mq_send_info->src &&
	    pid == mq_send_info->send_pid) {
		Key_msg_ptr = (bpf_u64_t)ret;  // ret = 内核消息块地址
		mq_send_info->Key_msg_ptr = Key_msg_ptr;
	} else {
		return 0;
	}

	/*
	 * 建立第二阶段哈希表：
	 * Key = 内核消息块地址（唯一 ID）
	 * Value = 完整的发送信息结构体
	 */
	bpf_map_update_elem(&send_msg2, &Key_msg_ptr, mq_send_info, BPF_ANY);
	return 0;
}

/*
 * kretprobe/do_mq_timedsend
 * 触发时机：mq_send 彻底执行完、返回用户态之前
 * 作用：记录发送结束时间，更新到第二阶段哈希表，清理第一阶段临时数据
 */
SEC("kretprobe/do_mq_timedsend")
int BPF_KRETPROBE(do_mq_timedsend_exit, void *ret)
{
	struct MsgQueue_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	u64 send_exit_time = bpf_ktime_get_ns();
	bpf_s32_t pid = (bpf_s32_t)bpf_get_current_pid_tgid();

	/* 从第一阶段获取 Key_msg_ptr */
	struct send_events *mq_send_info1 = bpf_map_lookup_elem(&send_msg1, &pid);
	if (!mq_send_info1)
		return 0;

	bpf_u64_t Key = mq_send_info1->Key_msg_ptr;

	/* 更新第二阶段的时间戳 */
	struct send_events *mq_send_info2 = bpf_map_lookup_elem(&send_msg2, &Key);
	if (!mq_send_info2)
		return 0;

	mq_send_info2->send_exit_time = send_exit_time;

	/* 清理第一阶段临时数据 */
	bpf_map_delete_elem(&send_msg1, &pid);
	return 0;
}

// ========================== 挂载点：接收端 ==========================

/*
 * kprobe/do_mq_timedreceive
 * 触发时机：进程调用 mq_receive 进入内核时
 * 作用：记录接收进程的 PID、进入时间、用户态缓冲区地址
 */
SEC("kprobe/do_mq_timedreceive")
int BPF_KPROBE(mq_timedreceive_entry,
		mqd_t mqdes,
		const char *u_msg_ptr,
		size_t msg_len,
		unsigned int msg_prio,
		struct timespec64 *ts)
{
	struct MsgQueue_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	u64 rcv_enter_time = bpf_ktime_get_ns();
	bpf_s32_t pid = (bpf_s32_t)bpf_get_current_pid_tgid();

	/* 暂存接收端初始信息 */
	struct rcv_events mq_rcv_info = {};
	mq_rcv_info.rcv_pid = pid;
	mq_rcv_info.rcv_enter_time = rcv_enter_time;
	mq_rcv_info.mqdes = (bpf_s32_t)mqdes;
	mq_rcv_info.u_msg_ptr = (bpf_u64_t)u_msg_ptr;

	bpf_map_update_elem(&rcv_msg1, &pid, &mq_rcv_info, BPF_ANY);
	return 0;
}

/*
 * kprobe/store_msg
 * 触发时机：内核把消息从内核空间拷贝到用户空间时
 * 作用：通过内核消息块指针，找到发送端信息，与接收端信息绑定配对
 */
SEC("kprobe/store_msg")
int BPF_KPROBE(store_msg, void *dest, struct msg_msg *msg, size_t len)
{
	struct MsgQueue_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	bpf_s32_t pid = (bpf_s32_t)bpf_get_current_pid_tgid();

	/* 以内核消息块指针作为 key */
	bpf_u64_t Key_msg_ptr = (bpf_u64_t)msg;

	/* 查找发送端信息 */
	struct send_events *mq_send_info = bpf_map_lookup_elem(&send_msg2, &Key_msg_ptr);
	if (!mq_send_info)
		return 0;

	/* 查找接收端信息 */
	struct rcv_events *mq_rcv_info = bpf_map_lookup_elem(&rcv_msg1, &pid);
	if (!mq_rcv_info)
		return 0;

	/*
	 * 确认这次 store_msg 确实是当前进程的接收操作：
	 * 目标地址 == 用户态传入的缓冲区地址，且 PID 匹配
	 */
	if ((bpf_u64_t)dest == mq_rcv_info->u_msg_ptr &&
	    pid == mq_rcv_info->rcv_pid) {
		mq_rcv_info->Key_msg_ptr = Key_msg_ptr;
		mq_rcv_info->dest = (bpf_u64_t)dest;
		mq_rcv_info->msg_prio = BPF_CORE_READ(msg, m_type);
		mq_rcv_info->msg_len = BPF_CORE_READ(msg, m_ts);
	} else {
		return 0;
	}

	return 0;
}

/*
 * kretprobe/do_mq_timedreceive
 * 触发时机：mq_receive 彻底执行完、返回用户态之前
 * 作用：收集发送端+接收端所有数据，打包通过 ringbuf 发给用户态，清理哈希表
 */
SEC("kretprobe/do_mq_timedreceive")
int BPF_KRETPROBE(do_mq_timedreceive_exit, void *ret)
{
	struct MsgQueue_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	u64 rcv_exit_time = bpf_ktime_get_ns();
	bpf_s32_t pid = (bpf_s32_t)bpf_get_current_pid_tgid();

	/* 获取接收端信息 */
	struct rcv_events *mq_rcv_info = bpf_map_lookup_elem(&rcv_msg1, &pid);
	if (!mq_rcv_info)
		return 0;

	/* 通过 Key_msg_ptr 找到配对的发送端信息 */
	bpf_u64_t Key = mq_rcv_info->Key_msg_ptr;
	struct send_events *mq_send_info = bpf_map_lookup_elem(&send_msg2, &Key);
	if (!mq_send_info)
		return 0;

	/* ===================== 发送事件到用户态 ===================== */
	struct MsgQueue_Delay_event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		goto cleanup;

	e->send_pid = mq_send_info->send_pid;
	e->rcv_pid = pid;
	e->mqdes = mq_send_info->mqdes;
	e->msg_len = mq_send_info->msg_len;
	e->msg_prio = mq_send_info->msg_prio;

	e->send_enter_time = mq_send_info->send_enter_time;
	e->send_exit_time = mq_send_info->send_exit_time;
	e->rcv_enter_time = mq_rcv_info->rcv_enter_time;
	e->rcv_exit_time = rcv_exit_time;

	bpf_ringbuf_submit(e, 0);

cleanup:
	/* 清理哈希表，防止内存泄漏 */
	bpf_map_delete_elem(&send_msg2, &Key);
	bpf_map_delete_elem(&rcv_msg1, &pid);
	return 0;
}
