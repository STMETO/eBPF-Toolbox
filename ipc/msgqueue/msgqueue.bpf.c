#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "msgqueue.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

/**
 * @struct mq_start
 * 每CPU临时缓存结构体，配合kprobe + kretprobe成对捕获mq收发系统调用
 * kprobe入口保存现场，kretprobe读取计算耗时、组装上报事件
 */
struct mq_start { 
	bpf_u64_t start_ts; 	// 系统调用进入时刻内核单调纳秒时间戳，用于计算调用延迟
	bpf_s32_t mqdes; 		// 消息队列句柄，区分不同mq实例
	bpf_u64_t msg_len; 		// 本次发送/接收的消息数据长度
	bpf_u32_t msg_prio; 	// 消息优先级
	bpf_u32_t is_send; 		// 标记类型：预留区分发送/接收（当前代码未实际使用该字段判断）
};

/*
 * start_map：每CPU独立临时缓存MAP
 * 类型：BPF_MAP_TYPE_PERCPU_ARRAY 每CPU拥有独立副本，天然无多核并发竞争、无需锁
 * max_entries=1：单CPU同一时刻只会执行一条mq send/recv调用，仅需一条缓存
 * key：固定int 0
 * value：mq_start 存储本次mq操作的起点上下文
 * 流程：kprobe写入缓存记录现场 → kretprobe读取使用后清空start_ts防止脏数据
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); 
	__uint(max_entries, 1);
	__type(key, int); 
	__type(value, struct mq_start);
} start_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY); 
	__uint(max_entries, 1);
	__type(key, int); 
	__type(value, struct Msgqueue_ctrl);
} ctrl_map SEC(".maps");

/*
 * stats_map：全局消息队列收发统计汇总MAP
 * 类型：全局ARRAY，单条统计记录永久累加
 * 每次合法mq收发事件都会更新计数、总耗时、最大耗时
 * 程序退出时用户态读取此map，打印收发汇总报表
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

static inline struct Msgqueue_ctrl *get_ctrl(void)
{ 
	return bpf_map_lookup_elem(&ctrl_map, &ctrl_key); 
}

static inline bool pid_skip(struct Msgqueue_ctrl *c, bpf_s32_t pid)
{ 
	return !c || !c->enable || (c->target_pid != 0 && pid != c->target_pid); 
}

/**
 * @brief 消息队列收发事件统一处理公共函数
 * 发送/接收的kretprobe复用此逻辑，完成过滤、事件封装推送、全局统计更新
 * @param v 当前CPU缓存的mq调用现场结构体m_qstart，存储入口记录的时间、队列句柄、消息信息
 * @param pid 当前操作消息队列的进程PID(TGID)
 * @param type 事件类型 MQ_EV_SEND(发送)/MQ_EV_RECV(接收)
 */
static void submit(struct mq_start *v, bpf_s32_t pid, bpf_u32_t type)
{
	int key = 0;
	struct Msgqueue_ctrl *c = get_ctrl();
	// 获取系统调用返回时的内核单调时间戳（纳秒）
	u64 now = bpf_ktime_get_ns();
	// 计算mq_timedsend/mq_timedreceive完整系统调用耗时：返回时间 - 入口记录的起始时间
	u64 delay = now - v->start_ts;

	// 过滤规则1：监控关闭 / 当前进程不匹配目标PID，直接丢弃本条事件
	if (pid_skip(c, pid))
		return;
	// 过滤规则2：配置了最小延迟阈值，且本次调用耗时低于阈值，丢弃不推送
	if (c->min_delay_ns && delay < c->min_delay_ns)
		return;

	// 从ringbuf预分配一块内存，用于封装事件下发给用户态
	struct Msgqueue_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return;

	// 填充事件基础字段
	e->type = type;               // 标记是发送还是接收事件
	e->ts_ns = now;               // 事件时间戳：系统调用返回时刻
	e->delay_ns = delay;          // 本次mq系统调用总耗时
	e->pid = pid;                 // 操作进程PID
	e->mqdes = v->mqdes;          // 消息队列文件描述符
	e->msg_len = v->msg_len;      // 消息长度
	e->msg_prio = v->msg_prio;    // 消息优先级
	// 读取当前进程名称存入事件
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// 将完整事件提交到环形缓冲区，用户态libbpf阻塞读取解析
	bpf_ringbuf_submit(e, 0);

	/* 更新全局收发统计指标，持久化到stats_map数组map */
	struct Msgqueue_stats *st = bpf_map_lookup_elem(&stats_map, &key);
	// 首次运行时stats_map无数据，初始化全零统计结构体写入map
	if (!st) {
		struct Msgqueue_stats z = {};
		bpf_map_update_elem(&stats_map, &key, &z, BPF_ANY);
		// 重新查询，保证指针有效
		st = bpf_map_lookup_elem(&stats_map, &key);
	}
	// 统计指针有效，区分发送/接收分别累加指标
	if (st) {
		if (type == MQ_EV_SEND) {
			st->send_count++;                // 发送总次数+1
			st->send_total_ns += delay;      // 累加所有发送调用总耗时
			if (delay > st->send_max_ns)     // 刷新单次最大发送延迟
				st->send_max_ns = delay;
		} else {
			st->recv_count++;                // 接收总次数+1
			st->recv_total_ns += delay;      // 累加所有接收调用总耗时
			if (delay > st->recv_max_ns)     // 刷新单次最大接收延迟
				st->recv_max_ns = delay;
		}
	}
}
 

/*
 * kprobe/do_mq_timedsend：消息队列发送系统调用入口探针
 * 作用：捕获 mq_timedsend 内核入口，保存本次发送操作上下文到 PERCPU 临时缓存 start_map
 * 搭配 kretprobe(mq_send_exit) 成对使用：入口存现场，返回时计算耗时、上报事件
 * 过滤逻辑：全局监控开关关闭则直接跳过，不写入缓存
 */
/**
* @brief mq_timedsend 内核函数入口钩子，记录发送起点信息
* @param mqdes 消息队列操作句柄，区分不同消息队列实例
* @param u_msg_ptr 用户态消息缓冲区指针（本程序未读取消息内容，仅记录长度）
* @param msg_len 待发送消息数据字节长度
* @param msg_prio 本次发送消息的优先级
* @param ts 超时时间戳（本程序未使用）
* @return 0 BPF探针固定返回值
*/
SEC("kprobe/do_mq_timedsend")
int BPF_KPROBE(mq_send_enter, mqd_t mqdes, const char *u_msg_ptr, size_t msg_len, unsigned int msg_prio, struct timespec64 *ts)
{
	struct Msgqueue_ctrl *c = get_ctrl();
	if (!c || !c->enable)
		return 0;

	int key = 0;
	// 获取当前CPU专属临时缓存结构体
	struct mq_start *v = bpf_map_lookup_elem(&start_map, &key);
	if (!v)
		return 0;

	// 记录函数进入时刻纳秒时间戳，用于返回探针计算系统调用耗时
	v->start_ts = bpf_ktime_get_ns();
	// 保存消息队列句柄
	v->mqdes = (bpf_s32_t)mqdes;
	// 保存消息长度
	v->msg_len = msg_len;
	// 保存消息优先级
	v->msg_prio = msg_prio;

	return 0;
}
 
 /*
  * kretprobe/do_mq_timedsend：消息队列发送系统调用返回探针
  * 配合上面 kprobe 成对使用：读取同CPU缓存，调用公共submit函数完成过滤、事件推送、统计更新
  * 处理完成后清零 start_ts，清除缓存脏数据，避免下一次调用错乱
  */
/**
* @brief mq_timedsend 内核函数返回钩子，统一提交发送事件
* @param ret do_mq_timedsend 系统调用返回值（成功/失败码，当前逻辑未使用）
* @return 0 BPF探针固定返回值
*/
 SEC("kretprobe/do_mq_timedsend")
int BPF_KRETPROBE(mq_send_exit, int ret)
{
	struct Msgqueue_ctrl *c = get_ctrl();
	if (!c || !c->enable)
		return 0;

	int key = 0;
	// 获取当前CPU缓存的发送现场
	struct mq_start *v = bpf_map_lookup_elem(&start_map, &key);
	if (!v || v->start_ts == 0)
		return 0;

	// 获取当前进程TGID作为PID过滤依据
	bpf_s32_t pid = bpf_get_current_pid_tgid();
	// 调用公共逻辑：过滤、封装MQ_EV_SEND事件、推送ringbuf、更新发送统计
	submit(v, pid, MQ_EV_SEND);
	// 清空时间戳标记本条记录已消费，防止脏数据干扰后续mq操作
	v->start_ts = 0;

	return 0;
}
 

/*
 * kprobe/do_mq_timedreceive：消息队列接收系统调用入口探针
 * 配套 kretprobe(mq_recv_exit) 成对使用
 * 捕获 mq_timedreceive 内核函数进入时机，保存接收操作现场到每CPU临时缓存 start_map
 * 仅监控开启时才记录数据，否则直接返回不处理
 */
  /**
  * @brief mq_timedreceive 内核接收函数入口钩子，记录接收起点上下文
  * @param mqdes 消息队列操作句柄，标识目标消息队列
  * @param u_msg_ptr 用户态存放接收消息的缓冲区指针（本程序不读取消息内容）
  * @param msg_len 预期可接收的最大消息长度
  * @param msg_prio 输出参数，用于存放读出消息的优先级，入口仅暂存字段位置
  * @param ts 阻塞超时时间戳（代码未使用）
  * @return 0 BPF探针标准返回值
  */
SEC("kprobe/do_mq_timedreceive")
int BPF_KPROBE(mq_recv_enter, mqd_t mqdes, const char *u_msg_ptr, size_t msg_len, unsigned int msg_prio, struct timespec64 *ts)
{
	struct Msgqueue_ctrl *c = get_ctrl();
	if (!c || !c->enable)
		return 0;

	int key = 0;
	// 获取当前CPU专属临时缓存
	struct mq_start *v = bpf_map_lookup_elem(&start_map, &key);
	if (!v)
		return 0;

	// 记录接收调用进入时刻的内核纳秒时间戳，用于返回探针计算耗时
	v->start_ts = bpf_ktime_get_ns();
	// 保存消息队列句柄
	v->mqdes = (bpf_s32_t)mqdes;
	// 保存消息长度上限
	v->msg_len = msg_len;
	// 预留消息优先级字段
	v->msg_prio = msg_prio;
	// 标记本次操作为接收（0=接收，1=发送，当前逻辑仅预留未分支判断）
	v->is_send = 0;

	return 0;
}
 
/*
* kretprobe/do_mq_timedreceive：消息队列接收系统调用返回探针
* 读取同CPU缓存的接收现场，调用公共submit函数过滤、生成接收事件、更新接收统计
* 处理完成清空start_ts，清除缓存脏数据，避免下一次操作数据错乱
*/
/**
* @brief mq_timedreceive 内核接收函数返回钩子，统一提交接收事件
* @param ret do_mq_timedreceive 系统调用返回值（成功/失败码，当前代码未使用）
* @return 0 BPF探针标准返回值
*/
SEC("kretprobe/do_mq_timedreceive")
int BPF_KRETPROBE(mq_recv_exit, int ret)
{
	struct Msgqueue_ctrl *c = get_ctrl();
	if (!c || !c->enable)
		return 0;

	int key = 0;
	// 获取当前CPU缓存的接收起点上下文
	struct mq_start *v = bpf_map_lookup_elem(&start_map, &key);
	if (!v || v->start_ts == 0)
		return 0;

	// 获取当前进程TGID，用于PID过滤判断
	bpf_s32_t pid = bpf_get_current_pid_tgid();
	// 调用公共处理函数，标记事件类型为MQ_EV_RECV（接收事件）
	submit(v, pid, MQ_EV_RECV);
	// 清空时间戳，标记本条接收记录已消费，防止脏数据干扰后续操作
	v->start_ts = 0;

	return 0;
}
 
