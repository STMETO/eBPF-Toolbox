#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "udp_monitor.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
const int ctrl_key = 0;

/*
 * 每CPU临时缓存结构体 udp_start
 * 配合 kprobe + kretprobe 成对使用：
 * 1. kprobe/udp_sendmsg 函数入口：记录发包起始时间、报文长度、四元组、进程信息存入此结构
 * 2. kretprobe/udp_sendmsg 函数返回：读取本CPU缓存计算调用延迟，组装输出事件
 * 使用 PERCPU_ARRAY 无多核锁竞争，单CPU同一时间只会有一个udp_sendmsg调用，无需多条目
 */
struct udp_start {
	bpf_u64_t start_ts;        // udp_sendmsg 入口时刻内核纳秒时间戳，用于计算调用耗时
	bpf_u64_t len;             // 本次发送UDP报文数据长度（应用层传入的缓冲区字节数）
	bpf_u32_t tgid;            // 线程组ID（用户态ps展示的进程PID）
	bpf_s32_t pid;             // 内核线程LWP ID
	bpf_u16_t sport, dport;    // 本地源端口、远端目的端口
	bpf_u32_t saddr_v4, daddr_v4; // IPv4 源、目的地址（网络序）
	int af;                    // 地址族 AF_INET / AF_INET6
	bpf_s8_t  comm[TASK_COMM_LEN];// 进程名称
	bpf_u8_t  saddr_v6[16], daddr_v6[16]; // IPv6 完整16字节源/目的地址
};

/*
 * start_map：每CPU数组缓存，存放udp_sendmsg调用现场
 * 类型：BPF_MAP_TYPE_PERCPU_ARRAY 每CPU独立副本，天然无并发竞争，无需锁
 * max_entries=1：仅需一条缓存，同一CPU同一时刻只能执行一次udp_sendmsg
 * key：固定int 0
 * value：udp_start 临时会话快照
 * 流程：kprobe写入 → kretprobe读取后清空start_ts标记已消费
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct udp_start);
} start_map SEC(".maps");

/*
 * ctrl_map：全局监控控制参数数组Map
 * max_entries=1，key固定0存储 UdpMonitor_ctrl 控制规则
 * 存储内容：总开关enable、延迟过滤阈值min_latency_ns、PID过滤target_pid
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct UdpMonitor_ctrl);
} ctrl_map SEC(".maps");

/*
 * stats_map：全局UDP发包统计汇总数组Map
 * 每捕获一条符合条件的UDP发包事件就更新计数、总耗时、总字节、最大延迟记录
 * 程序退出时用户态读取此Map打印汇总报表
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct UdpMonitor_stats);
} stats_map SEC(".maps");

/*
 * rb：环形缓冲区RingBuf，内核向用户态推送UDP事件通道
 * 容量 256KB，内核通过bpf_ringbuf_reserve/submit投递 UdpMonitor_event
 * 用户态libbpf ring_buffer阻塞poll读取、解析打印每条UDP发包事件
 * 缓冲区满时分配内存失败，直接丢弃当前事件
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");


static inline struct UdpMonitor_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
}

/* ── kprobe/udp_sendmsg：记录开始 ──────────────────────────── */
/*
 * kprobe/udp_sendmsg 入口探针
 * 作用：捕获UDP发包系统调用入口，保存本次发包上下文到PERCPU临时缓存start_map
 * 搭配kretprobe(ret_udp_sendmsg)成对使用：入口存快照，返回时计算耗时、上报事件
 * 挂载点：内核udp_sendmsg函数入口，所有UDP sendmsg发送报文都会触发
 * 过滤逻辑：监控开关关闭 / 指定PID不匹配则直接跳过，不写入缓存
 */
/**
* @brief UDP发包入口钩子，记录发包起点信息存入每CPU临时缓存
* @param sk 当前UDP套接字对应的内核struct sock指针
* @param msg 应用传入的消息缓冲区结构体（本程序未使用）
* @param len 本次待发送UDP报文载荷字节长度
* @return 0 BPF探针标准返回值
*/
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	struct UdpMonitor_ctrl *c = get_ctrl();
	u32 tgid = bpf_get_current_pid_tgid() >> 32;

	// 过滤：未开启监控，直接退出不记录
	if (!c || !c->enable)
		return 0;
	// 过滤：配置了目标PID且当前进程不匹配，直接跳过
	if (c->target_pid != 0 && (u32)c->target_pid != tgid)
		return 0;

	int key = 0;
	// 查询当前CPU专属临时缓存结构体
	struct udp_start *v = bpf_map_lookup_elem(&start_map, &key);
	if (!v)
		return 0;

	// 记录udp_sendmsg调用进入时刻的内核单调时钟（纳秒），用于返回探针计算耗时
	v->start_ts = bpf_ktime_get_ns();
	// 保存本次发送报文长度（入参len）
	v->len    = len;
	// 低32位：内核线程LWP ID
	v->pid    = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	// 高32位：进程TGID（ps展示的PID）
	v->tgid   = tgid;

	// CO-RE安全读取套接字通用头部地址族、端口信息
	v->af     = BPF_CORE_READ(sk, __sk_common.skc_family);
	v->sport  = BPF_CORE_READ(sk, __sk_common.skc_num);       // 本地源端口（主机序）
	v->dport  = BPF_CORE_READ(sk, __sk_common.skc_dport);     // 对端目的端口（网络序）

	// 读取当前进程名称存入缓存
	bpf_get_current_comm(&v->comm, sizeof(v->comm));

	// 根据地址族分支读取IPv4 / IPv6地址
	if (v->af == AF_INET) {
		// IPv4：读取32位源、目的IP（网络字节序）
		v->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		v->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	} else {
		// IPv6：批量读取16字节IPv6地址数组存入缓存
		BPF_CORE_READ_INTO(&v->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&v->daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	return 0;
}
 
/* ── kretprobe/udp_sendmsg：计算延迟、发送 ─────────────────── */
/*
 * kretprobe/udp_sendmsg 函数返回探针
 * 配合前面 kprobe/udp_sendmsg 成对使用：
 * 1. kprobe 在函数入口保存发包上下文到 PERCPU 临时缓存 start_map
 * 2. 本 kretprobe 在 udp_sendmsg 执行完成、即将返回用户态时触发
 * 3. 读取同CPU缓存，计算本次UDP发包系统调用耗时；按延迟阈值过滤
 * 4. 符合条件则封装事件投递到 ringbuf，同时更新全局UDP汇总统计
 * 关键：读取缓存后立刻清零 start_ts，防止同CPU下一次调用覆盖残留脏数据
 */
/**
* @brief UDP发包系统调用返回钩子，计算调用延迟、过滤、上报事件并更新统计
* @param retval udp_sendmsg 系统调用返回值（本次代码未使用）
* @return 0 BPF探针固定返回值
*/
SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(ret_udp_sendmsg, int retval)
{
	struct UdpMonitor_ctrl *c = get_ctrl();
	if (!c || !c->enable)
		return 0;

	int key = 0;
	// 获取当前CPU独有的udp发包临时缓存
	struct udp_start *v = bpf_map_lookup_elem(&start_map, &key);
	if (!v || v->start_ts == 0)
		return 0;

	// 获取函数返回时刻的内核单调时钟纳秒时间戳
	u64 now = bpf_ktime_get_ns();
	// 计算完整udp_sendmsg系统调用耗时：返回时间 - 入口记录的起始时间
	u64 lat = now - v->start_ts;
	// 清空缓存时间戳，标记本条发包记录已消费，避免脏数据干扰下一次CPU发包
	v->start_ts = 0;

	// 配置了最小延迟阈值，且本次调用耗时小于阈值，过滤丢弃本条事件，不上报
	if (c->min_latency_ns && lat < c->min_latency_ns)
		return 0;

	// 从环形缓冲区预分配一块内存，用于封装UDP事件下发给用户态
	struct UdpMonitor_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	// 填充事件基础时间、耗时、报文长度信息
	e->ts_ns      = now;                 // 事件时间戳：udp_sendmsg返回时刻
	e->latency_ns = lat;                 // 本次发包系统调用总耗时(ns)
	e->len        = v->len;              // 本次发送UDP报文载荷字节数

	// 填充进程PID/TGID、地址族、端口、IPv4地址
	e->pid        = v->pid;
	e->tgid       = v->tgid;
	e->af         = v->af;
	e->sport      = v->sport;
	e->dport      = v->dport;
	e->saddr_v4   = v->saddr_v4;
	e->daddr_v4   = v->daddr_v4;

	// 拷贝进程名、IPv6地址数组到输出事件
	__builtin_memcpy(e->comm, v->comm, TASK_COMM_LEN);
	__builtin_memcpy(e->saddr_v6, v->saddr_v6, 16);
	__builtin_memcpy(e->daddr_v6, v->daddr_v6, 16);

	// 将完整事件提交ringbuf，用户态libbpf可阻塞读取解析
	bpf_ringbuf_submit(e, 0);

	/* 更新全局UDP发包统计指标，存储在stats_map数组map */
	struct UdpMonitor_stats *st = bpf_map_lookup_elem(&stats_map, &ctrl_key);
	// 临时全零统计结构体，用于首次初始化map条目
	struct UdpMonitor_stats z = {};
	if (!st) {
		bpf_map_update_elem(&stats_map, &ctrl_key, &z, BPF_ANY);
		// 重新查询，确保st指针有效
		st = bpf_map_lookup_elem(&stats_map, &ctrl_key);
	}
	// 指针有效则累加各项统计数据
	if (st) {
		st->count++;                    // 总发包次数+1
		st->total_ns += lat;            // 累加所有发包总耗时
		st->total_bytes += v->len;      // 累加所有发送总字节数
		// 判断是否刷新历史最大延迟记录
		if (lat > st->max_ns) {
			st->max_ns = lat;
			st->max_pid = v->pid;
			__builtin_memcpy(st->max_comm, v->comm, TASK_COMM_LEN);
		}
	}

	return 0;
}
