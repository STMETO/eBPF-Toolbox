#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "TcpConnect_Delay.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
代码属于:客户端
这个延迟到底算的是哪一段？
	延迟 = 客户端发起 SYN → 收到 SYN-ACK 的时间
	TCP 三次握手的前半段（建连等待时间）

	1.cp_v4_connect（记录开始时间）
		→ 客户端发送 SYN 包
		→ 状态变为 TCP_SYN_SENT（已发送同步包，等待回应）
	2.等待服务器回复
	3.收到 SYN+ACK
		→ 触发 tcp_rcv_state_process
		→ 记录结束时间
	4.延迟 = 结束时间 - 开始时间
*/

// 进程数据映射表：记录 TCP 连接发起时的进程信息
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct sock *);
	__type(value, struct piddata);
} start SEC(".maps");

// 事件上报映射表：BPF 采集后发送给用户态的完整数据
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

// 控制map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct TcpConnect_Delay_ctrl);
} ctrl_map SEC(".maps");

/////////////////////////////////////////////////////////////////

static inline struct TcpConnect_Delay_ctrl *get_ctrl(void) {
    struct TcpConnect_Delay_ctrl *ctrl;
    ctrl = bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
    if (!ctrl || !ctrl->enable) {
        return NULL;
    }
    return ctrl;
}

// 函数作用：捕获 TCP 连接发起事件，记录进程信息 + 时间戳
static int trace_connect(struct sock *sk)
{
	struct TcpConnect_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl) return 0;

	// 获取当前进程 ID（tgid）
	// bpf_get_current_pid_tgid() 返回 64 位值：高 32 位是进程 TGID，低 32 位是线程 TID
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	// 定义存储进程信息的结构体（进程名、时间戳、PID）
	struct piddata piddata = {};

	// 过滤逻辑：如果设置了目标进程 targ_tgid，且当前进程不是它，直接退出
	if (targ_tgid && targ_tgid != tgid)
		return 0;

	// 获取当前进程名称
	bpf_get_current_comm(&piddata.comm, sizeof(piddata.comm));

	// 获取当前时间戳（纳秒级别），用于后续计算延迟
	piddata.ts = bpf_ktime_get_ns();

	// 把进程 PID 存入结构体
	piddata.tgid = tgid;

	// 将 sock 作为 key，进程信息作为 value，存入 BPF 哈希表
	// 等连接建立时，再取出来计算时间差
	bpf_map_update_elem(&start, &sk, &piddata, 0);

	return 0;
}


// 函数作用：处理TCP状态机变化事件，计算TCP连接建立延迟，并上报事件
// ctx: BPF程序上下文
// sk: 发生状态变化的TCP套接字结构
static int handle_tcp_rcv_state_process(void *ctx, struct sock *sk)
{
	// 如果获取失败，直接退出，不执行后续逻辑
	struct TcpConnect_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl) return 0;

	struct piddata *piddatap;	// 指向哈希表中存储的【发起连接时的进程信息+时间戳】
	struct event event = {};	// 要上报给用户态的完整事件数据
	__s64 delta;				// 连接耗时（时间差）
	__u64 ts;					// 当前时间戳

	// 1. 过滤状态：只处理【SYN已发送，等待响应】的状态
	// BPF_CORE_READ 安全读取内核结构体成员（兼容不同内核版本）
	if (BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_SYN_SENT)
		return 0;

	// 2. 查找哈希表：根据当前socket，找到连接发起时记录的信息
	piddatap = bpf_map_lookup_elem(&start, &sk);
	// 如果没找到记录（说明不是我们监控的连接），直接退出
	if (!piddatap)
		return 0;

	// 3. 计算时间差：当前时间 - 连接发起时间 = 建连耗时
	ts = bpf_ktime_get_ns();
	delta = (__s64)(ts - piddatap->ts);
	if (delta < 0)	// 时间异常（负数），直接清理并退出
		goto cleanup;

	// 4. 单位转换：纳秒(ns) 转 微秒(us)
	event.delta_us = delta / 1000U;
	// 过滤延迟：如果设置了最小阈值，低于阈值的不上报
	if (targ_min_us && event.delta_us < targ_min_us)
		goto cleanup;

	// 5. 填充事件结构体数据
	// 拷贝进程名
	// event.comm = piddatap->comm;  // ❌ 错误！,C 语言不允许两个数组直接用 = 赋值
	// __builtin_memcpy 是 BPF 里唯一能用的拷贝函数
	__builtin_memcpy(&event.comm, piddatap->comm, sizeof(event.comm));
	// 事件时间戳（微秒）
	event.ts_us = ts / 1000;
	// 进程ID
	event.tgid = piddatap->tgid;
	// 本地端口
	event.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	// 目标端口（网络字节序，用户态需要转换）
	event.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	// 地址族：IPv4 还是 IPv6
	event.af = BPF_CORE_READ(sk, __sk_common.skc_family);

	// 6. 根据IPv4/IPv6分别填充源IP和目标IP
	if (event.af == AF_INET) {
		// IPv4 地址
		event.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		event.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	} else {
		// IPv6 地址（批量读取16字节地址）
		BPF_CORE_READ_INTO(&event.saddr_v6, sk,
			__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&event.daddr_v6, sk,
			__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	// 7. 上报事件给用户态程序
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
		&event, sizeof(event));

// 清理标签：无论是否上报成功，都必须删除哈希表中的数据，防止内存泄漏
cleanup:
	// 删除哈希表中对应的socket记录
	bpf_map_delete_elem(&start, &sk);
	return 0;
}


///////////////////////////////////////////////////////////////////////////
// 这里采用fentry探针，因为相比kprobe在高版本内核中性能高出很多，适用于版本大于5.5的内核

// 挂载 fentry 高性能探针：捕获 IPv4 的 TCP 连接发起事件（tcp_v4_connect 函数）
// fentry 比 kprobe 性能更高，适用于高版本内核
SEC("fentry/tcp_v4_connect")
int BPF_PROG(fentry_tcp_v4_connect, struct sock *sk)
{
	return trace_connect(sk);
}

// 挂载 fentry 高性能探针：捕获 IPv6 的 TCP 连接发起事件（tcp_v6_connect 函数）
SEC("fentry/tcp_v6_connect")
int BPF_PROG(fentry_tcp_v6_connect, struct sock *sk)
{
	return trace_connect(sk);
}

// 挂载 fentry 高性能探针：捕获 TCP 状态机处理事件（tcp_rcv_state_process 函数）
// 用于判断连接是否从 SYN_SENT 状态收到响应，计算建连延迟
SEC("fentry/tcp_rcv_state_process")
int BPF_PROG(fentry_tcp_rcv_state_process, struct sock *sk)
{
	return handle_tcp_rcv_state_process(ctx, sk);
}

// 不保留kprobe探针
// ///////////////////////////////////////////////////////////////////////////
// // 挂载 kprobe 探针：捕获 IPv4 的 TCP 连接发起事件（tcp_v4_connect 函数）
// SEC("kprobe/tcp_v4_connect")
// int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
// {
// 	return trace_connect(sk);
// }

// // 挂载 kprobe 探针：捕获 IPv6 的 TCP 连接发起事件（tcp_v6_connect 函数）
// SEC("kprobe/tcp_v6_connect")
// int BPF_KPROBE(tcp_v6_connect, struct sock *sk)
// {
// 	return trace_connect(sk);
// }

// // 挂载 kprobe 探针：捕获 TCP 状态机处理事件（tcp_rcv_state_process 函数）
// // 用于判断连接是否从 SYN_SENT 状态收到响应，计算建连延迟
// SEC("kprobe/tcp_rcv_state_process")
// int BPF_KPROBE(tcp_rcv_state_process, struct sock *sk)
// {
// 	return handle_tcp_rcv_state_process(ctx, sk);
// }