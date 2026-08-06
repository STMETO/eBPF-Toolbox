/**
* tcp_monitor.bpf.c
* eBPF TCP连接观测探针
* 功能：捕获客户端主动TCP连接，统计握手延迟、报文重传、连接生命周期；支持容器PID namespace、PID过滤、握手延迟阈值过滤。
*
* 探针挂载点说明：
* fentry/fexit: tcp_v4_connect / tcp_v6_connect      捕获connect调用入口与返回，创建连接会话sess
* fentry: tcp_finish_connect                         三次握手完成，上报TCP_EV_HANDSHAKE握手事件
* kprobe: tcp_retransmit_skb                         TCP报文重传触发，上报TCP_EV_RETRANSMIT重传事件
* kprobe: tcp_close                                  socket关闭，上报TCP_EV_CLOSE连接关闭事件
*
* 关键设计：
* 1. sess_map(LRU_HASH) key为sock*指针，跨软中断上下文保存连接进程归属；
* 2. 聚合统计(PERCPU_ARRAY stats_map)优先更新，ringbuf满仅丢失明细事件，聚合统计不会丢失；
* 3. 支持PID namespace转换，适配容器环境，输出容器内可见PID/TID；
* 4. connect失败时立刻清理sess会话；连接关闭时立刻删除sess_map，避免socket对象复用造成数据污染。
*
* 局限：
* 1. 仅捕获客户端主动connect连接，不捕获服务端listen+accept被动接入连接；
* 2. tcp_retransmit_skb、tcp_close使用kprobe，内核版本变更符号可能失效；fentry安全性、稳定性优于kprobe。
* 3. LRU_HASH存在自动淘汰，连接数量超过max_entries，旧会话会被自动回收，对应连接后续事件会丢失会话上下文。
*/

/*
用户态libbpf
    ↓(写入ctrl_map配置：enable/target_pid/min_latency_ns/pidns信息)
eBPF探针挂载完成
    │
    ├───────────────────────────TCP客户端connect调用(应用上下文)───────────────────────────│
    │  fentry/tcp_v4_connect / fentry/tcp_v6_connect 【入口钩子】
    │      → record_connect()
    │          → 校验ctrl->enable
    │          → app_current_pid_tgid_ns() 转换PID namespace，拿到容器内tgid/tid
    │          → target_pid过滤，不匹配直接返回，不创建会话
    │          → 填充tcp_sess：start_ts(connect时间戳)、tgid、tid、comm
    │          → key=(u64)sk，bpf_map_update_elem写入 sess_map
    │          → stats->connect_attempted++
    │
    │  fexit/tcp_v4_connect / fexit/tcp_v6_connect 【返回钩子】
    │      → finish_connect_call()
    │          ├─ ret < 0 (connect系统调用失败)
    │          │    → bpf_map_delete_elem 删除sess_map条目，直接结束；无后续事件
    │          └─ ret >=0 (connect成功)
    │               → 查找sess_map，save_sock()把四元组存入tcp_sess会话缓存
    │
    ├────────────────────三次握手完成(softirq软中断上下文)────────────────────│
    │  fentry/tcp_finish_connect
    │      → 查找sess_map(key=sock*)
    │          ├─找不到sess：全量模式统计untracked_events，return
    │          └─找到sess
    │              → session_allowed()做PID过滤；handshake_reputed标记防重复上报
    │              → latency_ns = bpf_ktime_get_ns()‑sess->start_ts
    │              ├─ latency < min_latency_ns：stats->filtered_latency++，return，不上报明细
    │              └─阈值通过
    │                   → save_sock 更新会话四元组
    │                   →【优先更新per‑cpu stats】hs_count/hs_total_ns/hs_max_ns更新
    │                   → ringbuf_reserve 分配事件内存
    │                       ├─reserve失败：stats->ringbuf_dropped++，聚合统计已写好，直接return
    │                       └─成功：填充TCP_EV_HANDSHAKE事件，ringbuf_submit推送给用户态
    │
    ├────────────────────数据传输阶段：可多次触发重传(softirq上下文)────────────────────│
    │  kprobe/tcp_retransmit_skb 【每重传1个skb触发一次】
    │      → 查找sess_map(key=sock*)
    │          ├─找不到sess：全量模式untracked_events++ return
    │          └─找到sess
    │              → session_allowed() PID过滤校验
    │              → __sync_fetch_and_add(&sess->retrans_cnt,1) 会话重传计数原子+1
    │              →【优先更新stats->rt_count++】
    │              → ringbuf_reserve
    │                  ├─失败 ringbuf_dropped++ return
    │                  └─成功：填充TCP_EV_RETRANSMIT事件，提交ringbuf
    │
    └────────────────────TCP连接关闭(softirq上下文)────────────────────│
       kprobe/tcp_close
           →查找sess_map(key=sock*)
               ├─找不到sess：直接return
               └─找到sess
                   → __builtin_memcpy(&snapshot, sess, sizeof(snapshot)) 【拷贝会话快照！】
                   → bpf_map_delete_elem(&sess_map, &key) 【立刻删除map，防止sock对象复用污染】
                   → session_allowed(&snapshot)过滤
                   → lifetime_ns = now‑snapshot.start_ts
                   →【优先更新stats：cl_count / cl_total_ns / cl_max_ns】
                   → ringbuf_reserve
                       ├─失败 ringbuf_dropped++ return
                       └─成功：填充TCP_EV_CLOSE事件(携带总retrans_cnt、生命周期)，提交ringbuf

──────────────────────────────────────────────────────────────────────
ringbuf 环形缓冲区 → 用户态tcp_monitor_run()读取事件，解析type做业务处理
用户退出时读取stats_map所有CPU副本，聚合求和输出全局统计报表

save_sock()的作用是从内核 sk 结构体拷贝四元组存入会话。
connect 阶段（尤其是非阻塞 connect）无法保证 fexit 时刻四元组已经完全固化；
tcp_finish_connect是内核真正完成三次握手、四元组彻底稳定的时机，
在这里做一次兜底更新。连接一旦建立完成，四元组不再变化，后面重传、close 直接读取会话缓存，不需要重复从 sk 拷贝

应用进程调用connect()
        ↓(fentry)
sess_map 存入tcp_sess(时间戳、pid、comm)
        ↓
├─connect失败 → 删除sess_map，生命周期结束
└─connect成功
        ↓
        ├─tcp_finish_connect(握手完成) → TCP_EV_HANDSHAKE事件
        │
        ├─(多次)tcp_retransmit_skb → TCP_EV_RETRANSMIT事件（可0次、多次）
        │
        └─tcp_close → 拷贝snapshot，删除sess_map → TCP_EV_CLOSE事件

所有明细事件 → ringbuf → 用户态
所有聚合指标 → per‑cpu stats_map（ringbuf丢事件不影响聚合统计）

*/

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "tcp_monitor.h"
#include "common/pid_namespace.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ctrl_map、stats_map数组MAP固定下标，只使用index=0
const int ctrl_key = 0;

/**
* @map sess_map
* 类型 BPF_MAP_TYPE_LRU_HASH LRU哈希表
* max_entries=16384：最多缓存16384条TCP连接会话；LRU策略，满时自动淘汰最久未访问会话
* key：bpf_u64_t，存放struct sock*内核指针；以此把connect上下文与握手/重传/关闭事件做关联
* value：struct tcp_sess，单条连接完整会话上下文
* 注意：握手、重传、关闭运行在softirq上下文，current不再是发起连接进程，必须依靠sock指针做会话关联
*/
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, bpf_u64_t);
	__type(value, struct tcp_sess);
} sess_map SEC(".maps");

/**
* @map ctrl_map
* 类型 BPF_MAP_TYPE_ARRAY 定长数组MAP
* max_entries=1；仅保存一份全局控制配置
* key固定ctrl_key=0
* value struct TcpMonitor_ctrl；用户态写入控制开关、过滤参数
*/
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct TcpMonitor_ctrl);
} ctrl_map SEC(".maps");

/**
* @map stats_map
* 类型 BPF_MAP_TYPE_PERCPU_ARRAY 每CPU数组MAP
* max_entries=1；每个CPU保存一份TcpMonitor_stats；避免多CPU竞争锁，提升性能
* key固定ctrl_key=0；用户态读取后需要把所有CPU副本做聚合求和得到全局统计
* value struct TcpMonitor_stats；全局聚合统计数据
*/
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct TcpMonitor_stats);
} stats_map SEC(".maps");

/**
* @map rb
* 类型 BPF_MAP_TYPE_RINGBUF 高性能环形缓冲区
* max_entries 256*1024 = 256KB；内核态向用户态推送明细事件；缓冲区满bpf_ringbuf_reserve返回NULL，事件丢弃
*/
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
* get_ctrl
* @brief 获取全局控制配置结构体
* @return 成功返回TcpMonitor_ctrl指针；NULL代表map未初始化，直接停止采集
*/
static __always_inline struct TcpMonitor_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
}

/**
* get_stats
* @brief 获取当前CPU的per‑cpu统计结构体
* @return 返回TcpMonitor_stats指针；percpu_array一定存在，不会返回NULL
*/
static __always_inline struct TcpMonitor_stats *get_stats(void)
{
	return bpf_map_lookup_elem(&stats_map, &ctrl_key);
}

/**
* session_allowed
* @brief 判断当前会话是否满足采集过滤条件(总开关+target_pid)
* @param ctrl 全局控制参数指针
* @param sess 待判断tcp会话
* @return true允许采集该连接；false跳过该连接所有事件
*/
static __always_inline bool session_allowed(const struct TcpMonitor_ctrl *ctrl,
						const struct tcp_sess *sess)
{
	if (!ctrl || !ctrl->enable)
		return false;
	/* target_pid为0表示不做PID过滤；非0则匹配会话tgid */
	return !ctrl->target_pid || (bpf_u32_t)ctrl->target_pid == sess->tgid;
}

/**
* fill_sock
* @brief 从struct sock*实时读取socket四元组，填充TcpMonitor_event事件结构体
* @note dport内核存储为网络字节序；转换为主机字节序存入事件；输出字段统一主机字节序，简化用户态解析
* @param event 待填充事件结构体
* @param sk 内核sock指针
*/
static __always_inline void fill_sock(struct TcpMonitor_event *event, struct sock *sk)
{
	event->af = BPF_CORE_READ(sk, __sk_common.skc_family);
	event->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	event->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (event->af == AF_INET) {
		event->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		event->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__builtin_memset(event->saddr_v6, 0, sizeof(event->saddr_v6));
		__builtin_memset(event->daddr_v6, 0, sizeof(event->daddr_v6));
	} else if (event->af == AF_INET6) {
		event->saddr_v4 = 0;
		event->daddr_v4 = 0;
		BPF_CORE_READ_INTO(event->saddr_v6, sk,
				__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(event->daddr_v6, sk,
				__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
}

/**
* fill_process
* @brief 将tcp_sess会话中的进程信息(tgid/tid/comm)拷贝到输出事件
* @param event 输出事件
* @param sess tcp会话上下文
*/
static __always_inline void fill_process(struct TcpMonitor_event *event,
					const struct tcp_sess *sess)
{
	event->tgid = sess->tgid;
	event->tid = sess->tid;
	__builtin_memcpy(event->comm, sess->comm, TASK_COMM_LEN);
}

/**
* save_sock
* @brief 从sock读取四元组，保存到tcp_sess会话结构体；会话长期缓存四元组
* @param sess tcp会话上下文
* @param sk 内核sock指针
*/
static __always_inline void save_sock(struct tcp_sess *sess, struct sock *sk)
{
	sess->af = BPF_CORE_READ(sk, __sk_common.skc_family);
	sess->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	sess->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (sess->af == AF_INET) {
		sess->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		sess->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	} else if (sess->af == AF_INET6) {
		BPF_CORE_READ_INTO(sess->saddr_v6, sk,
				__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(sess->daddr_v6, sk,
				__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
}

/**
* fill_saved_sock
* @brief 把tcp_sess缓存的四元组拷贝到输出事件；close场景sk已经被销毁，不能再读取sk，使用会话缓存的四元组
* @param event 输出事件
* @param sess tcp会话上下文
*/
static __always_inline void fill_saved_sock(struct TcpMonitor_event *event,
						const struct tcp_sess *sess)
{
	event->af = sess->af;
	event->sport = sess->sport;
	event->dport = sess->dport;
	event->saddr_v4 = sess->saddr_v4;
	event->daddr_v4 = sess->daddr_v4;
	__builtin_memcpy(event->saddr_v6, sess->saddr_v6, sizeof(event->saddr_v6));
	__builtin_memcpy(event->daddr_v6, sess->daddr_v6, sizeof(event->daddr_v6));
}

/**
* record_connect
* @brief connect调用入口逻辑；创建tcp_sess会话存入sess_map；记录connect时间戳、进程PID/TID/comm
* @param sk 当前connect的socket指针
* @return 0
* 说明：connect运行在应用进程上下文，可以拿到真实current进程信息；经过pid namespace转换存入sess，供后续中断上下文使用
*/
static __always_inline int record_connect(struct sock *sk)
{
	struct TcpMonitor_ctrl *ctrl = get_ctrl();
	struct TcpMonitor_stats *stats;
	struct tcp_sess sess = {};
	bpf_u64_t pid_tgid, key;

	if (!ctrl || !ctrl->enable)
		return 0;

	/* app_current_pid_tgid_ns：把内核PID转换为目标PID namespace内可见pid_tgid，适配容器 */
	pid_tgid = app_current_pid_tgid_ns(ctrl->pid_ns_dev, ctrl->pid_ns_ino);
	if (!pid_tgid)
		return 0;
	sess.tgid = (bpf_u32_t)(pid_tgid >> 32);
	sess.tid = (bpf_u32_t)pid_tgid;

	/* target_pid过滤，不匹配直接退出，不创建会话 */
	if (ctrl->target_pid && (bpf_u32_t)ctrl->target_pid != sess.tgid)
		return 0;

	stats = get_stats();
	if (stats)
		stats->connect_attempted++;

	/* 记录connect调用时刻时间戳，用于后续握手延迟计算 */
	sess.start_ts = bpf_ktime_get_ns();
	bpf_get_current_comm(sess.comm, sizeof(sess.comm));

	/*
	* 握手、重传、关闭会运行在softirq/ksoftirqd软中断上下文，current不再是发起连接的应用进程；
	* 使用sock对象指针作为key，把进程归属信息存入sess_map，跨上下文关联同一条TCP连接。
	*/
	key = (bpf_u64_t)sk;
	if (bpf_map_update_elem(&sess_map, &key, &sess, BPF_ANY) && stats)
		stats->map_update_failed++;
	return 0;
}

/**
* @fentry tcp_v4_connect
* @brief IPv4 connect函数进入点，调用record_connect创建会话
* 内核原型：int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
*/
SEC("fentry/tcp_v4_connect")
int BPF_PROG(fentry_tcp_v4_connect, struct sock *sk)
{
	return record_connect(sk);
}

/**
* @fentry tcp_v6_connect
* @brief IPv6 connect函数进入点，调用record_connect创建会话
* 内核原型：int tcp_v6_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
*/
SEC("fentry/tcp_v6_connect")
int BPF_PROG(fentry_tcp_v6_connect, struct sock *sk)
{
	return record_connect(sk);
}

/**
* finish_connect_call
* @brief connect返回处理逻辑；connect失败(ret<0)直接删除sess会话，该连接不会产生握手事件
* @param sk socket指针
* @param ret tcp_v4/tcp_v6_connect返回值，负数代表connect系统调用失败
* @return 0
*/
static __always_inline int finish_connect_call(struct sock *sk, int ret)
{
	bpf_u64_t key = (bpf_u64_t)sk;
	struct tcp_sess *sess;

	/* connect失败，不会走到tcp_finish_connect握手完成，立刻清理会话，避免残留无效条目 */
	if (ret < 0) {
		bpf_map_delete_elem(&sess_map, &key);
		return 0;
	}
	/* connect调用成功，从sk读取四元组更新到sess会话缓存 */
	sess = bpf_map_lookup_elem(&sess_map, &key);
	if (sess)
		save_sock(sess, sk);
	return 0;
}

/**
* @fexit tcp_v4_connect
* @brief IPv4 connect函数返回钩子，拿到connect返回值，调用finish_connect_call
*/
SEC("fexit/tcp_v4_connect")
int BPF_PROG(fexit_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr,
		int addr_len, int ret)
{
	(void)uaddr;
	(void)addr_len;
	return finish_connect_call(sk, ret);
}

/**
* @fexit tcp_v6_connect
* @brief IPv6 connect函数返回钩子，拿到connect返回值，调用finish_connect_call
*/
SEC("fexit/tcp_v6_connect")
int BPF_PROG(fexit_tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr,
		int addr_len, int ret)
{
	(void)uaddr;
	(void)addr_len;
	return finish_connect_call(sk, ret);
}

/**
* @fentry tcp_finish_connect
* @brief 三次握手完成钩子；主动TCP连接真正进入ESTABLISHED状态时触发；上报TCP_EV_HANDSHAKE握手事件
* 内核原型：void tcp_finish_connect(struct sock *sk, struct sk_buff *skb)
* @param sk socket指针
* @param skb 完成握手的syn‑ack报文skb
*
* 逻辑要点：
* 1. 查找sess_map会话；无会话，全量模式统计untracked_events；PID过滤模式忽略；
* 2. handshake_reported标记防止同一条连接重复上报握手事件；
* 3. 计算握手延迟 = 当前时间 - sess.start_ts(connect调用时刻)；
* 4. 低于min_latency_ns阈值，只更新filtered_latency，不上报明细事件；
* 5. 【重要】优先更新per‑cpu聚合统计，再执行ringbuf_reserve；ringbuf满只丢失明细，聚合统计不会丢失；
* 6. ringbuf预留成功，填充事件提交给用户态。
*/
SEC("fentry/tcp_finish_connect")
int BPF_PROG(trace_tcp_finish_connect, struct sock *sk, struct sk_buff *skb)
{
	struct TcpMonitor_ctrl *ctrl = get_ctrl();
	struct TcpMonitor_stats *stats = get_stats();
	struct tcp_sess *sess;
	struct TcpMonitor_event *event;
	bpf_u64_t key = (bpf_u64_t)sk;
	bpf_u64_t now, latency_ns;

	(void)skb;
	if (!ctrl || !ctrl->enable)
		return 0;

	sess = bpf_map_lookup_elem(&sess_map, &key);
	if (!sess) {
		/* 指定target_pid过滤时，找不到会话属于正常现象；全量采集才统计untracked_events指标 */
		if (stats && !ctrl->target_pid)
			stats->untracked_events++;
		return 0;
	}

	/* PID过滤不匹配 或者握手已经上报过，直接返回，避免重复上报 */
	if (!session_allowed(ctrl, sess) || sess->handshake_reported)
		return 0;

	now = bpf_ktime_get_ns();
	latency_ns = now - sess->start_ts;
	/* 标记握手已上报，保证一条连接握手事件最多输出一次 */
	sess->handshake_reported = true;

	/* 握手延迟小于阈值，统计过滤计数，不上报明细 */
	if (ctrl->min_latency_ns && latency_ns < ctrl->min_latency_ns) {
		if (stats)
			stats->filtered_latency++;
		return 0;
	}

	/* 更新会话缓存四元组 */
	save_sock(sess, sk);

	/*
	* 聚合统计优先更新；不能依赖用户态是否消费ringbuf；ringbuf满只丢明细，聚合数据完整。
	* 更新握手总次数、总耗时；如果当前延迟大于历史最大值，保存最大握手延迟对应的连接信息。
	*/
	if (stats) {
		stats->hs_count++;
		stats->hs_total_ns += latency_ns;
		if (latency_ns > stats->hs_max_ns) {
			stats->hs_max_ns = latency_ns;
			stats->hs_max_sport = sess->sport;
			stats->hs_max_dport = sess->dport;
			stats->hs_max_af = sess->af;
			stats->hs_max_saddr = sess->saddr_v4;
			stats->hs_max_daddr = sess->daddr_v4;
			__builtin_memcpy(stats->hs_max_saddr_v6, sess->saddr_v6,
					sizeof(stats->hs_max_saddr_v6));
			__builtin_memcpy(stats->hs_max_daddr_v6, sess->daddr_v6,
					sizeof(stats->hs_max_daddr_v6));
			__builtin_memcpy(stats->hs_max_comm, sess->comm, TASK_COMM_LEN);
		}
	}

	/* ringbuf缓冲区满，丢弃本次明细事件，聚合统计已经完成，不影响全局指标 */
	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event) {
		if (stats)
			stats->ringbuf_dropped++;
		return 0;
	}
	__builtin_memset(event, 0, sizeof(*event));
	event->type = TCP_EV_HANDSHAKE;
	event->ts_ns = now;
	event->latency_ns = latency_ns;
	event->state = BPF_CORE_READ(sk, __sk_common.skc_state);
	fill_process(event, sess);
	fill_saved_sock(event, sess);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

/**
* @kprobe tcp_retransmit_skb
* @brief TCP报文重传钩子；每重传一个skb触发一次；上报TCP_EV_RETRANSMIT事件
* 内核原型：void tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb)
* @param sk socket指针
*
* 逻辑要点：
* 1. sess->retrans_cnt原子自增；重传计数聚合统计优先更新，ringbuf满不会丢失重传计数；
* 2. 重传事件latency_ns固定填0；
*/
SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(trace_tcp_retransmit, struct sock *sk)
{
	struct TcpMonitor_ctrl *ctrl = get_ctrl();
	struct TcpMonitor_stats *stats = get_stats();
	struct tcp_sess *sess;
	struct TcpMonitor_event *event;
	bpf_u64_t key = (bpf_u64_t)sk;
	bpf_u32_t retrans_cnt;

	if (!ctrl || !ctrl->enable)
		return 0;

	sess = bpf_map_lookup_elem(&sess_map, &key);
	if (!sess) {
		if (stats && !ctrl->target_pid)
			stats->untracked_events++;
		return 0;
	}
	if (!session_allowed(ctrl, sess))
		return 0;

	/* 原子加，更新该socket累计重传次数 */
	__sync_fetch_and_add(&sess->retrans_cnt, 1);
	retrans_cnt = sess->retrans_cnt;

	/* rt_count全局重传总计数优先更新，ringbuf丢弃不影响聚合指标 */
	if (stats)
		stats->rt_count++;

	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event) {
		if (stats)
			stats->ringbuf_dropped++;
		return 0;
	}
	__builtin_memset(event, 0, sizeof(*event));
	event->type = TCP_EV_RETRANSMIT;
	event->ts_ns = bpf_ktime_get_ns();
	event->state = BPF_CORE_READ(sk, __sk_common.skc_state);
	event->retrans_cnt = retrans_cnt;
	fill_process(event, sess);
	fill_sock(event, sk);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

/**
* @kprobe tcp_close
* @brief socket关闭钩子；TCP连接销毁触发；上报TCP_EV_CLOSE事件，输出连接生命周期、累计重传次数
* 内核原型：void tcp_close(struct sock *sk, long timeout)
* @param sk socket指针
*
* 关键风险点：
* tcp_close返回后，sock对象会被释放，内核成员会被清零；不能在delete_elem之后读取sock/sess。
* 处理流程：
* 1. 查询sess会话，先做snapshot完整拷贝会话上下文；
* 2. 立刻删除sess_map条目，防止socket对象复用时旧会话残留，污染新连接；
* 3. 使用snapshot副本做后续统计、事件填充，禁止使用已经删除map内的sess指针；
* 4. 计算连接生命周期 = 当前时间 - snapshot.start_ts(connect时间戳)；
* 5. 优先更新连接关闭聚合统计，再做ringbuf_reserve。
*/
SEC("kprobe/tcp_close")
int BPF_KPROBE(trace_tcp_close, struct sock *sk)
{
	struct TcpMonitor_ctrl *ctrl = get_ctrl();
	struct TcpMonitor_stats *stats = get_stats();
	struct tcp_sess *sess;
	struct TcpMonitor_event *event;
	struct tcp_sess snapshot;
	bpf_u64_t key = (bpf_u64_t)sk;
	bpf_u64_t now, lifetime_ns;

	sess = bpf_map_lookup_elem(&sess_map, &key);
	if (!sess)
		return 0;

	/*
	* tcp_close执行完毕，sock对象很快释放；先完整拷贝会话快照，再删除map；
	* 如果先删除map，后续不能再访问sess指针。
	*/
	__builtin_memcpy(&snapshot, sess, sizeof(snapshot));
	/* 无论是否上报事件，必须删除map条目，避免socket对象复用上一条连接的会话残留 */
	bpf_map_delete_elem(&sess_map, &key);

	if (!session_allowed(ctrl, &snapshot))
		return 0;

	now = bpf_ktime_get_ns();
	lifetime_ns = now - snapshot.start_ts;

	/* 连接关闭聚合统计优先更新，ringbuf满只丢明细 */
	if (stats) {
		stats->cl_count++;
		stats->cl_total_ns += lifetime_ns;
		if (lifetime_ns > stats->cl_max_ns)
			stats->cl_max_ns = lifetime_ns;
	}

	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event) {
		if (stats)
			stats->ringbuf_dropped++;
		return 0;
	}
	__builtin_memset(event, 0, sizeof(*event));
	event->type = TCP_EV_CLOSE;
	event->ts_ns = now;
	event->latency_ns = lifetime_ns;
	event->state = BPF_CORE_READ(sk, __sk_common.skc_state);
	event->retrans_cnt = snapshot.retrans_cnt;
	fill_process(event, &snapshot);
	fill_saved_sock(event, &snapshot);
	bpf_ringbuf_submit(event, 0);
	return 0;
}
