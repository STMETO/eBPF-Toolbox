#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "tcp_monitor.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
const int ctrl_key = 0;

/*
 * sess_map：TCP建连临时会话哈希表
 * key：u64 = bpf_get_current_pid_tgid()，高32位TGID(进程PID)、低32位TID(线程ID)
 * value：struct tcp_sess，保存connect时的时间戳、进程名、PID等上下文
 * 业务逻辑：
 * 1. fentry/tcp_v4_connect / tcp_v6_connect 触发时写入本条线程pid_tgid对应的会话信息
 * 2. tcp_rcv_state_process（握手完成）根据pid_tgid查询，计算握手延迟、生成事件后删除本条
 * 3. 作用：关联「connect发起」和「三次握手完成」两个不同探针点，计算建连耗时
 */
 struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, struct tcp_sess);
} sess_map SEC(".maps");

/*
 * retrans_map：TCP连接重传计数哈希表
 * key：u64 = 内核struct sock对象虚拟地址，唯一标识一条TCP连接
 * value：struct retrans_track，记录该连接累计重传报文次数
 * 业务逻辑：
 * 1. kprobe/tcp_retransmit_skb 报文重传触发：按sock地址查询，计数+1，不存在则新建记录
 * 2. kprobe/tcp_close 连接关闭：取出该连接总重传次数上报事件，随后删除map条目释放空间
 * 3. 作用：一条连接多次重传时做累加统计，关闭时汇总总重传量给到用户态
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, struct retrans_track);
} retrans_map SEC(".maps");

/*
 * ctrl_map：全局监控控制参数数组Map
 * max_entries=1：仅存一条全局配置，key固定为0
 * key：int 固定0
 * value：struct TcpMonitor_ctrl，存储总开关、PID过滤、握手延迟阈值
 * 业务逻辑：
 * 1. 用户态启动时写入配置到key=0位置
 * 2. BPF程序所有探针通过get_ctrl()读取全局过滤规则，统一控制采集行为
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct TcpMonitor_ctrl);
} ctrl_map SEC(".maps");

/*
 * stats_map：全局监控统计汇总数组Map
 * value：struct TcpMonitor_stats，累加握手次数、总延迟、最大延迟、重传总数、关闭连接数等
 * 业务逻辑：
 * 1. 每生成一条TCP事件(握手/重传/关闭)都会更新对应统计字段
 * 2. 用户态程序退出时读取此Map，打印全局汇总报表
 * 3. 数组Map天然支持原子更新，多CPU并发更新无需额外锁
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct TcpMonitor_stats);
} stats_map SEC(".maps");

/*
 * rb：环形缓冲区RingBuf，BPF内核→用户态事件通道
 * max_entries：256*1024 = 256KB 缓冲区总大小
 * 业务逻辑：
 * 1. 内核侧：bpf_ringbuf_reserve分配事件内存，填充TcpMonitor_event后bpf_ringbuf_submit提交
 * 2. 用户态：libbpf阻塞poll读取缓冲区，解析每条TCP事件打印/存储
 * 优势对比旧perf buffer：
 * 1. 单缓冲区多CPU无锁写入，无需PERCPU拆分
 * 2. 内存释放由用户态主动控制，不会丢事件或OOM
 * 3. 接口简洁，无需处理perf采样的样本头、对齐碎片
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");


/**
 * @brief 封装获取全局监控控制配置的工具函数
 * @return 指向ctrl_map中全局配置项的指针，为空代表读取失败
 * @note ctrl_map是长度为1的ARRAY map，固定key=ctrl_key(0)存储全局开关、过滤规则
 */
static inline struct TcpMonitor_ctrl *get_ctrl(void)
{ 
	// 根据固定key 0 查询全局控制参数
	return bpf_map_lookup_elem(&ctrl_map, &ctrl_key); 
}
 
 /**
  * @brief PID过滤判断工具函数，判断当前线程是否需要跳过采集
  * @param c 全局控制配置指针，由get_ctrl()获取
  * @param tgid 当前进程的线程组ID（用户态ps展示的PID）
  * @return true=跳过不采集；false=符合过滤条件，正常采集
  * 过滤逻辑：
  * 1. 无配置 或 总开关关闭 → 跳过
  * 2. 配置了指定target_pid且当前tgid不匹配 → 跳过
  * 3. target_pid=0（全量采集） 或 tgid匹配目标PID → 放行
  */
static inline bool pid_skip(struct TcpMonitor_ctrl *c, u32 tgid)
{
	if (!c || !c->enable) return true;
	if (c->target_pid != 0 && (u32)c->target_pid != tgid) return true;
	return false;
}
 
 /**
  * @brief 从内核struct sock读取四元组信息，填充输出事件TcpMonitor_event地址端口字段
  * @param e 待填充的ringbuf输出事件结构体
  * @param sk 内核socket对象指针，包含TCP/IPv4/IPv6完整地址信息
  * @detail 使用BPF_CORE_READ系列CO-RE安全读取，跨内核兼容
  * sk公共字段__sk_common统一存放地址族、端口、IP，IPv4与IPv6地址分支处理
  */
static void fill_sock(struct TcpMonitor_event *e, struct sock *sk)
{
	// 读取地址族 AF_INET(2) / AF_INET6(10)
	e->af    = BPF_CORE_READ(sk, __sk_common.skc_family);
	// 本地源端口（主机序）
	e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	// 对端目的端口（网络大端序，用户态需ntohs转换）
	e->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

	if (e->af == AF_INET) {
		// IPv4分支：读取32位源、目的IPv4地址（网络序）
		e->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		e->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	} else {
		// IPv6分支：一次性读取16字节IPv6地址数组到事件结构体
		BPF_CORE_READ_INTO(&e->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&e->daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
}
 
 /**
  * @brief 全局统计更新函数，每产生一条TCP事件就更新stats_map汇总指标
  * @param e 刚生成的TCP事件，根据type区分握手/重传/关闭做不同统计累加
  * @note stats_map为长度1的ARRAY map，key固定0存储全局统计；
  * 若统计条目不存在则初始化全零结构体再写入，避免空指针访问崩溃
  */
static void update_stats(struct TcpMonitor_event *e)
{
	// 查询全局统计存储位置
	struct TcpMonitor_stats *st = bpf_map_lookup_elem(&stats_map, &ctrl_key);
	// 统计条目不存在，初始化全0结构体写入map
	if (!st) { 
		struct TcpMonitor_stats z = {}; 
		bpf_map_update_elem(&stats_map, &ctrl_key, &z, BPF_ANY); 
		// 重新查询，确保后续操作指针有效
		st = bpf_map_lookup_elem(&stats_map, &ctrl_key); 
	}
	// 初始化失败直接返回，不更新统计
	if (!st) return;

	// 根据事件类型分别更新对应统计字段
	switch (e->type) {
		case TCP_EV_HANDSHAKE:
			// 握手计数+1，累加总握手耗时
			st->hs_count++; 
			st->hs_total_ns += e->latency_ns;
			// 如果本次握手延迟是历史最大值，刷新最大延迟记录与对应连接信息
			if (e->latency_ns > st->hs_max_ns) { 
				st->hs_max_ns = e->latency_ns; 
				st->hs_max_sport = e->sport; 
				st->hs_max_dport = e->dport; 
				st->hs_max_saddr = e->saddr_v4; 
				st->hs_max_daddr = e->daddr_v4; 
				// 拷贝进程名到统计最大延迟记录
				__builtin_memcpy(st->hs_max_comm, e->comm, TASK_COMM_LEN); 
			}
			break;
		case TCP_EV_RETRANSMIT: 
			// 重传事件仅全局重传计数+1，无耗时统计
			st->rt_count++; 
			break;
		case TCP_EV_CLOSE: 
			// 连接关闭计数+1，累加连接总存活时长
			st->cl_count++; 
			st->cl_total_ns += e->latency_ns; 
			// 更新最长连接存活时长
			if (e->latency_ns > st->cl_max_ns) 
				st->cl_max_ns = e->latency_ns; 
			break;
	}
}
 

/* ── connect: 只存 pid/comm/ts，端口稍后在 handshake 时从 sk 取 ── */
/*
 * connect 入口公共处理函数：捕获应用发起TCP连接请求，保存会话起点上下文
 * 挂载点：fentry/tcp_v4_connect、fentry/tcp_v6_connect（IPv4/IPv6建立连接通用）
 * 核心问题：调用connect阶段，内核sock尚未分配真实源端口，无法读取完整四元组
 * 解决方案：仅记录进程、时间戳存入sess_map；握手完成后再从sock读取端口/IP填充事件
 */
static int trace_connect(struct sock *sk)
{
	// 获取全局监控开关、PID过滤配置
	struct TcpMonitor_ctrl *c = get_ctrl();
	// 获取当前线程pid_tgid组合值：高32位TGID(进程PID)，低32位TID(线程LWP)
	u64 pid_tgid = bpf_get_current_pid_tgid();
	// 过滤判断：关闭监控 / 指定PID不匹配，直接退出不记录会话
	if (pid_skip(c, pid_tgid >> 32)) return 0;

	// 初始化会话缓存结构体，清零所有字段
	struct tcp_sess s = {};
	// 记录connect发起时刻内核单调时钟纳秒时间戳，用于握手完成后计算建连延迟
	s.start_ts = bpf_ktime_get_ns();
	// 低32位 = 线程LWP ID
	s.pid  = pid_tgid & 0xFFFFFFFF;
	// 高32位 = TGID，用户态ps/top展示的进程PID
	s.tgid = pid_tgid >> 32;
	// 读取当前进程名存入会话缓存
	bpf_get_current_comm(&s.comm, sizeof(s.comm));

	// 以pid_tgid为key，将会话信息存入哈希表sess_map，BPF_ANY存在则覆盖、不存在则新增
	bpf_map_update_elem(&sess_map, &pid_tgid, &s, BPF_ANY);
	return 0;
}
 

SEC("fentry/tcp_v4_connect")
int BPF_PROG(fentry_tcp_v4_connect, struct sock *sk) 
{ 
	return trace_connect(sk); 
}

SEC("fentry/tcp_v6_connect")
int BPF_PROG(fentry_tcp_v6_connect, struct sock *sk) 
{
	return trace_connect(sk); 
}

/*
 * fentry/tcp_rcv_state_process 探针：捕获TCP三次握手完成事件
 * 背景：connect阶段拿不到本地随机源端口，因此拆分两步采集
 * 1. connect探针仅存进程、发起时间到sess_map
 * 2. 本探针在客户端收到SYN+ACK、握手即将完成时触发，此时sock已分配完整四元组
 * 过滤条件：仅处理当前sock状态为TCP_SYN_SENT（客户端发完SYN等待对端应答）的连接
 * 逻辑：根据pid_tgid取出connect缓存，计算建连耗时，填充完整事件投递ringbuf并更新全局统计
 */
/**
* @brief 捕获TCP客户端握手完成，生成握手延迟事件上报用户态
* @param sk 当前TCP连接对应的内核sock结构体指针
* @return 0 BPF探针固定返回值
*/
SEC("fentry/tcp_rcv_state_process")
int BPF_PROG(fentry_tcp_rcv_state_process, struct sock *sk)
{
	struct TcpMonitor_ctrl *c = get_ctrl();
	if (!c || !c->enable) return 0;

	// 仅处理处于 TCP_SYN_SENT 状态的套接字：客户端刚发送SYN，收到服务端SYN+ACK
	// 其他TCP状态（ESTABLISHED/TIME_WAIT等）直接跳过，不做处理
	if (BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_SYN_SENT) return 0;

	// 获取当前线程pid_tgid（key，用于匹配connect时存入的会话缓存）
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct tcp_sess *s = bpf_map_lookup_elem(&sess_map, &pid_tgid);
	if (!s) return 0;

	// 从ringbuf预分配一块内存，用于存放输出事件
	struct TcpMonitor_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		bpf_map_delete_elem(&sess_map, &pid_tgid);
		return 0;
	}

	// 标记事件类型为握手事件
	e->type = TCP_EV_HANDSHAKE;
	e->ts_ns = bpf_ktime_get_ns();
	// 计算三次握手总延迟：当前时间 - connect发起时间
	e->latency_ns = e->ts_ns - s->start_ts;

	// 从connect缓存拷贝进程、线程ID信息
	e->pid = s->pid;
	e->tgid = s->tgid;
	
	// 握手刚完成，尚无往返采样、重传、RTO数据，全部置0
	e->retrans_cnt = 0;
	e->state = 0;

	// 拷贝进程名称
	__builtin_memcpy(e->comm, s->comm, TASK_COMM_LEN);

	// 从当前sk读取完整IP+端口四元组（此时源端口已分配，connect阶段port为0无法读取）
	fill_sock(e, sk);
	// 跳过 tcp_close 时 sk 已部分销毁的情况 (源端口为0)
	if (e->sport == 0) { bpf_ringbuf_discard(e, 0); return 0; }

	// 更新全局握手统计：计数、总延迟、最大延迟记录
	update_stats(e);
	// 将事件提交ringbuf，用户态可读取解析
	bpf_ringbuf_submit(e, 0);
	// 会话处理完毕，删除sess_map中本条缓存释放哈希表空间
	bpf_map_delete_elem(&sess_map, &pid_tgid);

	return 0;
}
 

/* ── RETRANSMIT ──────────────────────────────────────────── */
/*
 * kprobe/tcp_retransmit_skb：捕获TCP报文重传事件
 * 挂载点：tcp_retransmit_skb，内核触发任意TCP报文重传时进入
 * 设计思路：以内核sock虚拟地址作为唯一标识，统计单条连接累计重传次数
 * 流程：过滤不需要监控的进程 → 查询/更新重传计数哈希表 → 封装重传事件推ringbuf、更新全局统计
 * 说明：此处使用kprobe而非fentry，部分老内核tcp_retransmit_skb无BTF；若内核5.10+推荐替换fentry更稳定
*/
/**
 * @brief 捕获TCP报文重传动作，生成重传事件上报用户态
 * @param sk 发生报文重传的TCP连接内核sock结构体指针
 * @return 0 BPF探针固定返回值
*/
SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(trace_tcp_retransmit, struct sock *sk)
{
	struct TcpMonitor_ctrl *c = get_ctrl();
	if (pid_skip(c, bpf_get_current_pid_tgid() >> 32))
		return 0;

	// 将sock指针强转为u64，作为retrans_map哈希表唯一key，一条TCP连接对应一个sock地址
	u64 sk_addr = (u64)sk;
	// 根据sock地址查询该连接历史重传记录
	struct retrans_track *rt = bpf_map_lookup_elem(&retrans_map, &sk_addr);

	// 三元逻辑：已有记录则计数+1；无记录则初始化一条count=1的记录写入map
	u32 cnt = rt ? ++rt->count : ({
		struct retrans_track z = {.count=1,.addr=sk_addr};
		bpf_map_update_elem(&retrans_map, &sk_addr, &z, BPF_ANY);
		1;
	});

	// 从环形缓冲区预分配事件内存
	struct TcpMonitor_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	// 填充事件基础信息
	e->type = TCP_EV_RETRANSMIT;                // 标记事件类型为重传
	e->ts_ns = bpf_ktime_get_ns();              // 重传触发时刻纳秒时间戳
	e->state = BPF_CORE_READ(sk, __sk_common.skc_state); // 当前TCP连接状态(ESTABLISHED/TIME_WAIT等)
	e->retrans_cnt = cnt;                       // 当前连接累计重传总次数
	e->pid = bpf_get_current_pid_tgid() >> 32;  // 进程TGID(用户态PID)
	e->tgid = e->pid;                           // 单线程程序pid与tgid相同

	// 重传事件无建连延迟、无实时srtt/mss/rto采样，统一置0
	e->latency_ns = 0;

	// 获取发起该TCP连接的进程名称
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	// 从sock读取完整IPv4/IPv6四元组填充事件
	fill_sock(e, sk);
	// 跳过 tcp_close 时 sk 已部分销毁的情况 (源端口为0)
	if (e->sport == 0) { bpf_ringbuf_discard(e, 0); return 0; }
	// 更新全局统计：全局重传总计数+1
	update_stats(e);

	// 将完整事件提交ringbuf，用户态读取解析
	bpf_ringbuf_submit(e, 0);

	return 0;
}


/* ── CLOSE ───────────────────────────────────────────────── */
/*
 * kprobe/tcp_close 探针：捕获TCP连接关闭事件
 * 挂载点：内核tcp_close函数，应用主动close/内核异常断连都会触发
 * 核心逻辑：
 * 1. 通过sock地址查询该连接生命周期内累计重传总次数
 * 2. 取出重传计数后清理retrans_map中的本条记录，避免哈希表内存堆积
 * 3. 封装TCP_EV_CLOSE事件上报用户态，携带整条连接总重传次数、四元组、进程信息
 * 4. 更新全局关闭连接统计计数
 */
 /**
 * @brief TCP连接关闭钩子，输出连接生命周期汇总事件
 * @param sk 待关闭的TCP套接字内核struct sock指针
 * @return 0 BPF探针标准返回值
 */
SEC("kprobe/tcp_close")
int BPF_KPROBE(trace_tcp_close, struct sock *sk)
{
	struct TcpMonitor_ctrl *c = get_ctrl();
	if (pid_skip(c, bpf_get_current_pid_tgid() >> 32))
		return 0;

	// 将sock内核虚拟地址转为u64，作为retrans_map的检索key
	u64 sk_addr = (u64)sk;
	// 初始化重传总次数为0（无重传则上报0）
	u32 rt_cnt = 0;
	// 查询当前连接对应的重传记录
	struct retrans_track *rt = bpf_map_lookup_elem(&retrans_map, &sk_addr);
	if (rt) {
		// 取出该连接全程累计重传报文总数
		rt_cnt = rt->count;
		// 连接销毁，删除哈希表记录释放map配额
		bpf_map_delete_elem(&retrans_map, &sk_addr);
	}

	// 从ringbuf分配事件内存，用于推送关闭事件至用户态
	struct TcpMonitor_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	// 标记事件类型为TCP连接关闭
	e->type = TCP_EV_CLOSE;
	// 记录连接关闭时刻内核纳秒时间戳
	e->ts_ns = bpf_ktime_get_ns();
	// 读取关闭前套接字所处TCP状态（ESTABLISHED/TIME_WAIT/CLOSED等）
	e->state = BPF_CORE_READ(sk, __sk_common.skc_state);
	// 填入整条连接生命周期累计重传总次数
	e->retrans_cnt = rt_cnt;
	// 当前进程TGID（用户态PID）
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tgid = e->pid;

	// 关闭事件无建连延迟、实时RTT/MSS/RTO指标，全部置0占位
	e->latency_ns = 0;

	// 获取当前业务进程名称
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	// 从sock读取IPv4/IPv6完整四元组填充事件
	fill_sock(e, sk);
	// 跳过 tcp_close 时 sk 已部分销毁的情况 (源端口为0)
	if (e->sport == 0) { bpf_ringbuf_discard(e, 0); return 0; }
	// 更新全局统计：关闭连接计数+1，累加连接存活时长、更新最长连接记录
	update_stats(e);
	
	// 将完整关闭事件提交环形缓冲区，用户态读取解析
	bpf_ringbuf_submit(e, 0);

	return 0;
}