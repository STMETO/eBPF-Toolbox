#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "tcp_monitor.h"
#include "common/pid_namespace.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
const int ctrl_key = 0;

/* 用 socket 身份跨进程/软中断上下文关联连接生命周期。 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, bpf_u64_t);
	__type(value, struct tcp_sess);
} sess_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct TcpMonitor_ctrl);
} ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct TcpMonitor_stats);
} stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline struct TcpMonitor_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
}

static __always_inline struct TcpMonitor_stats *get_stats(void)
{
	return bpf_map_lookup_elem(&stats_map, &ctrl_key);
}

static __always_inline bool session_allowed(const struct TcpMonitor_ctrl *ctrl,
					    const struct tcp_sess *sess)
{
	if (!ctrl || !ctrl->enable)
		return false;
	return !ctrl->target_pid || (bpf_u32_t)ctrl->target_pid == sess->tgid;
}

/* 事件中的两个端口统一存主机字节序，用户态不再猜测字段语义。 */
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

static __always_inline void fill_process(struct TcpMonitor_event *event,
					 const struct tcp_sess *sess)
{
	event->tgid = sess->tgid;
	event->tid = sess->tid;
	__builtin_memcpy(event->comm, sess->comm, TASK_COMM_LEN);
}

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

static __always_inline int record_connect(struct sock *sk)
{
	struct TcpMonitor_ctrl *ctrl = get_ctrl();
	struct TcpMonitor_stats *stats;
	struct tcp_sess sess = {};
	bpf_u64_t pid_tgid, key;

	if (!ctrl || !ctrl->enable)
		return 0;
	pid_tgid = app_current_pid_tgid_ns(ctrl->pid_ns_dev, ctrl->pid_ns_ino);
	if (!pid_tgid)
		return 0;
	sess.tgid = (bpf_u32_t)(pid_tgid >> 32);
	sess.tid = (bpf_u32_t)pid_tgid;
	if (ctrl->target_pid && (bpf_u32_t)ctrl->target_pid != sess.tgid)
		return 0;

	stats = get_stats();
	if (stats)
		stats->connect_attempted++;
	sess.start_ts = bpf_ktime_get_ns();
	bpf_get_current_comm(sess.comm, sizeof(sess.comm));
	/*
	 * 后续握手、重传和关闭可能运行在 softirq/ksoftirqd 上下文，current
	 * PID 不再属于发起连接的应用。以 socket 地址为 key 保存进程归属，
	 * 才能在跨上下文事件中保持同一连接身份。
	 */
	key = (bpf_u64_t)sk;
	if (bpf_map_update_elem(&sess_map, &key, &sess, BPF_ANY) && stats)
		stats->map_update_failed++;
	return 0;
}

SEC("fentry/tcp_v4_connect")
int BPF_PROG(fentry_tcp_v4_connect, struct sock *sk)
{
	return record_connect(sk);
}

SEC("fentry/tcp_v6_connect")
int BPF_PROG(fentry_tcp_v6_connect, struct sock *sk)
{
	return record_connect(sk);
}

static __always_inline int finish_connect_call(struct sock *sk, int ret)
{
	bpf_u64_t key = (bpf_u64_t)sk;
	struct tcp_sess *sess;

	/* tcp_v[46]_connect 失败时不会有有效握手完成事件，立即释放会话。 */
	if (ret < 0) {
		bpf_map_delete_elem(&sess_map, &key);
		return 0;
	}
	sess = bpf_map_lookup_elem(&sess_map, &key);
	if (sess)
		save_sock(sess, sk);
	return 0;
}

SEC("fexit/tcp_v4_connect")
int BPF_PROG(fexit_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr,
	     int addr_len, int ret)
{
	(void)uaddr;
	(void)addr_len;
	return finish_connect_call(sk, ret);
}

SEC("fexit/tcp_v6_connect")
int BPF_PROG(fexit_tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr,
	     int addr_len, int ret)
{
	(void)uaddr;
	(void)addr_len;
	return finish_connect_call(sk, ret);
}

/* tcp_finish_connect 只在主动连接真正进入已建立阶段时调用。 */
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
		/*
		 * 指定 PID 时，未跟踪 socket 很可能只是其他进程的连接，不能当作
		 * 关联失败；全量模式下才把它计为真正的数据质量指标。
		 */
		if (stats && !ctrl->target_pid)
			stats->untracked_events++;
		return 0;
	}
	if (!session_allowed(ctrl, sess) || sess->handshake_reported)
		return 0;

	now = bpf_ktime_get_ns();
	latency_ns = now - sess->start_ts;
	/* 无论阈值过滤还是 ringbuf 满，一条连接的握手最多处理一次。 */
	sess->handshake_reported = true;
	if (ctrl->min_latency_ns && latency_ns < ctrl->min_latency_ns) {
		if (stats)
			stats->filtered_latency++;
		return 0;
	}

	/*
	 * 汇总统计不应依赖用户态是否来得及消费 ringbuf，因此先缓存四元组并
	 * 聚合，再尝试 reserve。ringbuf 满只丢失该条明细，不会让退出摘要少算。
	 */
	save_sock(sess, sk);
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

	__sync_fetch_and_add(&sess->retrans_cnt, 1);
	retrans_cnt = sess->retrans_cnt;
	/* 重传计数是聚合指标，即使明细因 ringbuf 满被丢弃也必须保留。 */
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
	 * tcp_close 后 socket 字段可能被清零或对象很快释放，因此先复制会话
	 * 和建连时缓存的四元组，再删除 Map。这样 close 输出不会出现源端口 0，
	 * socket 地址复用也不会继承上一条连接的计数。
	 */
	__builtin_memcpy(&snapshot, sess, sizeof(snapshot));
	/* 状态无论是否上报都必须清理，避免 socket 地址复用污染。 */
	bpf_map_delete_elem(&sess_map, &key);
	if (!session_allowed(ctrl, &snapshot))
		return 0;

	now = bpf_ktime_get_ns();
	lifetime_ns = now - snapshot.start_ts;
	/* 连接生命周期摘要同样先于 ringbuf reserve 更新，避免输出拥塞少算。 */
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
