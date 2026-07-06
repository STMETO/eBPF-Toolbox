#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "tcp_monitor.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
const int ctrl_key = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, struct tcp_sess);
} sess_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, struct retrans_track);
} retrans_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct TcpMonitor_ctrl);
} ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct TcpMonitor_stats);
} stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static inline struct TcpMonitor_ctrl *get_ctrl(void)
{ return bpf_map_lookup_elem(&ctrl_map, &ctrl_key); }

static inline bool pid_skip(struct TcpMonitor_ctrl *c, u32 tgid)
{
	if (!c || !c->enable) return true;
	if (c->target_pid != 0 && (u32)c->target_pid != tgid) return true;
	return false;
}

static void fill_sock(struct TcpMonitor_event *e, struct sock *sk)
{
	e->af    = BPF_CORE_READ(sk, __sk_common.skc_family);
	e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	e->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	if (e->af == AF_INET) {
		e->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		e->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	} else {
		BPF_CORE_READ_INTO(&e->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&e->daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
}

static void update_stats(struct TcpMonitor_event *e)
{
	struct TcpMonitor_stats *st = bpf_map_lookup_elem(&stats_map, &ctrl_key);
	if (!st) { struct TcpMonitor_stats z = {}; bpf_map_update_elem(&stats_map, &ctrl_key, &z, BPF_ANY); st = bpf_map_lookup_elem(&stats_map, &ctrl_key); }
	if (!st) return;
	switch (e->type) {
	case TCP_EV_HANDSHAKE:
		st->hs_count++; st->hs_total_ns += e->latency_ns;
		if (e->latency_ns > st->hs_max_ns) { st->hs_max_ns = e->latency_ns; st->hs_max_sport = e->sport; st->hs_max_dport = e->dport; st->hs_max_saddr = e->saddr_v4; st->hs_max_daddr = e->daddr_v4; __builtin_memcpy(st->hs_max_comm, e->comm, TASK_COMM_LEN); }
		break;
	case TCP_EV_RETRANSMIT: st->rt_count++; break;
	case TCP_EV_CLOSE: st->cl_count++; st->cl_total_ns += e->latency_ns; if (e->latency_ns > st->cl_max_ns) st->cl_max_ns = e->latency_ns; break;
	}
}

/* ── connect: 只存 pid/comm/ts，端口稍后在 handshake 时从 sk 取 ── */
static int trace_connect(struct sock *sk)
{
	struct TcpMonitor_ctrl *c = get_ctrl();
	u64 pid_tgid = bpf_get_current_pid_tgid();
	if (pid_skip(c, pid_tgid >> 32)) return 0;
	struct tcp_sess s = {};
	s.start_ts = bpf_ktime_get_ns();
	s.pid  = pid_tgid & 0xFFFFFFFF;
	s.tgid = pid_tgid >> 32;
	bpf_get_current_comm(&s.comm, sizeof(s.comm));
	bpf_map_update_elem(&sess_map, &pid_tgid, &s, BPF_ANY);
	return 0;
}

SEC("fentry/tcp_v4_connect")
int BPF_PROG(fentry_tcp_v4_connect, struct sock *sk) { return trace_connect(sk); }
SEC("fentry/tcp_v6_connect")
int BPF_PROG(fentry_tcp_v6_connect, struct sock *sk) { return trace_connect(sk); }

/* ── HANDSHAKE: 从 sk 直接读端口（避免 connect 时 port=0） ── */
SEC("fentry/tcp_rcv_state_process")
int BPF_PROG(fentry_tcp_rcv_state_process, struct sock *sk)
{
	struct TcpMonitor_ctrl *c = get_ctrl();
	if (!c || !c->enable) return 0;
	if (BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_SYN_SENT) return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct tcp_sess *s = bpf_map_lookup_elem(&sess_map, &pid_tgid);
	if (!s) return 0;

	struct TcpMonitor_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) { bpf_map_delete_elem(&sess_map, &pid_tgid); return 0; }
	e->type = TCP_EV_HANDSHAKE;
	e->ts_ns = bpf_ktime_get_ns();
	e->latency_ns = e->ts_ns - s->start_ts;
	e->pid = s->pid; e->tgid = s->tgid; e->srtt_us = 0; e->mss = 0; e->retrans_cnt = 0; e->rto = 0; e->state = 0;
	__builtin_memcpy(e->comm, s->comm, TASK_COMM_LEN);
	fill_sock(e, sk);  /* ← 从 sk 直接读，端口此时已分配 */
	update_stats(e);
	bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&sess_map, &pid_tgid);
	return 0;
}

/* ── RETRANSMIT ──────────────────────────────────────────── */
SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(trace_tcp_retransmit, struct sock *sk)
{
	struct TcpMonitor_ctrl *c = get_ctrl();
	if (pid_skip(c, bpf_get_current_pid_tgid() >> 32)) return 0;
	u64 sk_addr = (u64)sk;
	struct retrans_track *rt = bpf_map_lookup_elem(&retrans_map, &sk_addr);
	u32 cnt = rt ? ++rt->count : ({ struct retrans_track z = {.count=1,.addr=sk_addr}; bpf_map_update_elem(&retrans_map, &sk_addr, &z, BPF_ANY); 1; });
	struct TcpMonitor_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;
	e->type = TCP_EV_RETRANSMIT; e->ts_ns = bpf_ktime_get_ns(); e->state = BPF_CORE_READ(sk, __sk_common.skc_state);
	e->retrans_cnt = cnt; e->pid = bpf_get_current_pid_tgid() >> 32; e->tgid = e->pid;
	e->latency_ns = 0; e->srtt_us = 0; e->mss = 0; e->rto = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	fill_sock(e, sk); update_stats(e); bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── CLOSE ───────────────────────────────────────────────── */
SEC("kprobe/tcp_close")
int BPF_KPROBE(trace_tcp_close, struct sock *sk)
{
	struct TcpMonitor_ctrl *c = get_ctrl();
	if (pid_skip(c, bpf_get_current_pid_tgid() >> 32)) return 0;
	u64 sk_addr = (u64)sk;
	u32 rt_cnt = 0;
	struct retrans_track *rt = bpf_map_lookup_elem(&retrans_map, &sk_addr);
	if (rt) { rt_cnt = rt->count; bpf_map_delete_elem(&retrans_map, &sk_addr); }
	struct TcpMonitor_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;
	e->type = TCP_EV_CLOSE; e->ts_ns = bpf_ktime_get_ns(); e->state = BPF_CORE_READ(sk, __sk_common.skc_state);
	e->retrans_cnt = rt_cnt; e->pid = bpf_get_current_pid_tgid() >> 32; e->tgid = e->pid;
	e->latency_ns = 0; e->srtt_us = 0; e->mss = 0; e->rto = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	fill_sock(e, sk); update_stats(e); bpf_ringbuf_submit(e, 0);
	return 0;
}
