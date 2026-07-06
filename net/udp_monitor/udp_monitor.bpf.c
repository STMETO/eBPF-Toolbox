#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "udp_monitor.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
const int ctrl_key = 0;

/* ── PERCPU 暂存 udp_sendmsg 入参 ─────────────────────────── */
struct udp_start {
	bpf_u64_t start_ts;
	bpf_u64_t len;
	bpf_u32_t tgid;
	bpf_s32_t pid;
	bpf_u16_t sport, dport;
	bpf_u32_t saddr_v4, daddr_v4;
	int af;
	bpf_s8_t  comm[TASK_COMM_LEN];
	bpf_u8_t  saddr_v6[16], daddr_v6[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct udp_start);
} start_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct UdpMonitor_ctrl);
} ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct UdpMonitor_stats);
} stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static inline struct UdpMonitor_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
}

/* ── kprobe/udp_sendmsg：记录开始 ──────────────────────────── */
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	struct UdpMonitor_ctrl *c = get_ctrl();
	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!c || !c->enable) return 0;
	if (c->target_pid != 0 && (u32)c->target_pid != tgid) return 0;

	int key = 0;
	struct udp_start *v = bpf_map_lookup_elem(&start_map, &key);
	if (!v) return 0;

	v->start_ts = bpf_ktime_get_ns();
	v->len    = len;
	v->pid    = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	v->tgid   = tgid;
	v->af     = BPF_CORE_READ(sk, __sk_common.skc_family);
	v->sport  = BPF_CORE_READ(sk, __sk_common.skc_num);
	v->dport  = BPF_CORE_READ(sk, __sk_common.skc_dport);
	bpf_get_current_comm(&v->comm, sizeof(v->comm));

	if (v->af == AF_INET) {
		v->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		v->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	} else {
		BPF_CORE_READ_INTO(&v->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&v->daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
	return 0;
}

/* ── kretprobe/udp_sendmsg：计算延迟、发送 ─────────────────── */
SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(ret_udp_sendmsg, int retval)
{
	struct UdpMonitor_ctrl *c = get_ctrl();
	if (!c || !c->enable) return 0;

	int key = 0;
	struct udp_start *v = bpf_map_lookup_elem(&start_map, &key);
	if (!v || v->start_ts == 0) return 0;

	u64 now = bpf_ktime_get_ns();
	u64 lat = now - v->start_ts;
	v->start_ts = 0;

	if (c->min_latency_ns && lat < c->min_latency_ns) return 0;

	struct UdpMonitor_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;

	e->ts_ns      = now;
	e->latency_ns = lat;
	e->len        = v->len;
	e->pid        = v->pid;
	e->tgid       = v->tgid;
	e->af         = v->af;
	e->sport      = v->sport;
	e->dport      = v->dport;
	e->saddr_v4   = v->saddr_v4;
	e->daddr_v4   = v->daddr_v4;
	__builtin_memcpy(e->comm, v->comm, TASK_COMM_LEN);
	__builtin_memcpy(e->saddr_v6, v->saddr_v6, 16);
	__builtin_memcpy(e->daddr_v6, v->daddr_v6, 16);
	bpf_ringbuf_submit(e, 0);

	/* 统计 */
	struct UdpMonitor_stats *st = bpf_map_lookup_elem(&stats_map, &ctrl_key);
	struct UdpMonitor_stats z = {};
	if (!st) { bpf_map_update_elem(&stats_map, &ctrl_key, &z, BPF_ANY); st = bpf_map_lookup_elem(&stats_map, &ctrl_key); }
	if (st) {
		st->count++; st->total_ns += lat; st->total_bytes += v->len;
		if (lat > st->max_ns) {
			st->max_ns = lat; st->max_pid = v->pid;
			__builtin_memcpy(st->max_comm, v->comm, TASK_COMM_LEN);
		}
	}
	return 0;
}
