#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "tcp_retransmit.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct TcpRetransmit_ctrl);
} ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static inline struct TcpRetransmit_ctrl *get_ctrl(void)
{
	struct TcpRetransmit_ctrl *ctrl;
	ctrl = bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
	return (ctrl && ctrl->enable) ? ctrl : NULL;
}

/*
 * kprobe/tcp_retransmit_skb
 * 触发时机：TCP 协议栈决定重传一个报文段
 * 作用：记录重传事件的源/目的 IP、端口、进程信息
 */
SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(trace_tcp_retransmit, struct sock *sk, struct sk_buff *skb)
{
	struct TcpRetransmit_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	struct TcpRetransmit_event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ts_ns = bpf_ktime_get_ns();
	e->pid   = (bpf_s32_t)(bpf_get_current_pid_tgid() >> 32);
	e->af    = BPF_CORE_READ(sk, __sk_common.skc_family);
	e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	e->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	e->state = BPF_CORE_READ(sk, __sk_common.skc_state);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	if (e->af == AF_INET) {
		e->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		e->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	} else {
		BPF_CORE_READ_INTO(&e->saddr_v6, sk,
			__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&e->daddr_v6, sk,
			__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}
