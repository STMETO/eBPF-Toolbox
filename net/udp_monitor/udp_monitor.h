#ifndef __UDP_MONITOR_H
#define __UDP_MONITOR_H

#include "common/types.h"

#ifndef AF_INET
#define AF_INET  2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

struct UdpMonitor_ctrl {
	bpf_bool_t enable;
	bpf_u64_t  min_latency_ns;
	bpf_s32_t  target_pid;
};

struct UdpMonitor_event {
	bpf_u64_t ts_ns, latency_ns;
	bpf_u64_t len;             // 发送字节数
	bpf_s32_t pid;
	bpf_u32_t tgid;
	bpf_u16_t sport, dport;
	bpf_u32_t saddr_v4, daddr_v4;
	int af;
	bpf_s8_t  comm[TASK_COMM_LEN];
	bpf_u8_t  saddr_v6[16], daddr_v6[16];
};

struct UdpMonitor_stats {
	bpf_u64_t count, total_ns, max_ns, total_bytes;
	bpf_u32_t max_pid;
	bpf_s8_t  max_comm[TASK_COMM_LEN];
};

#ifndef __BPF__
#include <stdbool.h>
int udp_monitor_run(int poll_timeout_ms, bool enable,
		    bpf_s32_t target_pid, bpf_u64_t min_latency_ns);
#endif

#endif
