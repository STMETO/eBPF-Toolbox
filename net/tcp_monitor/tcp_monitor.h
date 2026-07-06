#ifndef __TCP_MONITOR_H
#define __TCP_MONITOR_H

#include "common/types.h"

#ifndef AF_INET
#define AF_INET  2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* ── 事件类型 ────────────────────────────────────────────── */
#define TCP_EV_HANDSHAKE   0
#define TCP_EV_RETRANSMIT  1
#define TCP_EV_CLOSE       2

/* ── 控制 ────────────────────────────────────────────────── */
struct TcpMonitor_ctrl {
	bpf_bool_t enable;
	bpf_u64_t  min_latency_ns;
	bpf_s32_t  target_pid;
};

/* ── 内部存储（enter→exit 关联，key=pid_tgid） ───────────── */
struct tcp_sess {
	bpf_u64_t start_ts;
	bpf_u32_t tgid;
	bpf_s32_t pid;
	bpf_u16_t sport, dport;
	bpf_u32_t saddr_v4, daddr_v4;
	int af;
	bpf_u8_t saddr_v6[16], daddr_v6[16];
	bpf_s8_t comm[TASK_COMM_LEN];
};

/* ── 输出事件 ────────────────────────────────────────────── */
struct TcpMonitor_event {
	bpf_u32_t type;            // HANDSHAKE / RETRANSMIT / CLOSE
	bpf_u64_t ts_ns;
	bpf_u64_t latency_ns;      // HANDSHAKE:建连延迟  CLOSE:存活时长  RETRANSMIT:0
	bpf_u32_t srtt_us;         // 内核平滑 RTT（微秒）
	bpf_u32_t mss;             // MSS
	bpf_u32_t retrans_cnt;     // 该连接累计重传次数
	bpf_s32_t pid;
	bpf_u32_t tgid;
	bpf_u16_t sport, dport;
	bpf_u32_t saddr_v4, daddr_v4;
	int af;
	bpf_u32_t state;           // TCP 状态
	bpf_u32_t rto;             // 重传超时(ms)
	bpf_s8_t  comm[TASK_COMM_LEN];
	bpf_u8_t  saddr_v6[16], daddr_v6[16];
};

/* ── 全局统计 ────────────────────────────────────────────── */
struct TcpMonitor_stats {
	bpf_u64_t hs_count, hs_total_ns, hs_max_ns;
	bpf_u64_t rt_count;
	bpf_u64_t cl_count, cl_total_ns, cl_max_ns;
	bpf_u32_t hs_max_sport, hs_max_dport;
	bpf_u32_t hs_max_saddr, hs_max_daddr;
	bpf_s8_t  hs_max_comm[TASK_COMM_LEN];
};

/* ── 重传计数（key=sock*） ───────────────────────────────── */
struct retrans_track {
	bpf_u32_t count;           // 该连接累计重传次数
	bpf_u64_t addr;            // sock 地址（用于 close 查找）
};

#ifndef __BPF__
#include <stdbool.h>
int tcp_monitor_run(int poll_timeout_ms, bool enable,
		    bpf_s32_t target_pid, bpf_u64_t min_latency_ns);
#endif

#endif
