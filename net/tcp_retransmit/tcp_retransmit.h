#ifndef __TCP_RETRANSMIT_H
#define __TCP_RETRANSMIT_H

#include "common/types.h"

#ifndef AF_INET
#define AF_INET  2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

struct TcpRetransmit_ctrl {
	bpf_bool_t enable;
};

struct TcpRetransmit_event {
	bpf_u64_t ts_ns;               // 重传时间戳（纳秒）
	bpf_s32_t pid;                 // 触发重传的进程 PID
	bpf_s32_t state;               // TCP 连接状态
	int af;                        // AF_INET / AF_INET6
	bpf_u32_t saddr_v4;            // 源 IP (v4)
	bpf_u32_t daddr_v4;            // 目的 IP (v4)
	bpf_u8_t  saddr_v6[16];        // 源 IP (v6)
	bpf_u8_t  daddr_v6[16];        // 目的 IP (v6)
	bpf_u16_t sport;               // 源端口
	bpf_u16_t dport;               // 目的端口
	bpf_s8_t  comm[TASK_COMM_LEN]; // 进程名
};

#ifndef __BPF__
#include <stdbool.h>
int tcp_retransmit_run(int poll_timeout_ms, bool enable);
#endif

#endif
