#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "common/cli.h"
#include "common/types.h"
#include "common/logger.h"
#include "tcp_monitor.h"
#include "net/tcp_monitor/skel.h"

static struct tcp_monitor_bpf *g_skel = NULL;

static void fmt_addr(char *buf, size_t len, int af, uint32_t v4, uint8_t *v6,
		     uint16_t port)
{
	char ip[INET6_ADDRSTRLEN];
	if (af == AF_INET)
		inet_ntop(AF_INET, &v4, ip, sizeof(ip));
	else if (af == AF_INET6) {
		inet_ntop(AF_INET6, v6, ip, sizeof(ip));
		/* 精简 IPv4-mapped: ::ffff:1.2.3.4 → 1.2.3.4 */
		if (strncmp(ip, "::ffff:", 7) == 0)
			snprintf(buf, len, "%s:%-5d", ip + 7, ntohs(port));
		else
			snprintf(buf, len, "[%s]:%-5d", ip, ntohs(port));
		return;
	} else { snprintf(buf, len, "?:%-5d", ntohs(port)); return; }
	snprintf(buf, len, "%s:%-5d", ip, ntohs(port));
}

static void print_stats(void)
{
	if (!g_skel) return;
	struct TcpMonitor_stats s = {};
	int key = 0;
	if (bpf_map__lookup_elem(g_skel->maps.stats_map, &key, sizeof(key),
				 &s, sizeof(s), 0) || s.hs_count + s.rt_count + s.cl_count == 0)
		return;

	char src[64], dst[64];
	fprintf(stderr, "\n");
	printf(C_CYAN C_BOLD "══════ TCP 监控统计 ══════\n" C_RESET);
	if (s.hs_count) {
		fmt_addr(src, sizeof(src), AF_INET, s.hs_max_saddr, NULL, s.hs_max_sport);
		fmt_addr(dst, sizeof(dst), AF_INET, s.hs_max_daddr, NULL, s.hs_max_dport);
		printf("  握手: %" PRIu64 " 次  avg=%" PRIu64 " us  max=%" PRIu64 " us"
		       "  (%s → %s)\n",
		       s.hs_count, s.hs_total_ns / (s.hs_count * 1000),
		       s.hs_max_ns / 1000, src, dst);
	}
	if (s.rt_count)
		printf("  重传: %" PRIu64 " 次\n", s.rt_count);
	if (s.cl_count)
		printf("  关闭: %" PRIu64 " 次\n", s.cl_count);
	printf(C_CYAN C_BOLD "════════════════════════════\n" C_RESET);
}

static void sig_handler(int sig) { (void)sig; print_stats(); _exit(0); }

static const char *tcp_state_str(uint32_t state)
{
	switch (state) {
	case 1: return "ESTAB"; case 2: return "SYN_SENT"; case 3: return "SYN_RECV";
	case 4: return "FIN_W1"; case 5: return "CLOSE_W"; case 6: return "LAST_ACK";
	case 7: return "TIME_W"; case 8: return "CLOSED"; default: return "???";
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct TcpMonitor_event *e = data;
	(void)ctx; (void)data_sz;
	char src[48], dst[48];
	fmt_addr(src, sizeof(src), e->af, e->saddr_v4, (uint8_t*)e->saddr_v6, e->sport);
	fmt_addr(dst, sizeof(dst), e->af, e->daddr_v4, (uint8_t*)e->daddr_v6, e->dport);

	switch (e->type) {
	case TCP_EV_HANDSHAKE:
		LOG("%-10s | PID=%-6d %-16s %-25s → %-25s | ",
		    C_GREEN "HANDSHAKE" C_RESET, e->pid, e->comm, src, dst);
		log_col_us(e->latency_ns / 1000, 1000, 10000);
		printf("\n");
		break;
	case TCP_EV_RETRANSMIT:
		LOG("%-10s | PID=%-6d %-16s %-25s ← %-25s | R#%-3u %s\n",
		    C_YELLOW "RETRANSMIT" C_RESET, e->pid, e->comm, src, dst,
		    e->retrans_cnt, tcp_state_str(e->state));
		break;
	case TCP_EV_CLOSE:
		LOG("%-10s | PID=%-6d %-16s %-25s → %-25s | R#%-3u %s\n",
		    C_CYAN "CLOSE" C_RESET, e->pid, e->comm, src, dst,
		    e->retrans_cnt, tcp_state_str(e->state));
		break;
	}
	return 0;
}

int tcp_monitor_run(int poll_timeout_ms, bool enable,
		    bpf_s32_t target_pid, bpf_u64_t min_latency_ns)
{
	struct tcp_monitor_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	const int key = 0; int err = 0;

	skel = tcp_monitor_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "打开BPF程序失败\n"); return 1; }
	g_skel = skel;

	struct TcpMonitor_ctrl ctrl = {.enable = enable, .min_latency_ns = min_latency_ns,
				       .target_pid = target_pid};
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) { fprintf(stderr, "设置控制开关失败: %s\n", strerror(-err)); goto cleanup; }

	signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -ENOMEM; fprintf(stderr, "创建RingBuffer失败\n"); goto cleanup; }
	err = tcp_monitor_bpf__attach(skel);
	if (err) { fprintf(stderr, "挂载BPF程序失败\n"); goto cleanup; }

	log_banner("TCP 网络监控", enable);
	if (target_pid) LOG("过滤 PID=%d\n", target_pid);
	LOG_HDR("%-12s %-7s %-16s %-26s %-26s %s",
		"EVENT", "PID", "COMM", "SRC:PORT", "DST:PORT", "DETAIL");
	LOG_SEP();

	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) { fprintf(stderr, "轮询事件失败: %s\n", strerror(-err)); break; }
	}
	print_stats();

cleanup:
	g_skel = NULL; ring_buffer__free(rb); tcp_monitor_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
