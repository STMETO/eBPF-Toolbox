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
#include "udp_monitor.h"
#include "net/udp_monitor/skel.h"

static struct udp_monitor_bpf *g_skel = NULL;

static void ip_str(char *buf, size_t len, int af, uint32_t v4, uint8_t *v6)
{
	if (af == AF_INET) inet_ntop(AF_INET, &v4, buf, len);
	else if (af == AF_INET6) inet_ntop(AF_INET6, v6, buf, len);
	else snprintf(buf, len, "?");
}

static void print_stats(void)
{
	if (!g_skel) return;
	struct UdpMonitor_stats s = {};
	int key = 0;
	if (bpf_map__lookup_elem(g_skel->maps.stats_map, &key, sizeof(key),
				 &s, sizeof(s), 0) || s.count == 0) return;
	printf(C_CYAN C_BOLD "\n══════ UDP 监控统计 ══════\n" C_RESET);
	printf("  发送: %" PRIu64 " 次  %" PRIu64 " 字节\n", s.count, s.total_bytes);
	printf("  平均: %" PRIu64 " ns  最大: %" PRIu64 " ns (PID=%d %s)\n",
	       s.total_ns / s.count, s.max_ns, s.max_pid, s.max_comm);
	printf(C_CYAN C_BOLD "════════════════════════════\n" C_RESET);
}

static void sig_handler(int sig) { (void)sig; print_stats(); _exit(0); }

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct UdpMonitor_event *e = data;
	(void)ctx; (void)data_sz;
	char src[64], dst[64];
	ip_str(src, sizeof(src), e->af, e->saddr_v4, (uint8_t*)e->saddr_v6);
	ip_str(dst, sizeof(dst), e->af, e->daddr_v4, (uint8_t*)e->daddr_v6);

	LOG("PID=%-6d(%-16s) %s:%-5d → %s:%-5d | %-6" PRIu64 " B | ",
	    e->pid, e->comm, src, e->sport, dst, e->dport, e->len);
	log_col_ns(e->latency_ns, 10000, 100000);
	printf("\n");
	return 0;
}

int udp_monitor_run(int poll_timeout_ms, bool enable,
		    bpf_s32_t target_pid, bpf_u64_t min_latency_ns)
{
	struct udp_monitor_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	const int key = 0; int err = 0;

	skel = udp_monitor_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "打开BPF程序失败\n"); return 1; }
	g_skel = skel;

	struct UdpMonitor_ctrl ctrl = {.enable = enable, .min_latency_ns = min_latency_ns,
				       .target_pid = target_pid};
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) { fprintf(stderr, "设置控制开关失败: %s\n", strerror(-err)); goto cleanup; }

	signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -ENOMEM; fprintf(stderr, "创建RingBuffer失败\n"); goto cleanup; }
	err = udp_monitor_bpf__attach(skel);
	if (err) { fprintf(stderr, "挂载BPF程序失败\n"); goto cleanup; }

	log_banner("UDP 发送监控", enable);
	if (target_pid) LOG("过滤 PID=%d  阈值=%" PRIu64 " ns\n", target_pid, min_latency_ns);
	else if (min_latency_ns) LOG("过滤 ALL PID  阈值=%" PRIu64 " ns\n", min_latency_ns);
	else LOG("过滤 ALL PID  阈值=无\n");
	LOG_HDR("%-7s %-16s %-22s %-22s %-10s %s",
		"PID", "COMM", "SRC:PORT", "DST:PORT", "BYTES", "DELAY");
	LOG_SEP();

	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) { fprintf(stderr, "轮询事件失败: %s\n", strerror(-err)); break; }
	}
	print_stats();

cleanup:
	g_skel = NULL; ring_buffer__free(rb); udp_monitor_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
