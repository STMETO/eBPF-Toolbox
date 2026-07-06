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
#include "msgqueue.h"
#include "lock/msgqueue/skel.h"

static struct msgqueue_bpf *g_skel = NULL;

static void print_stats(void)
{
	if (!g_skel) return; struct Msgqueue_stats s = {}; int key = 0;
	if (bpf_map__lookup_elem(g_skel->maps.stats_map, &key, sizeof(key), &s, sizeof(s), 0)) return;
	if (!s.send_count && !s.recv_count) return;
	fprintf(stderr, "\n");
	printf(C_CYAN C_BOLD "══════ 消息队列统计 ══════\n" C_RESET);
	if (s.send_count) printf("  发送: %" PRIu64 " 次  avg=%" PRIu64 " ns  max=%" PRIu64 " ns\n", s.send_count, s.send_total_ns/s.send_count, s.send_max_ns);
	if (s.recv_count) printf("  接收: %" PRIu64 " 次  avg=%" PRIu64 " ns  max=%" PRIu64 " ns\n", s.recv_count, s.recv_total_ns/s.recv_count, s.recv_max_ns);
	printf(C_CYAN C_BOLD "════════════════════════════\n" C_RESET);
}
static void sig_handler(int sig) { (void)sig; print_stats(); _exit(0); }

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Msgqueue_event *e = data; (void)ctx; (void)data_sz;
	LOG("%-4s | PID=%-6d %-16s MQDES=%-4d LEN=%-6" PRIu64 " PRIO=%-4u | ",
	    e->type == MQ_EV_SEND ? C_GREEN "SEND" C_RESET : C_YELLOW "RECV" C_RESET,
	    e->pid, e->comm, e->mqdes, e->msg_len, e->msg_prio);
	log_col_ns(e->delay_ns, 10000, 100000); printf("\n");
	return 0;
}

int msgqueue_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid, bpf_u64_t min_delay_ns)
{
	struct msgqueue_bpf *skel = NULL; struct ring_buffer *rb = NULL;
	const int key = 0; int err = 0;
	skel = msgqueue_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "打开BPF程序失败\n"); return 1; }
	g_skel = skel;
	struct Msgqueue_ctrl ctrl = {.enable = enable, .min_delay_ns = min_delay_ns, .target_pid = target_pid};
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key), &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) { fprintf(stderr, "设置控制开关失败\n"); goto cleanup; }
	signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -ENOMEM; fprintf(stderr, "创建RingBuffer失败\n"); goto cleanup; }
	err = msgqueue_bpf__attach(skel);
	if (err) { fprintf(stderr, "挂载BPF程序失败\n"); goto cleanup; }
	log_banner("消息队列延迟监控", enable);
	if (target_pid) LOG("过滤 PID=%d\n", target_pid);
	LOG_HDR("%-6s %-7s %-16s %-6s %-7s %-5s   %s", "TYPE", "PID", "COMM", "MQDES", "LEN", "PRIO", "DELAY");
	LOG_SEP();
	while (!app_should_exit()) { err = ring_buffer__poll(rb, poll_timeout_ms); if (err == -EINTR) { err = 0; break; } if (err < 0) break; }
	print_stats();
cleanup: g_skel = NULL; ring_buffer__free(rb); msgqueue_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
