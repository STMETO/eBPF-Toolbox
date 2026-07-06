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
#include "syscall.h"
#include "lock/syscall/skel.h"

static struct syscall_bpf *g_skel = NULL;

static void print_stats(void)
{
	if (!g_skel) return;
	struct Syscall_stats s = {}; int key = 0;
	if (bpf_map__lookup_elem(g_skel->maps.stats_map, &key, sizeof(key), &s, sizeof(s), 0) || s.count == 0) return;
	fprintf(stderr, "\n");
	printf(C_CYAN C_BOLD "══════ 系统调用统计 ══════\n" C_RESET);
	printf("  采样: %" PRIu64 " 次  avg=%" PRIu64 " us\n", s.count, s.total_ns / s.count);
	printf("  最大: %" PRIu64 " us  PID=%d(%s)  syscall=%d\n", s.max_ns, s.max_pid, s.max_comm, s.max_syscall_id);
	printf(C_CYAN C_BOLD "════════════════════════════\n" C_RESET);
}
static void sig_handler(int sig) { (void)sig; print_stats(); _exit(0); }

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Syscall_event *e = data; (void)ctx; (void)data_sz;
	LOG("%-5d %-5d %-16s %-4d | ", e->pid, e->tid, e->comm, e->syscall_id);
	log_col_us(e->delay_ns, 100, 1000); printf("\n");
	return 0;
}

int syscall_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid, bpf_u64_t min_delay_ns)
{
	struct syscall_bpf *skel = NULL; struct ring_buffer *rb = NULL;
	const int key = 0; int err = 0;
	skel = syscall_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "打开BPF程序失败\n"); return 1; }
	g_skel = skel;
	struct Syscall_ctrl ctrl = {.enable = enable, .min_delay_ns = min_delay_ns, .target_pid = target_pid};
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key), &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) { fprintf(stderr, "设置控制开关失败\n"); goto cleanup; }
	signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -ENOMEM; fprintf(stderr, "创建RingBuffer失败\n"); goto cleanup; }
	err = syscall_bpf__attach(skel);
	if (err) { fprintf(stderr, "挂载BPF程序失败\n"); goto cleanup; }
	log_banner("系统调用延迟监控", enable);
	if (target_pid) LOG("过滤 PID=%d\n", target_pid);
	LOG_HDR("%-5s %-5s %-16s %-4s   %s", "PID", "TID", "COMM", "SYSCALL", "DELAY");
	LOG_SEP();
	while (!app_should_exit()) { err = ring_buffer__poll(rb, poll_timeout_ms); if (err == -EINTR) { err = 0; break; } if (err < 0) break; }
	print_stats();
cleanup: g_skel = NULL; ring_buffer__free(rb); syscall_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
