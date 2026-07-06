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
#include "mutexlock.h"
#include "lock/mutexlock/skel.h"

static struct mutexlock_bpf *g_skel = NULL;

static void print_stats(void)
{
	if (!g_skel) return; struct Mutexlock_stats s = {}; int key = 0;
	if (bpf_map__lookup_elem(g_skel->maps.stats_map, &key, sizeof(key), &s, sizeof(s), 0) || !s.contention_count) return;
	fprintf(stderr, "\n");
	printf(C_CYAN C_BOLD "══════ 互斥锁统计 ══════\n" C_RESET);
	printf("  竞争: %" PRIu64 " 次\n", s.contention_count);
	printf(C_CYAN C_BOLD "════════════════════════════\n" C_RESET);
}
static void sig_handler(int sig) { (void)sig; print_stats(); _exit(0); }

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Mutexlock_event *e = data; (void)ctx; (void)data_sz;
	LOG("LOCK=0x%-16" PRIx64 " | OWNER: PID=%-6d %-16s PRIO=%-4d | "
	    C_RED "CONTENDER" C_RESET ": PID=%-6d %-16s PRIO=%-4d\n",
	    e->ptr, e->owner_pid, e->owner_name, e->owner_prio,
	    e->contender_pid, e->contender_name, e->contender_prio);
	return 0;
}

int mutexlock_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid, bpf_u64_t min_delay_ns)
{
	struct mutexlock_bpf *skel = NULL; struct ring_buffer *rb = NULL;
	const int key = 0; int err = 0;
	skel = mutexlock_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "打开BPF程序失败\n"); return 1; }
	g_skel = skel;
	struct Mutexlock_ctrl ctrl = {.enable = enable, .min_delay_ns = min_delay_ns, .target_pid = target_pid};
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key), &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) { fprintf(stderr, "设置控制开关失败\n"); goto cleanup; }
	signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -ENOMEM; fprintf(stderr, "创建RingBuffer失败\n"); goto cleanup; }
	err = mutexlock_bpf__attach(skel);
	if (err) { fprintf(stderr, "挂载BPF程序失败\n"); goto cleanup; }
	log_banner("互斥锁竞争监控", enable);
	if (target_pid) LOG("过滤 PID=%d\n", target_pid);
	LOG_HDR("%-20s %-7s %-16s %-5s   %-7s %-16s %-5s",
		"LOCK_ADDR", "OWNER", "O_NAME", "PRIO", "CTENDER", "C_NAME", "PRIO");
	LOG_SEP();
	while (!app_should_exit()) { err = ring_buffer__poll(rb, poll_timeout_ms); if (err == -EINTR) { err = 0; break; } if (err < 0) break; }
	print_stats();
cleanup: g_skel = NULL; ring_buffer__free(rb); mutexlock_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
