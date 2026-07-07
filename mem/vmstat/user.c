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
#include "vmstat.h"
#include "mem/vmstat/skel.h"

static struct vmstat_bpf *g_skel = NULL;

static void print_stats(void) {
	if (!g_skel) return; struct Vmstat_stats s = {}; int key = 0;
	if (bpf_map__lookup_elem(g_skel->maps.stats_map, &key, sizeof(key), &s, sizeof(s), 0) || !s.count) return;
	printf(C_CYAN C_BOLD "\n══════ 内存水位统计 ══════\n" C_RESET);
	printf("  采样: %" PRIu64 " 次  avg_free=%" PRIu64 " 页  min=%" PRIu64 "  max=%" PRIu64 "\n",
	       s.count, s.total_free / s.count, s.min_free, s.max_free);
	printf(C_CYAN C_BOLD "════════════════════════════\n" C_RESET);
}
static void sig_handler(int sig) { (void)sig; print_stats(); _exit(0); }

static int handle_event(void *ctx, void *data, size_t data_sz) {
	const struct Vmstat_event *e = data; (void)ctx; (void)data_sz;
	LOG("NODE=%-2d CPU=%-2d FREE=%-6" PRIu64 " | "
	    "ANON: act=%-6" PRIu64 " inact=%-6" PRIu64 " | "
	    "FILE: act=%-6" PRIu64 " inact=%-6" PRIu64 " | "
	    "SLAB: rec=%-6" PRIu64 " unrec=%-6" PRIu64 " | "
	    "O0/1/2/3: %" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64 "\n",
	    e->node_id, e->cpu, e->nr_free,
	    e->nr_anon_active, e->nr_anon_inactive,
	    e->nr_file_active, e->nr_file_inactive,
	    e->nr_slab_reclaimable, e->nr_slab_unreclaimable,
	    e->free_order[0], e->free_order[1], e->free_order[2], e->free_order[3]);
	return 0;
}

int vmstat_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid, bpf_u64_t min_delay_ns) {
	struct vmstat_bpf *skel = NULL; struct ring_buffer *rb = NULL;
	const int key = 0; int err = 0;
	skel = vmstat_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "打开BPF程序失败\n"); return 1; }
	g_skel = skel;
	struct Vmstat_ctrl ctrl = {.enable = enable, .target_pid = target_pid, .sample_rate = (uint32_t)(min_delay_ns > 0 ? 1 : 0)};
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key), &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) { fprintf(stderr, "设置控制开关失败\n"); goto cleanup; }
	signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -ENOMEM; fprintf(stderr, "创建RingBuffer失败\n"); goto cleanup; }
	err = vmstat_bpf__attach(skel);
	if (err) { fprintf(stderr, "挂载BPF程序失败\n"); goto cleanup; }
	log_banner("系统内存监控 (vmstat)", enable);
	LOG_HDR("%-6s %-4s %-7s   %-22s   %-22s   %-22s   %s",
		"NODE", "CPU", "FREE", "ANON(act/inact)", "FILE(act/inact)", "SLAB(rec/unrec)", "FRAG(O0/1/2/3)");
	LOG_SEP();
	while (!app_should_exit()) { err = ring_buffer__poll(rb, poll_timeout_ms); if (err == -EINTR) { err = 0; break; } if (err < 0) break; }
	print_stats();
cleanup: g_skel = NULL; ring_buffer__free(rb); vmstat_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
