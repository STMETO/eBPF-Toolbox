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
#include "block_io.h"
#include "fs/block_io/skel.h"

static struct block_io_bpf *g_skel = NULL;

static void print_stats(void)
{
	if (!g_skel) return; struct BlockIo_stats s = {}; int key = 0;
	if (bpf_map__lookup_elem(g_skel->maps.stats_map, &key, sizeof(key), &s, sizeof(s), 0) || !s.complete_cnt) return;
	fprintf(stderr, "\n");
	printf(C_CYAN C_BOLD "══════ 磁盘 IO 统计 ══════\n" C_RESET);
	printf("  完成: %" PRIu64 " 次  avg=%" PRIu64 " us  max=%" PRIu64 " us\n",
	       s.complete_cnt, s.total_lat_ns / (s.complete_cnt * 1000), s.max_lat_ns / 1000);
	printf(C_CYAN C_BOLD "════════════════════════════\n" C_RESET);
}
static void sig_handler(int sig) { (void)sig; print_stats(); _exit(0); }

static const char *rwbs_str(int r) { switch(r) { case 1: return "R"; case 2: return "W"; case 3: return "D"; case 4: return "F"; default: return "?"; } }

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct BlockIo_event *e = data; (void)ctx; (void)data_sz;
	LOG("DEV=%-4d PID=%-6d %-16s SECT=%-8" PRIu64 " CNT=%-4u %s %-6" PRIu64 " B | ",
	    e->dev, e->pid, e->comm, e->sector, e->nr_sectors, rwbs_str(e->rwbs), e->bytes);
	log_col_us(e->latency_ns / 1000, 100, 1000); printf("\n");
	return 0;
}

int block_io_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid, bpf_u64_t min_latency_ns)
{
	struct block_io_bpf *skel = NULL; struct ring_buffer *rb = NULL;
	const int key = 0; int err = 0;
	skel = block_io_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "打开BPF程序失败\n"); return 1; }
	g_skel = skel;
	struct BlockIo_ctrl ctrl = {.enable = enable, .min_latency_ns = min_latency_ns, .target_pid = target_pid};
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key), &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) { fprintf(stderr, "设置控制开关失败\n"); goto cleanup; }
	signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -ENOMEM; fprintf(stderr, "创建RingBuffer失败\n"); goto cleanup; }
	err = block_io_bpf__attach(skel);
	if (err) { fprintf(stderr, "挂载BPF程序失败\n"); goto cleanup; }
	log_banner("磁盘 IO 监控", enable);
	if (target_pid) LOG("过滤 PID=%d\n", target_pid);
	LOG_HDR("%-5s %-7s %-16s %-9s %-4s %s %-7s   %s", "DEV", "PID", "COMM", "SECTOR", "CNT", "RW", "BYTES", "LATENCY");
	LOG_SEP();
	while (!app_should_exit()) { err = ring_buffer__poll(rb, poll_timeout_ms); if (err == -EINTR) { err = 0; break; } if (err < 0) break; }
	print_stats();
cleanup: g_skel = NULL; ring_buffer__free(rb); block_io_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
