#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "common/cli.h"
#include "proc_stat.h"
#include "mem/proc_stat/skel.h"

static struct proc_stat_bpf *g_skel = NULL;
static void sig_handler(int sig) { (void)sig; _exit(0); }

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct ProcStat_event *e = data;
	(void)ctx; (void)data_sz;
	printf("[%d] %-16s\n", e->pid, e->comm);
	fflush(stdout);
	return 0;
}

int proc_stat_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid, bpf_u64_t min_delay_ns)
{
	struct proc_stat_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	const int key = 0; int err = 0;

	skel = proc_stat_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "打开BPF程序失败\n"); return 1; }
	g_skel = skel;

	struct ProcStat_ctrl ctrl = {.enable = enable, .min_delay_ns = min_delay_ns, .target_pid = target_pid};
	bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key), &ctrl, sizeof(ctrl), BPF_ANY);

	signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { fprintf(stderr, "ringbuf fail\n"); goto cleanup; }
	err = proc_stat_bpf__attach(skel);
	if (err) { fprintf(stderr, "attach fail\n"); goto cleanup; }

	printf("proc_stat running, Ctrl+C to exit\n");
	if (target_pid) printf("filter PID=%d\n", target_pid);
	fflush(stdout);

	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) break;
	}

cleanup:
	g_skel = NULL; ring_buffer__free(rb); proc_stat_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
