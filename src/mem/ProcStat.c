#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "app_common.h"
#include "common.h"
#include "ProcStat.h"
#include "proc_stat.h"
#include "mem/ProcStat.skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct ProcStat_event *e = data; (void)ctx; (void)data_sz;
	struct tm *tm; char ts[32]; time_t t;
	time(&t); tm = localtime(&t); strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("%-8s %-8d %-8ld %-8lld %-8lld %-8lld\n",
	       ts, e->pid, e->size, e->rssanon, e->rssfile, e->rssshmem);
	return 0;
}

int proc_stat_run(int poll_timeout_ms, bool enable)
{
	struct ProcStat_bpf *skel = NULL; struct ring_buffer *rb = NULL;
	struct ProcStat_ctrl ctrl = { .enable = enable }; const int key = 0; int err = 0;
	skel = ProcStat_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "Failed ProcStat\n"); return 1; }
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key), &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) { fprintf(stderr, "Control fail: %d\n", err); goto cleanup; }
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -ENOMEM; goto cleanup; }
	err = ProcStat_bpf__attach(skel);
	if (err) { fprintf(stderr, "Attach fail: %d\n", err); goto cleanup; }
	printf("%-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "SIZE", "RSSANON", "RSSFILE", "RSSSHMEM");
	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) break;
	}
cleanup: ring_buffer__free(rb); ProcStat_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
