#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "app_common.h"
#include "common.h"
#include "OomKiller.h"
#include "oom_killer.h"
#include "mem/OomKiller.skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct OomKiller_event *e = data; (void)ctx; (void)data_sz;
	struct tm *tm; char ts[32]; time_t t;
	time(&t); tm = localtime(&t); strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("%-8s TriggerPID=%-8u KillPID=%-8u Pages=%-8u Comm=%-16s\n",
	       ts, e->triggered_pid, e->oomkill_pid, e->mem_pages, e->comm);
	return 0;
}

int oom_killer_run(int poll_timeout_ms, bool enable)
{
	struct OomKiller_bpf *skel = NULL; struct ring_buffer *rb = NULL;
	struct OomKiller_ctrl ctrl = { .enable = enable }; const int key = 0; int err = 0;
	skel = OomKiller_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "Failed OomKiller\n"); return 1; }
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key), &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) { fprintf(stderr, "Control fail\n"); goto cleanup; }
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -ENOMEM; goto cleanup; }
	err = OomKiller_bpf__attach(skel);
	if (err) { fprintf(stderr, "Attach fail\n"); goto cleanup; }
	printf("Waiting for OOM events...\n");
	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) break;
	}
cleanup: ring_buffer__free(rb); OomKiller_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
