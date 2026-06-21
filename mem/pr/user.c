#include <errno.h>
#include <stdio.h>
#include <bpf/libbpf.h>
#include "common/cli.h"
#include "common/types.h"
#include "pr.h"
#include "pr.h"
#include "mem/pr/skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Pr_event *e = data;
	(void)ctx; (void)data_sz;
	printf("%-8lu %-8lu %-8u %-8u %-8u\n",
	       e->reclaim, e->reclaimed, e->unqueued_dirty, e->congested, e->writeback);
	return 0;
}

int pr_run(int poll_timeout_ms, bool enable)
{
	struct pr_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct Pr_ctrl ctrl = { .enable = enable };
	const int key = 0;
	int err = 0;

	skel = pr_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "Failed to open Pr BPF skeleton\n"); return 1; }
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key), &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) { fprintf(stderr, "Failed to set control: %d\n", err); goto cleanup; }
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -ENOMEM; fprintf(stderr, "Failed to create ring buffer\n"); goto cleanup; }
	err = pr_bpf__attach(skel);
	if (err) { fprintf(stderr, "Failed to attach: %d\n", err); goto cleanup; }

	printf("%-8s %-8s %-8s %-8s %-8s\n", "RECLAIM", "RECLAIMED", "UNQUEUE", "CONGESTED", "WRITEBACK");
	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) { fprintf(stderr, "Poll error: %d\n", err); break; }
	}
cleanup:
	ring_buffer__free(rb); pr_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
