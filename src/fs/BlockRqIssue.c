#include <errno.h>
#include <stdio.h>
#include <inttypes.h>

#include <bpf/libbpf.h>

#include "app_common.h"
#include "common.h"
#include "BlockRqIssue.h"
#include "block_rq_issue.h"
#include "fs/BlockRqIssue.skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct BlockRqIssue_event *e = data;
	(void)ctx;
	(void)data_sz;

	printf("%-10lld %-9d %-7d %-4d %-16s Total I/O: %" PRIu64 "\n",
	       e->timestamp, e->dev, e->sector, e->nr_sectors, e->comm, e->total_io);
	return 0;
}

int block_rq_issue_run(int poll_timeout_ms, bool enable)
{
	struct BlockRqIssue_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct BlockRqIssue_ctrl ctrl = { .enable = enable };
	const int key = 0;
	int err = 0;

	skel = BlockRqIssue_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BlockRqIssue BPF skeleton\n");
		return 1;
	}

	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Failed to set control switch: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	err = BlockRqIssue_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("%-10s %-9s %-7s %-4s %-16s %-12s\n",
	       "TIME", "DEV", "SECTOR", "RWBS", "COMM", "Total I/O");

	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	BlockRqIssue_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
