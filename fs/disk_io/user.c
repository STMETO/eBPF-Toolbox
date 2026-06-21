#include <errno.h>
#include <stdio.h>
#include <inttypes.h>

#include <bpf/libbpf.h>

#include "common/cli.h"
#include "common/types.h"
#include "disk_io.h"
#include "fs/disk_io/skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct DiskIoVisit_event *e = data;
	(void)ctx;
	(void)data_sz;

	printf("%-10lld %-9d %-7d %-4d %-7d %-16s\n",
	       e->timestamp, e->blk_dev, e->sectors, e->rwbs, e->count, e->comm);
	return 0;
}

int disk_io_visit_run(int poll_timeout_ms, bool enable)
{
	struct disk_io_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct DiskIoVisit_ctrl ctrl = { .enable = enable };
	const int key = 0;
	int err = 0;

	skel = disk_io_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load DiskIoVisit BPF skeleton\n");
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

	err = disk_io_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("%-18s %-7s %-7s %-4s %-7s %-16s\n",
	       "TIME", "DEV", "SECTOR", "RWBS", "COUNT", "COMM");

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
	disk_io_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
