#include <errno.h>
#include <stdio.h>
#include <time.h>

#include <bpf/libbpf.h>

#include "app_common.h"
#include "common.h"
#include "Write.h"
#include "write.h"
#include "fs/Write.skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Write_event *e = data;
	(void)ctx;
	(void)data_sz;

	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s  %-7d %-7d %-7llu %-7llu\n",
	       ts, e->pid, e->fd, e->real_count, e->count);
	return 0;
}

int write_run(int poll_timeout_ms, bool enable)
{
	struct Write_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct Write_ctrl ctrl = { .enable = enable };
	const int key = 0;
	int err = 0;

	skel = Write_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load Write BPF skeleton\n");
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

	err = Write_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("%-8s  %-7s %-7s %-7s %-7s\n",
	       "TIME", "PID", "FD", "REAL", "COUNT");

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
	Write_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
