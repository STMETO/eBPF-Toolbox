#include <errno.h>
#include <stdio.h>
#include <time.h>

#include <bpf/libbpf.h>

#include "common/cli.h"
#include "common/types.h"
#include "read.h"
#include "read.h"
#include "fs/read/skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Read_event *e = data;
	(void)ctx;
	(void)data_sz;

	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s  %-7d  %-7llu\n", ts, e->pid, e->duration_ns);
	return 0;
}

int read_run(int poll_timeout_ms, bool enable)
{
	struct read_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct Read_ctrl ctrl = { .enable = enable };
	const int key = 0;
	int err = 0;

	/* Open and load BPF program */
	skel = read_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load Read BPF skeleton\n");
		return 1;
	}

	/* Update ctrl_map to enable/disable monitoring */
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Failed to set control switch: %d\n", err);
		goto cleanup;
	}

	/* Create ring buffer */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Attach BPF program */
	err = read_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("%-8s  %-7s   %-7s\n", "TIME", "PID", "durations");

	/* Poll ring buffer */
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
	read_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
