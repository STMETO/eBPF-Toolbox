#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "app_common.h"
#include "common.h"
#include "Open.h"
#include "open.h"
#include "fs/Open.skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Open_event *e = data;
	int map_fd = *(int *)ctx; /* ctx 传递的是 comm_cache map 的文件描述符 */

	char fd_path[FS_OPEN_PATH_SIZE];
	char actual_path[FS_OPEN_PATH_SIZE];
	char comm[TASK_COMM_LEN];

	for (int i = 0; i < e->n_; ++i) {
		snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", e->pid_, i);
		ssize_t len = readlink(fd_path, actual_path, sizeof(actual_path) - 1);
		if (len != -1) {
			actual_path[len] = '\0';
			if (strcmp(e->path_name_, actual_path) == 0) {
				if (bpf_map_lookup_elem(map_fd, &e->pid_, &comm) == 0) {
					printf("%-8s  %-8d  %-8d  %-8s\n",
					       e->path_name_, i, e->pid_, comm);
				} else {
					printf("%-8s  %-8d  %-8d  %-8s\n",
					       e->path_name_, i, e->pid_, "?");
				}
			}
		}
	}
	return 0;
}

int open_run(int poll_timeout_ms, bool enable)
{
	struct Open_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct Open_ctrl ctrl = { .enable = enable };
	const int key = 0;
	int err = 0;

	skel = Open_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load Open BPF skeleton\n");
		return 1;
	}

	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Failed to set control switch: %d\n", err);
		goto cleanup;
	}

	/* 获取 comm_cache map 的 fd，作为 ctx 传入 ring buffer 回调 */
	int map_fd = bpf_map__fd(skel->maps.comm_cache);
	if (map_fd < 0) {
		fprintf(stderr, "Failed to get comm_cache map fd\n");
		err = -1;
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &map_fd, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	err = Open_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("%-8s  %-8s  %-8s  %-8s\n",
	       "FILENAME", "FD", "PID", "COMM");

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
	Open_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
