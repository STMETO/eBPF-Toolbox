/*
 * fs/write/user.c — write 系统调用监控用户态运行器
 */

#include <errno.h>
#include <stdio.h>
#include <time.h>

#include <bpf/libbpf.h>

#include "common/cli.h"
#include "common/types.h"
#include "write.h"
#include "fs/write/skel.h"
#include "common/logger.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	(void)ctx;
	(void)data_sz;

	const struct Write_event *e = data;

	struct tm *tm;
	char ts[32];
	time_t t = (time_t)(e->timestamp_ns / 1000000000ULL);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	/* 每个字段带类型标签，real_count 为 -1 表示写失败 */
	printf("TIME=%-8s  PID=%-8d  FD=%-4d  REQ=%-8lld  ACTUAL=%-8lld  COMM=%-16s  PATH=%s\n",
	       ts, e->pid, e->fd,
	       (long long)e->count, (long long)e->real_count, e->comm,
	       e->path_name_[0] ? e->path_name_ : "(unknown)");
	return 0;
}

int write_run(int poll_timeout_ms, bool enable,
		    bpf_s32_t target_pid, bpf_u64_t min_delay_ns)
{
	struct write_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct Write_ctrl ctrl = { .enable = enable };
	const int key = 0;
	int err = 0;

	skel = write_bpf__open_and_load();
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

	err = write_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("%-12s %-10s %-6s %-12s %-12s %-18s %s\n",
	       "TIME", "PID", "FD", "REQ(COUNT)", "ACTUAL(RET)", "COMM", "PATH");
	printf("-------------------------------------------------------------------------------------\n");

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
	write_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
