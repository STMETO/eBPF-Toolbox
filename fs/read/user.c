/*
 * fs/read/user.c — read 系统调用监控用户态运行器
 *
 * 改进点（相比旧版 kprobe/vfs_read）：
 *   1. tracepoint 替代 kprobe — 内核稳定接口
 *   2. 事件包含完整信息 — 不再需要用户态查表获取文件名
 *   3. 输出每个字段带类型标签
 */

#include <errno.h>
#include <stdio.h>
#include <time.h>

#include <bpf/libbpf.h>

#include "common/cli.h"
#include "common/types.h"
#include "read.h"
#include "fs/read/skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	(void)ctx;
	(void)data_sz;

	const struct Read_event *e = data;

	/* 格式化时间戳 */
	struct tm *tm;
	char ts[32];
	time_t t = (time_t)(e->timestamp_ns / 1000000000ULL);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	/* 每个字段带类型标签 */
	printf("TIME=%-8s  PID=%-8d  FD=%-4d  BYTES=%-8lld  COMM=%-16s  PATH=%s\n",
	       ts, e->pid, e->fd, (long long)e->bytes_read, e->comm,
	       e->path_name_[0] ? e->path_name_ : "(unknown)");
	return 0;
}

int read_run(int poll_timeout_ms, bool enable)
{
	struct read_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct Read_ctrl ctrl = { .enable = enable };
	const int key = 0;
	int err = 0;

	skel = read_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load Read BPF skeleton\n");
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

	err = read_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("%-12s %-10s %-6s %-12s %-18s %s\n",
	       "TIME", "PID", "FD", "BYTES", "COMM", "PATH");
	printf("--------------------------------------------------------------------------------\n");

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
