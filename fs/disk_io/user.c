/*
 * fs/disk_io/user.c — 块设备 IO 完成事件监控
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "common/cli.h"
#include "common/types.h"
#include "disk_io.h"
#include "fs/disk_io/skel.h"
#include "common/logger.h"

struct event_ctx {
	int io_map_fd;
};

static const char *rwbs_to_str(bpf_s32_t rwbs)
{
	switch (rwbs) {
	case 1: return "READ";
	case 2: return "WRITE";
	case 3: return "DISCARD";
	case 4: return "FLUSH";
	case 5: return "OTHER";
	default: return "???";
	}
}

/* PERCPU 聚合：遍历所有 CPU 分片求和得到全局真实累计 IO 次数 */
/*
 * PERCPU map 值有 8 字节对齐——内核会向上取整，所以每个 CPU 的值
 * 实际占用 value_size 向上取 8 字节。下面用 value_size 8 来分配。
 */
#define PERCPU_VAL_SIZE 8

static uint32_t get_pid_global_count(int map_fd, uint32_t pid)
{
	int n_cpus = libbpf_num_possible_cpus();
	int buf_sz = PERCPU_VAL_SIZE * n_cpus;
	uint64_t *buf = calloc(1, buf_sz);
	if (!buf)
		return 0;

	int ret = bpf_map_lookup_elem(map_fd, &pid, buf);
	if (ret != 0) {
		free(buf);
		return 0;
	}

	uint32_t sum = 0;
	for (int cpu = 0; cpu < n_cpus; cpu++)
		sum += (uint32_t)buf[cpu];

	free(buf);
	return sum;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event_ctx *ectx = (struct event_ctx *)ctx;
	(void)data_sz;
	const struct DiskIoVisit_event *e = data;

	struct tm *tm;
	char ts[32];
	time_t t = (time_t)(e->timestamp / 1000000000ULL);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	uint32_t global_count = get_pid_global_count(ectx->io_map_fd, (uint32_t)e->pid);

	printf("TIME=%-8s  DEV=%-6d  PID=%-8d  SEC=%-6d  "
	       "RW=%-8s  CURR=%-10" PRIu64 "  COUNT=%-6u  COMM=%s\n",
	       ts, e->blk_dev, e->pid, e->sectors,
	       rwbs_to_str(e->rwbs), e->curr_io, global_count, e->comm);
	return 0;
}

int disk_io_visit_run(int poll_timeout_ms, bool enable)
{
	struct disk_io_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct event_ctx ectx;
	struct DiskIoVisit_ctrl ctrl = { .enable = enable };
	const int key = 0;
	int err = 0;

	skel = disk_io_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load disk_io BPF skeleton\n");
		return 1;
	}

	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Failed to set control switch: %d\n", err);
		goto cleanup;
	}

	ectx.io_map_fd = bpf_map__fd(skel->maps.io_count_map);
	if (ectx.io_map_fd < 0) {
		fprintf(stderr, "Failed to get io_count_map fd\n");
		err = -1;
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &ectx, NULL);
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

	printf("%-12s %-8s %-10s %-8s %-10s %-12s %-8s %s\n",
	       "TIME", "DEV", "PID", "SECTORS", "RW", "CURR_IO", "COUNT", "COMM");
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
	disk_io_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
