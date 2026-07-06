/*
 * fs/block_rq/user.c — 块设备 IO 请求监控
 *
 * PERCPU 聚合: handle_event 内读取 io_size_map 的所有 CPU 分片，求
 * 和得到进程全局真实累计 IO 量（GLOBAL_TOTAL），避免只显示单 CPU 局部值。
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
#include "block_rq.h"
#include "fs/block_rq/skel.h"
#include "common/logger.h"

/* 上下文：ringbuf 回调中需要访问 io_size_map fd 做 PERCPU 聚合 */
struct event_ctx {
	int io_map_fd;
};

static const char *rwbs_to_str(bpf_s32_t rwbs)
{
	switch (rwbs) {
	case 1:  return "READ";
	case 0:  return "WRITE";
	case -1: return "OTHER";
	default: return "???";
	}
}

/*
 * PERCPU 哈希查询：读取指定 PID 在所有 CPU 上的累计 IO 字节并求和。
 *
 * bpf_map_lookup_elem(fd, key, value_out) — 第 3 参数是输出缓冲区。
 * 对 PERCPU map，value_out 需要 value_size * num_cpus 字节空间。
 */
static uint64_t get_pid_global_total(int map_fd, uint32_t pid)
{
	int n_cpus = libbpf_num_possible_cpus();
	uint64_t *buf = calloc(n_cpus, sizeof(uint64_t));
	if (!buf)
		return 0;

	int ret = bpf_map_lookup_elem(map_fd, &pid, buf);
	if (ret != 0) {
		free(buf);
		return 0;
	}

	uint64_t sum = 0;
	for (int cpu = 0; cpu < n_cpus; cpu++)
		sum += buf[cpu];

	free(buf);
	return sum;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event_ctx *ectx = (struct event_ctx *)ctx;
	(void)data_sz;
	const struct BlockRqIssue_event *e = data;

	struct tm *tm;
	char ts[32];
	time_t t = (time_t)(e->timestamp / 1000000000ULL);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	uint64_t global_total = get_pid_global_total(ectx->io_map_fd, (uint32_t)e->pid);

	printf("TIME=%-8s  DEV=%-6d  SECTOR=%-8d  NR_SEC=%-6d  "
	       "RW=%-6s  CURR=%-10" PRIu64 "  TOTAL=%-12" PRIu64 "  COMM=%s\n",
	       ts, e->dev, e->sector, e->nr_sectors,
	       rwbs_to_str(e->rwbs), e->curr_io, global_total, e->comm);
	return 0;
}

int block_rq_issue_run(int poll_timeout_ms, bool enable)
{
	struct block_rq_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct event_ctx ectx;
	struct BlockRqIssue_ctrl ctrl = { .enable = enable };
	const int key = 0;
	int err = 0;

	skel = block_rq_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load block_rq BPF skeleton\n");
		return 1;
	}

	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Failed to set control switch: %d\n", err);
		goto cleanup;
	}

	ectx.io_map_fd = bpf_map__fd(skel->maps.io_size_map);
	if (ectx.io_map_fd < 0) {
		fprintf(stderr, "Failed to get io_size_map fd\n");
		err = -1;
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &ectx, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	err = block_rq_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("%-12s %-8s %-10s %-8s %-8s %-12s %-14s %s\n",
	       "TIME", "DEV", "SECTOR", "NR_SEC", "RW", "CURR_IO", "TOTAL_IO", "COMM");
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
	block_rq_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
