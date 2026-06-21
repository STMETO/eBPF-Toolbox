/*
 * fs/open/user.c — openat 监控用户态运行器
 *
 * 改进点：
 *   1. 进程名由内核态 bpf_get_current_comm 直接获取，不在用户态查询
 *   2. fd 由出口 tracepoint 的返回值直接获取，不再遍历 /proc/pid/fd/*
 *   3. 删除了 comm_cache map 和 ctx 指针传递，回调逻辑大幅简化
 *   4. 输出每个字段带类型标签，便于阅读和解析
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "common/cli.h"
#include "common/types.h"
#include "open.h"
#include "fs/open/skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	(void)ctx;
	(void)data_sz;

	const struct Open_event *e = data;

	/* 每条输出字段带类型标签：PID=<数值> PATH=<字符串> FD=<数值> COMM=<字符串> */
	printf("PID=%-8d  PATH=%-48s  FD=%-4d  COMM=%-16s\n",
	       e->pid, e->path_name_, e->fd, e->comm);
	return 0;
}

int open_run(int poll_timeout_ms, bool enable)
{
	struct open_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct Open_ctrl ctrl = { .enable = enable };
	const int key = 0;
	int err = 0;

	/* 1. 加载 BPF 字节码到内核 */
	skel = open_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load Open BPF skeleton\n");
		return 1;
	}

	/* 2. 写入采集开关 */
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Failed to set control switch: %d\n", err);
		goto cleanup;
	}

	/* 3. 创建 RingBuffer（不再需要传入 ctx，进程名已在 BPF 端获取） */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* 4. 挂载双探针：sys_enter_openat + sys_exit_openat */
	err = open_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("%-12s %-50s %-8s %-18s\n",
	       "PID", "PATH", "FD", "COMM");
	printf("------------------------------------------------------------------------------------------\n");

	/* 5. 轮询事件 */
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
	open_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
