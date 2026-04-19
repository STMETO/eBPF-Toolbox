#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "app_common.h"
#include "common.h"
#include "syscall_delay.h"
#include "SystemCall_Delay.h"
#include "perf/SystemCall_Delay.skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct SystemCall_Delay_event *e = data;
	uint32_t pid = e->pid >> 32;		// 提取 PID 高 32 位
	uint32_t tid = e->pid & 0xFFFFFFFF; // 提取 TID 低 32 位
	(void)ctx;
	(void)data_sz;

	printf("PID: %-6u TID: %-6u COMM: %-16s SYSCALL: %-4u DELAY: %-8" PRIu64 " us\n",
	       pid, tid, e->comm, e->syscall_id, e->delay);

	return 0;
}

int syscall_delay_run(int poll_timeout_ms, bool enable)
{
	struct SystemCall_Delay_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct SystemCall_Delay_ctrl ctrl = {.enable = enable};
	const int key = 0;
	int err = 0;

	skel = SystemCall_Delay_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Failed to enable ctrl_map: %s\n", strerror(-err));
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	err = SystemCall_Delay_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF program\n");
		goto cleanup;
	}

	printf("系统调用延迟监控已%s！Ctrl+C 退出\n", enable ? "启动" : "关闭");
	printf("PID     TID     COMM             SYSCALL  DELAY(us)\n");
	printf("-------------------------------------------------------\n");

	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "ring_buffer poll failed: %s\n", strerror(-err));
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	SystemCall_Delay_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
