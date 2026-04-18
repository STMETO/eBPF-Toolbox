#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <bpf/libbpf.h>

#include "common.h"
#include "SystemCall_Delay.h"
#include "perf/SystemCall_Delay.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct SystemCall_Delay_event *e = data;
	uint32_t pid = e->pid >> 32;
	uint32_t tid = e->pid & 0xFFFFFFFF;

	printf("PID: %-6d TID: %-6d COMM: %-16s SYSCALL: %-4u DELAY: %-8lu us\n",
	       pid,
	       tid,
	       e->comm,
	       e->syscall_id,
	       e->delay);

	return 0;
}

int main(int argc, char **argv)
{
	struct SystemCall_Delay_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;
	int key = 0;
	struct SystemCall_Delay_ctrl ctrl = {.enable = 1};

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = SystemCall_Delay_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = bpf_map__update_elem(skel->maps.ctrl_map,
				     &key, sizeof(key),
				     &ctrl, sizeof(ctrl),
				     BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Failed to enable ctrl_map: %s\n", strerror(-err));
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),
			      handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	err = SystemCall_Delay_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF program\n");
		goto cleanup;
	}

	printf("系统调用延迟监控已启动！Ctrl+C 退出\n");
	printf("PID     TID     COMM             SYSCALL  DELAY(us)\n");
	printf("-------------------------------------------------------\n");

	while (!exiting) {
		ring_buffer__poll(rb, 100);
	}

cleanup:
	ring_buffer__free(rb);
	SystemCall_Delay_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
