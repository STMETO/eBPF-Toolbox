#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "common/cli.h"
#include "common/types.h"
#include "preempt.h"
#include "sched/preempt/skel.h"
#include "common/logger.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Preempt_Delay_event *e = data;
	(void)ctx;
	(void)data_sz;

	LOG("PREV_PID: %-6d NEXT_PID: %-6d COMM: %-16s | DURATION: %-8" PRIu64 " ns",
	    e->prev_pid, e->next_pid, e->comm, e->duration);

	return 0;
}

int preempt_run(int poll_timeout_ms, bool enable)
{
	struct preempt_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct Preempt_Delay_ctrl ctrl = {.enable = enable};
	const int key = 0;
	int err = 0;

	skel = preempt_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "打开BPF程序失败\n");
		return 1;
	}

	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "设置控制开关失败: %s\n", strerror(-err));
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "创建RingBuffer失败\n");
		goto cleanup;
	}

	err = preempt_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载BPF程序失败\n");
		goto cleanup;
	}

	log_banner("抢占延迟监控", enable);
	LOG_HDR("%-8s %-8s %-16s %-13s", "PREV_PID", "NEXT_PID", "COMM", "DURATION");
	LOG_SEP();

	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "轮询事件失败: %s\n", strerror(-err));
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	preempt_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
