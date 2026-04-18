#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "app_common.h"
#include "common.h"
#include "ContextSwitch_Delay.h"
#include "context_switch_delay.h"
#include "perf/ContextSwitch_Delay.skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct ContextSwitch_Delay_event *e = data;
	(void)ctx;
	(void)data_sz;

	printf("进程切换延迟: %-8" PRIu64 " us | 开始: %-10" PRIu64 " | 结束: %-10" PRIu64 "\n",
	       e->delay, e->start_time, e->end_time);

	return 0;
}

int context_switch_delay_run(int poll_timeout_ms, bool enable)
{
	struct ContextSwitch_Delay_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct ContextSwitch_Delay_ctrl ctrl = {.enable = enable};
	const int key = 0;
	int err = 0;

	skel = ContextSwitch_Delay_bpf__open_and_load();
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

	err = ContextSwitch_Delay_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载BPF程序失败\n");
		goto cleanup;
	}

	printf("=========================================\n");
	printf("  进程切换延迟监控已%s！\n", enable ? "启动" : "关闭");
	printf("  按 Ctrl+C 退出\n");
	printf("=========================================\n");

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
	ContextSwitch_Delay_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
