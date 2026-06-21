#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "common/cli.h"
#include "common/types.h"
#include "mutexlock.h"
#include "lock/mutexlock/skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct MutexLock_Delay_event *e = data;
	(void)ctx;
	(void)data_sz;

	printf("LOCK: 0x%-16" PRIx64 " | "
	       "OWNER: PID=%-6d PRIO=%-4d NAME=%-16s | "
	       "CONTENDER: PID=%-6d PRIO=%-4d NAME=%-16s\n",
	       e->ptr,
	       e->owner_pid, e->owner_prio, e->owner_name,
	       e->contender_pid, e->contender_prio, e->contender_name);

	return 0;
}

// 入口函数：运行「互斥锁延迟监控」
// poll_timeout_ms：ring buffer 轮询超时（毫秒）
// enable：是否启用监控（true=启动，false=关闭）
int mutexlock_run(int poll_timeout_ms, bool enable)
{
	struct mutexlock_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct MutexLock_Delay_ctrl ctrl = {.enable = enable};
	const int key = 0;
	int err = 0;

	skel = mutexlock_bpf__open_and_load();
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

	err = mutexlock_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载BPF程序失败\n");
		goto cleanup;
	}

	printf("=========================================\n");
	printf("  互斥锁延迟监控已%s！\n", enable ? "启动" : "关闭");
	printf("  按 Ctrl+C 退出\n");
	printf("=========================================\n");
	printf("LOCK_ADDR          | OWNER_PID PRIO NAME              | "
	       "CONTENDER_PID PRIO NAME\n");
	printf("-------------------------------------------------------"
	       "---------------------------------------\n");

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
	mutexlock_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
