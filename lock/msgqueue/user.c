#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "common/cli.h"
#include "common/types.h"
#include "msgqueue.h"
#include "lock/msgqueue/skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct MsgQueue_Delay_event *e = data;
	(void)ctx;
	(void)data_sz;

	/* 计算各阶段延迟 */
	uint64_t send_delay = e->send_exit_time - e->send_enter_time;
	uint64_t rcv_delay  = e->rcv_exit_time  - e->rcv_enter_time;
	uint64_t total_delay = e->rcv_exit_time - e->send_enter_time;

	printf("SEND_PID: %-6d RCV_PID: %-6d MQDES: %-4d "
	       "MSG_LEN: %-6" PRIu64 " PRIO: %-4u | "
	       "SEND: %-8" PRIu64 " ns "
	       "RCV: %-8" PRIu64 " ns "
	       "TOTAL: %-8" PRIu64 " ns\n",
	       e->send_pid, e->rcv_pid, e->mqdes,
	       e->msg_len, e->msg_prio,
	       send_delay, rcv_delay, total_delay);

	return 0;
}

// 入口函数：运行「消息队列延迟监控」
// poll_timeout_ms：ring buffer 轮询超时（毫秒）
// enable：是否启用监控（true=启动，false=关闭）
int msgqueue_run(int poll_timeout_ms, bool enable)
{
	// BPF 程序骨架（自动生成的结构体）
	struct msgqueue_bpf *skel = NULL;
	// 环形缓冲区：内核 → 用户态 传递事件
	struct ring_buffer *rb = NULL;
	// 控制结构体：存储 enable 开关，传给 eBPF
	struct MsgQueue_Delay_ctrl ctrl = {.enable = enable};
	// BPF map 的 key 固定为 0
	const int key = 0;
	// 错误码
	int err = 0;

	// 打开并加载 BPF 程序（自动生成的 API）
	skel = msgqueue_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "打开BPF程序失败\n");
		return 1;
	}

	// 更新 ctrl_map，告诉内核是否开启监控
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "设置控制开关失败: %s\n", strerror(-err));
		goto cleanup;
	}

	// 创建 ring buffer，用于内核发送事件给用户态
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "创建RingBuffer失败\n");
		goto cleanup;
	}

	// 把 BPF 程序挂载到内核钩子点
	err = msgqueue_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载BPF程序失败\n");
		goto cleanup;
	}

	printf("=========================================\n");
	printf("  消息队列延迟监控已%s！\n", enable ? "启动" : "关闭");
	printf("  按 Ctrl+C 退出\n");
	printf("=========================================\n");
	printf("SEND_PID RCV_PID MQDES MSG_LEN PRIO | "
	       "SEND_DELAY(ns) RCV_DELAY(ns) TOTAL_DELAY(ns)\n");
	printf("-------------------------------------------------------"
	       "---------------------------------------\n");

	// 循环：检查是否收到退出信号（Ctrl+C）
	while (!app_should_exit()) {
		// 轮询 ring buffer，超时时间 poll_timeout_ms
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
	ring_buffer__free(rb);                   // 释放环形缓冲区
	msgqueue_bpf__destroy(skel);       // 卸载 BPF 程序
	return err < 0 ? -err : 0;              // 返回错误码（转正数）
}
