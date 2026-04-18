#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>

// 包含你定义的 共用结构体（头文件）
#include "ContextSwitch_Delay.h"

// 自动生成的 BPF 骨架头文件（make 时自动生成）
#include "perf/ContextSwitch_Delay.skel.h"

// 全局变量：控制程序退出
static volatile bool exiting = false;

// ========================
// 信号处理：Ctrl + C 退出
// ========================
static void sig_handler(int sig)
{
	exiting = true;
}

// ========================
// 回调函数：从 eBPF 读取事件并打印
// ========================
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	// 接收 eBPF 发过来的事件
	const struct ContextSwitch_Delay_event *e = data;

	printf("进程切换延迟: %-8llu us | 开始: %-10llu | 结束: %-10llu\n",
		e->delay, e->start_time, e->end_time);

	return 0;
}

int main(int argc, char **argv)
{
	struct ContextSwitch_Delay_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;

	// 设置 Ctrl+C 退出信号
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// ========================
	// 1. 加载 eBPF 程序
	// ========================
	skel = ContextSwitch_Delay_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "打开BPF程序失败\n");
		return 1;
	}

	// ========================
	// 2. 开启监控开关！
	// ========================
	struct ContextSwitch_Delay_ctrl ctrl = {
		.enable = true  // 打开监控
	};

	// 将开关配置写入 eBPF map
	err = bpf_map__update_elem(skel->maps.ctrl_map,
				   &(const int){0}, sizeof(int),
				   &ctrl, sizeof(ctrl),
				   BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "设置控制开关失败: %s\n", strerror(-err));
		goto cleanup;
	}

	// ========================
	// 3. 创建 ringbuffer 读取事件
	// ========================
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),
			     handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "创建RingBuffer失败\n");
		goto cleanup;
	}

	// ========================
	// 4. 启动 eBPF 程序
	// ========================
	err = ContextSwitch_Delay_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载BPF程序失败\n");
		goto cleanup;
	}

	printf("=========================================\n");
	printf("  进程切换延迟监控已启动！\n");
	printf("  按 Ctrl+C 退出\n");
	printf("=========================================\n");

	// ========================
	// 5. 循环读取事件
	// ========================
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "轮询事件失败: %s\n", strerror(-err));
			break;
		}
	}

// ========================
// 清理退出
// ========================
cleanup:
	ring_buffer__free(rb);
	ContextSwitch_Delay_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
