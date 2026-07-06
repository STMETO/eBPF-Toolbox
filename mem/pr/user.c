#include <errno.h>
#include <stdio.h>
#include <bpf/libbpf.h>
#include "common/cli.h"       
#include "common/types.h"     
#include "pr.h"                
#include "pr.h"               
#include "mem/pr/skel.h"      

/**
 * @brief RingBuffer事件回调函数，内核推送页面回收事件时自动触发
 * @param ctx 自定义上下文，当前代码未使用
 * @param data 内核下发的Pr_event页面回收事件数据指针
 * @param data_sz 事件数据长度，本代码未做长度合法性校验
 * @return int 回调处理返回值，0代表正常处理
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Pr_event *e = data;
	// 消除未使用参数编译警告
	(void)ctx; (void)data_sz;

	// 格式化打印本次回收指标：计划回收页数、实际回收页数、未排队脏页、拥塞计数、回写页面数
	printf("%-8lu %-8lu %-8u %-8u %-8u\n",
	       e->reclaim, e->reclaimed, e->unqueued_dirty, e->congested, e->writeback);
	return 0;
}

/**
 * @brief 页面回收监控工具主运行入口
 * @param poll_timeout_ms 环形缓冲区阻塞读取超时时间，单位ms
 * @param enable 采集总开关，true加载启动BPF探针，false关闭采集
 * @return int 0正常退出，正数为执行失败错误码
 */
int pr_run(int poll_timeout_ms, bool enable)
{
	struct pr_bpf *skel = NULL;         // BPF骨架句柄，统一管理BPF程序与所有Map
	struct ring_buffer *rb = NULL;      // libbpf环形缓冲区管理句柄，接收内核流式事件
	struct Pr_ctrl ctrl = { .enable = enable }; // 下发至内核的采集开关配置
	const int key = 0;                   // ctrl_map数组MAP固定下标key
	int err = 0;

	// 1. 打开BPF字节码并加载到内核，自动初始化所有BPF Map资源
	skel = pr_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open Pr BPF skeleton\n");
		return 1;
	}

	// 2. 将启停开关写入内核ctrl_map，控制探针是否采集页面回收事件
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key), &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Failed to set control: %d\n", err);
		goto cleanup;
	}

	// 3. 绑定内核rb环形缓冲区fd，创建RingBuffer实例并注册事件回调
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	// 4. 将kprobe探针挂载到内核shrink_page_list页面回收函数
	err = pr_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach: %d\n", err);
		goto cleanup;
	}

	// 打印输出表头，对应各项回收指标含义
	printf("%-8s %-8s %-8s %-8s %-8s\n", "RECLAIM", "RECLAIMED", "UNQUEUE", "CONGESTED", "WRITEBACK");

	// 主循环：阻塞等待内核推送页面回收事件，直到收到Ctrl+C退出信号
	while (!app_should_exit()) {
		// 阻塞读取环形缓冲区，超时时间由入参poll_timeout_ms控制
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { // 收到中断信号，视为正常退出流程
			err = 0;
			break;
		}
		if (err < 0) { // 缓冲区读取发生异常，终止监控
			fprintf(stderr, "Poll error: %d\n", err);
			break;
		}
	}

cleanup:
	// 逆序释放资源：先销毁环形缓冲区，再销毁BPF骨架，防止资源泄漏
	ring_buffer__free(rb);
	pr_bpf__destroy(skel);
	// 负数错误码转正后统一返回，无错误返回0
	return err < 0 ? -err : 0;
}
