#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "common/cli.h"
#include "common/types.h"
#include "common/logger.h"
#include "syscall.h"
#include "lock/syscall/skel.h"

// 全局BPF骨架指针，信号退出函数需要读取内核统计Map
static struct syscall_bpf *g_skel = NULL;

/**
 * @brief 程序退出时读取内核stats_map，打印整机系统调用汇总统计报表
 * 输出总采样次数、平均调用耗时、单次最大耗时及对应进程、系统调用号
 */
static void print_stats(void)
{
	// BPF骨架未初始化直接返回
	if (!g_skel)
		return;

	struct Syscall_stats s = {};
	int key = 0;
	// 读取全局统计数组唯一key=0条目；读取失败或无任何采样事件直接返回
	if (bpf_map__lookup_elem(g_skel->maps.stats_map, &key, sizeof(key),
				 &s, sizeof(s), 0) || s.count == 0)
		return;

	fprintf(stderr, "\n");
	// 彩色打印统计标题面板
	printf(C_CYAN C_BOLD "══════ 系统调用统计 ══════\n" C_RESET);
	printf("  采样: %" PRIu64 " 次  avg=%" PRIu64 " us\n",
	       s.count, s.total_ns / s.count);
	printf("  最大: %" PRIu64 " us  PID=%d(%s)  syscall=%d\n",
	       s.max_ns, s.max_pid, s.max_comm, s.max_syscall_id);
	printf(C_CYAN C_BOLD "════════════════════════════\n" C_RESET);
}

/**
 * @brief SIGINT(Ctrl+C)/SIGTERM 信号回调函数
 * 捕获中断信号，先打印全局系统调用统计再安全退出，避免丢失汇总数据
 * @param sig 触发的信号值，函数内未使用
 */
static void sig_handler(int sig) {
	(void)sig;
	print_stats();
	_exit(0);
}

/**
 * @brief RingBuffer事件回调函数，内核过滤出系统调用事件后libbpf自动调用
 * 格式化实时打印进程PID、线程TID、进程名、系统调用号、调用耗时
 * @param ctx 回调自定义上下文，未使用
 * @param data 内核下发的Syscall_event事件数据指针
 * @param data_sz 事件结构体字节大小，未使用
 * @return int 固定返回0
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Syscall_event *e = data;
	(void)ctx;
	(void)data_sz;

	// 打印PID、线程ID、进程名、系统调用号
	LOG("%-5d %-5d %-16s %-4d | ", e->pid, e->tid, e->comm, e->syscall_id);
	    
	// 彩色打印系统调用耗时，区分低延迟/高延迟高亮
	log_col_us(e->delay_ns, 100, 1000);
	printf("\n");
	return 0;
}

/**
 * @brief 系统调用延迟监控主业务入口函数，完整管理BPF全生命周期
 * @param poll_timeout_ms ring_buffer阻塞轮询超时毫秒
 * @param enable 下发给内核BPF的监控总开关
 * @param target_pid PID过滤，0=监控全部进程，非0仅采集对应TGID进程
 * @param min_latency_ns 系统调用耗时过滤阈值，低于该纳秒值不上报事件
 * @return int 0=正常退出，非0代表异常错误码
 */
int syscall_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid, bpf_u64_t min_latency_ns)
{
	struct syscall_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	const int key = 0;
	int err = 0;

	// 1. 打开并加载BPF骨架ELF，内核verifier校验BPF程序合法性
	skel = syscall_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "打开BPF程序失败\n");
		return 1;
	}
	g_skel = skel;

	// 组装监控控制参数，写入ctrl_map下发至内核所有tracepoint探针
	struct Syscall_ctrl ctrl = {
		.enable = enable,
		.min_latency_ns = min_latency_ns,
		.target_pid = target_pid
	};
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "设置控制开关失败: %s\n", strerror(-err));
		goto cleanup;
	}

	// 注册中断信号，实现Ctrl+C优雅退出并打印统计
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 2. 创建RingBuffer，绑定内核rb环形缓冲区与事件回调handle_event
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "创建RingBuffer失败\n");
		goto cleanup;
	}

	// 3. 挂载tracepoint/raw_syscalls/sys_enter、sys_exit追踪点
	err = syscall_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载BPF程序失败\n");
		goto cleanup;
	}

	// 打印程序启动横幅、当前PID过滤提示
	log_banner("系统调用延迟监控", enable);
	if (target_pid)
		LOG("过滤 PID=%d\n", target_pid);
	// 打印实时输出表头与分隔线
	LOG_HDR("%-5s %-5s %-16s %-4s   %s",
		"PID", "TID", "COMM", "SYSCALL", "DELAY");
	LOG_SEP();

	// 4. 主循环：阻塞轮询ringbuf，持续消费内核下发的系统调用事件
	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { // 被信号中断，正常退出循环
			err = 0;
			break;
		}
		if (err < 0) { // 轮询底层出错，打印错误并跳出循环
			fprintf(stderr, "轮询事件失败: %s\n", strerror(-err));
			break;
		}
	}

	// 主循环退出，读取内核全局统计并打印汇总面板
	print_stats();

cleanup:
	// 统一资源释放，防止句柄、探针泄漏
	g_skel = NULL;
	ring_buffer__free(rb);                // 销毁ringbuf事件通道
	syscall_bpf__destroy(skel);           // 卸载tracepoint、销毁BPF骨架
	return err < 0 ? -err : 0;
}
