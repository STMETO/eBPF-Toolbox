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
#include "write.h"
#include "fs/write/skel.h"

// 全局BPF骨架指针，信号回调函数需要访问内核stats统计Map
static struct write_bpf *g_skel = NULL;

/**
 * @brief 程序退出时读取内核全局统计map，打印文件write系统调用汇总报表
 * 逻辑隐患说明：使用 || 短路运算耦合读取判断与计数判断，可读性差，建议拆分为分步判断
 * 仅读取成功且存在采样事件时才输出统计面板，否则直接返回
 */
static void print_stats(void)
{
	// BPF骨架未初始化，无法访问内核map，直接返回
	if (!g_skel)
		return;

	struct Write_stats s = {};
	int key = 0;
	// 读取全局统计数组唯一key=0条目
	// 逻辑隐患：若bpf_map__lookup_elem读取失败，s为栈脏数据，仅靠短路规避访问s.count，维护风险高
	if (bpf_map__lookup_elem(g_skel->maps.stats_map, &key, sizeof(key),
				 &s, sizeof(s), 0) || !s.count)
		return;

	fprintf(stderr, "\n");
	// 彩色打印统计标题面板
	printf(C_CYAN C_BOLD "══════ Write 统计 ══════\n" C_RESET);
	printf("  采样: %" PRIu64 " 次\n", s.count);
	printf(C_CYAN C_BOLD "══════════════════════\n" C_RESET);
}

/**
 * @brief SIGINT(Ctrl+C) / SIGTERM 终止信号回调函数
 * 捕获退出信号后先打印整机write IO统计，再执行_exit安全退出，避免丢失采样指标
 * @param sig 触发的信号值，函数内未使用
 */
static void sig_handler(int sig) {
	(void)sig;
	print_stats();
	_exit(0);
}

/**
 * @brief RingBuffer事件回调函数，内核捕获write系统调用完成事件后libbpf自动触发
 * 格式化打印：进程PID、文件fd、请求写入字节、实际写入字节、进程名、文件路径
 * fd反向解析路径失败时显示占位符 (unknown)
 * @param ctx 回调自定义上下文，未使用
 * @param data 内核下发Write_event事件数据指针
 * @param data_sz 事件结构体字节大小，未使用
 * @return int 固定返回0
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Write_event *e = data;
	(void)ctx;
	(void)data_sz;

	// 实时打印单条write系统调用IO事件
	LOG("PID=%-6d FD=%-4d REQ=%-8lld ACTUAL=%-8lld %-16s %s\n",
	    e->pid, e->fd, (long long)e->count, (long long)e->real_count,
	    e->comm, e->path_name_[0] ? e->path_name_ : "(unknown)");
	return 0;
}

/**
 * @brief 文件write系统调用监控主入口函数，完整管理BPF全生命周期
 * @param poll_timeout_ms ring_buffer阻塞轮询超时毫秒
 * @param enable 下发至内核BPF的采集总开关
 * @param target_pid PID过滤，0监控全部进程，非0仅采集该TGID进程发起的write调用
 * @param min_delay_ns write调用耗时过滤阈值（内核配置预留字段）
 * @return int 0=正常退出，非0=底层IO/加载异常错误码
 */
int write_run(int poll_timeout_ms, bool enable,
	      bpf_s32_t target_pid, bpf_u64_t min_delay_ns)
{
	struct write_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	const int key = 0;
	int err = 0;

	// 1. 打开并加载BPF骨架ELF，内核verifier校验BPF程序合法性
	skel = write_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "打开BPF程序失败\n");
		return 1;
	}
	g_skel = skel;

	// 组装监控控制参数，写入ctrl_map下发给内核成对tracepoint
	struct Write_ctrl ctrl = {
		.enable = enable,
		.min_delay_ns = min_delay_ns,
		.target_pid = target_pid
	};
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "设置控制开关失败\n");
		goto cleanup;
	}

	// 注册终止信号，实现Ctrl+C优雅退出并打印全局write统计
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 2. 创建RingBuffer，绑定内核rb环形缓冲区与事件处理回调handle_event
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "创建RingBuffer失败\n");
		goto cleanup;
	}

	// 3. 挂载sys_enter_write / sys_exit_write 两组系统调用追踪点
	err = write_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载BPF程序失败\n");
		goto cleanup;
	}

	// 打印程序启动横幅与当前PID过滤规则
	log_banner("文件 Write 监控", enable);
	if (target_pid)
		LOG("过滤 PID=%d\n", target_pid);
	// 打印实时输出表头与分隔线
	LOG_HDR("%-7s %-5s %-9s %-9s %-16s   %s",
		"PID", "FD", "REQ", "ACTUAL", "COMM", "PATH");
	LOG_SEP();

	// 4. 主循环：阻塞轮询ringbuf，持续消费内核下发的write实时IO事件
	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { // 信号中断，正常退出循环
			err = 0;
			break;
		}
		if (err < 0) // 底层轮询出错，跳出循环
			break;
	}

	// 主循环退出，读取内核全局write统计并打印汇总面板
	print_stats();

cleanup:
	// 统一资源释放，防止BPF探针、ringbuf句柄泄漏
	g_skel = NULL;
	ring_buffer__free(rb);                // 销毁ringbuf事件通道
	write_bpf__destroy(skel);             // 卸载所有write系统调用追踪点、销毁BPF骨架
	return err < 0 ? -err : 0;
}
