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
#include "open.h"
#include "fs/open/skel.h"

// 全局BPF骨架指针，信号回调函数需要访问内核stats统计Map
static struct open_bpf *g_skel = NULL;

/**
 * @brief 程序退出时读取内核stats_map，打印全局open系统调用汇总统计
 * 无任何采样事件则不输出面板
 */
 static void print_stats(void)
 {
	 // BPF骨架未初始化直接返回
	 if (!g_skel)
		 return;
 
	 struct Open_stats s = {};
	 int key = 0;
	 // 先读取统计map
	 int ret = bpf_map__lookup_elem(g_skel->maps.stats_map, &key, sizeof(key),
				  &s, sizeof(s), 0);
	 // 读取失败，直接返回
	 if (ret != 0)
		 return;
	 // 读取成功，但无任何采样事件，不打印统计
	 if (!s.count)
		 return;
 
	 fprintf(stderr, "\n");
	 // 彩色打印统计标题面板
	 printf(C_CYAN C_BOLD "══════ Open 统计 ══════\n" C_RESET);
	 printf("  采样: %" PRIu64 " 次\n", s.count);
	 printf(C_CYAN C_BOLD "══════════════════════\n" C_RESET);
 }
 

/**
 * @brief SIGINT(Ctrl+C) / SIGTERM 终止信号回调函数
 * 收到退出信号先打印全局open统计，再执行_exit安全退出，避免丢失整机采样数据
 * @param sig 触发的信号值，函数内未使用
 */
static void sig_handler(int sig)
{
	(void)sig;
	print_stats();
	_exit(0);
}

/**
 * @brief RingBuffer事件回调函数，内核捕获openat事件后libbpf自动触发
 * 格式化实时打印进程PID、文件fd、进程名、打开的文件路径
 * @param ctx 回调自定义上下文，未使用
 * @param data 内核下发Open_event事件数据指针
 * @param data_sz 事件结构体字节大小，未使用
 * @return int 固定返回0
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Open_event *e = data;
	(void)ctx;
	(void)data_sz;

	// 实时打印单条open系统调用事件
	LOG("PID=%-6d FD=%-4d %-16s %s | ", e->pid, e->fd, e->comm, e->path_name_); log_col_ns(e->latency_ns, 10000, 100000); printf("\n");
	return 0;
}

/**
 * @brief 文件打开(openat)系统调用监控主入口函数，完整管理BPF全生命周期
 * @param poll_timeout_ms ring_buffer阻塞轮询超时毫秒
 * @param enable 下发至内核BPF的总开关
 * @param target_pid PID过滤，0监控全部进程，非0仅采集该TGID进程的open事件
 * @param min_delay_ns openat调用耗时过滤阈值（内核预留配置）
 * @return int 0正常退出，非0代表底层异常错误码
 */
int open_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid, bpf_u64_t min_delay_ns)
{
	struct open_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	const int key = 0;
	int err = 0;

	// 1. 打开并加载BPF骨架ELF，内核verifier校验BPF程序合法性
	skel = open_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "打开BPF程序失败\n");
		return 1;
	}
	g_skel = skel;

	// 组装监控控制参数，写入ctrl_map下发给内核tracepoint
	struct Open_ctrl ctrl = {
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

	// 注册中断信号，实现Ctrl+C优雅退出并打印统计
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 2. 创建RingBuffer，绑定内核rb环形缓冲区与事件处理回调handle_event
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "创建RingBuffer失败\n");
		goto cleanup;
	}

	// 3. 挂载sys_enter_openat / sys_exit_openat 两组tracepoint追踪点
	err = open_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载BPF程序失败\n");
		goto cleanup;
	}

	// 打印程序启动横幅与PID过滤提示
	log_banner("文件 Open 监控", enable);
	if (target_pid)
		LOG("过滤 PID=%d\n", target_pid);
	// 打印实时输出表头与分隔线
	LOG_HDR("%-7s %-5s %-16s %s", "PID", "FD", "COMM", "PATH");
	LOG_SEP();

	// 4. 主循环：阻塞轮询ringbuf，持续消费内核下发的open实时事件
	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { // 信号中断，正常退出循环
			err = 0;
			break;
		}
		if (err < 0) // 底层轮询出错，跳出循环
			break;
	}

	// 主循环退出，读取内核全局统计并打印整机open采样汇总
	print_stats();

cleanup:
	// 统一资源释放，防止探针、ringbuf、BPF句柄泄漏
	g_skel = NULL;
	ring_buffer__free(rb);                // 销毁ringbuf事件通道
	open_bpf__destroy(skel);              // 卸载所有tracepoint、销毁BPF骨架
	return err < 0 ? -err : 0;
}
