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
#include "read.h"
#include "fs/read/skel.h"

// 全局BPF骨架指针，信号回调函数需要访问内核stats统计Map
static struct read_bpf *g_skel = NULL;

/**
 * @brief 程序退出时读取内核stats_map，打印整机read系统调用汇总统计面板
 * 原代码存在读取与判断耦合问题，此处保留原逻辑并标注隐患，推荐拆分写法
 * 无任何read采样事件或map读取失败时，不输出统计面板
 */
static void print_stats(void)
{
	// BPF骨架未初始化直接返回
	if (!g_skel)
		return;

	struct Read_stats s = {};
	int key = 0;
	// 读取全局统计数组唯一key=0条目
	// 隐患：短路或运算，读取失败不会访问s.count，但可读性差，易引入后续bug
	if (bpf_map__lookup_elem(g_skel->maps.stats_map, &key, sizeof(key),
				 &s, sizeof(s), 0) || !s.count)
		return;

	fprintf(stderr, "\n");
	// 彩色打印统计标题
	printf(C_CYAN C_BOLD "══════ Read 统计 ══════\n" C_RESET);
	printf("  采样: %" PRIu64 " 次\n", s.count);
	printf(C_CYAN C_BOLD "══════════════════════\n" C_RESET);
}

/**
 * @brief SIGINT(Ctrl+C)/SIGTERM 终止信号回调函数
 * 捕获退出信号后先打印全局read IO统计，再安全退出，不丢失整机采样指标
 * @param sig 触发信号值，函数内未使用
 */
static void sig_handler(int sig) {
	(void)sig;
	print_stats();
	_exit(0);
}

/**
 * @brief RingBuffer事件回调，内核捕获read系统调用完成后libbpf自动触发
 * 格式化打印进程PID、文件fd、实际读取字节、进程名、文件路径
 * 若fd反查路径失败，则展示"(unknown)"占位
 * @param ctx 回调自定义上下文，未使用
 * @param data 内核下发Read_event事件数据指针
 * @param data_sz 事件结构体字节大小，未使用
 * @return int 固定返回0
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Read_event *e = data;
	(void)ctx;
	(void)data_sz;

	// 打印单条read IO事件，路径为空时显示unknown
	return 0;
	LOG("PID=%-6d FD=%-4d BYTES=%-8lld %-16s %s | ", e->pid, e->fd, (long long)e->bytes_read, e->comm, e->path_name_[0] ? e->path_name_ : "(unknown)"); log_col_ns(e->latency_ns, 10000, 100000); printf("\n");
}

/**
 * @brief 文件read系统调用监控主入口，完整管理BPF全生命周期
 * @param poll_timeout_ms ring_buffer阻塞轮询超时毫秒
 * @param enable 下发内核BPF的监控总开关
 * @param target_pid PID过滤，0=监控所有进程，非0仅采集该TGID进程的read IO
 * @param min_delay_ns read调用耗时过滤阈值（内核预留配置字段）
 * @return int 0=正常退出，非0=底层异常错误码
 */
int read_run(int poll_timeout_ms, bool enable,
	     bpf_s32_t target_pid, bpf_u64_t min_delay_ns)
{
	struct read_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	const int key = 0;
	int err = 0;

	// 1. 打开并加载BPF骨架ELF，内核verifier校验BPF程序合法性
	skel = read_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "打开BPF程序失败\n");
		return 1;
	}
	g_skel = skel;

	// 组装监控控制参数，写入ctrl_map下发至内核sys_enter/sys_exit追踪点
	struct Read_ctrl ctrl = {
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

	// 注册中断信号，实现Ctrl+C优雅退出、打印全局read统计
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 2. 创建RingBuffer，绑定内核rb环形缓冲区与事件处理回调handle_event
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "创建RingBuffer失败\n");
		goto cleanup;
	}

	// 3. 挂载成对tracepoint：sys_enter_read / sys_exit_read
	err = read_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载BPF程序失败\n");
		goto cleanup;
	}

	// 打印程序启动横幅与PID过滤提示
	log_banner("文件 Read 监控", enable);
	if (target_pid)
		LOG("过滤 PID=%d\n", target_pid);
	// 打印实时输出表头与分隔线
	LOG_HDR("%-7s %-5s %-9s %-16s   %s",
		"PID", "FD", "BYTES", "COMM", "PATH");
	LOG_SEP();

	// 4. 主循环：阻塞轮询ringbuf，持续消费内核下发的read IO实时事件
	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { // 信号中断，正常退出循环
			err = 0;
			break;
		}
		if (err < 0) // 底层轮询出错，跳出循环
			break;
	}

	// 主循环退出，读取内核全局read采样统计并打印汇总面板
	print_stats();

cleanup:
	// 统一资源释放，防止探针、ringbuf、BPF句柄泄漏
	g_skel = NULL;
	ring_buffer__free(rb);                // 销毁ringbuf事件通道
	read_bpf__destroy(skel);             // 卸载read成对tracepoint、销毁BPF骨架
	return err < 0 ? -err : 0;
}
