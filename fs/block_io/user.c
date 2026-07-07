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
#include "block_io.h"
#include "fs/block_io/skel.h"

// 全局BPF骨架指针，信号处理函数需要读取内核stats统计Map
static struct block_io_bpf *g_skel = NULL;

/**
 * @brief 程序退出时读取内核stats_map，打印整机磁盘IO汇总统计面板
 * 计算并展示平均、单次最大IO耗时（单位微秒），无IO完成事件则不输出
 */
static void print_stats(void)
{
	// BPF骨架未初始化直接返回
	if (!g_skel)
		return;

	struct BlockIo_stats s = {};
	int key = 0;
	// 读取全局统计数组唯一key=0条目；读取失败或无任何IO完成事件直接返回
	if (bpf_map__lookup_elem(g_skel->maps.stats_map, &key, sizeof(key),
				 &s, sizeof(s), 0) || !s.complete_cnt)
		return;

	fprintf(stderr, "\n");
	// 彩色打印统计标题
	printf(C_CYAN C_BOLD "══════ 磁盘 IO 统计 ══════\n" C_RESET);
	// 总完成次数、平均耗时(ns转us)、单次最大耗时(ns转us)
	printf("  完成: %" PRIu64 " 次  avg=%" PRIu64 " us  max=%" PRIu64 " us\n",
	       s.complete_cnt,
	       s.total_lat_ns / (s.complete_cnt * 1000),
	       s.max_lat_ns / 1000);
	printf(C_CYAN C_BOLD "════════════════════════════\n" C_RESET);
}

/**
 * @brief SIGINT(Ctrl+C)/SIGTERM 中断信号回调
 * 捕获退出信号后先打印全局磁盘IO统计，再安全退出，避免丢失整机指标
 * @param sig 触发信号值，函数内未使用
 */
static void sig_handler(int sig) {
	(void)sig;
	print_stats();
	_exit(0);
}

/**
 * @brief 将数字RW编码转换为可读字符串标识
 * @param r 内核下发的数字类型：1=R读 2=W写 3=D丢弃 4=F刷新
 * @return 可读字符 "R"/"W"/"D"/"F"/"?"
 */
static const char *rwbs_str(int r) {
	switch(r) {
		case 1: return "R";
		case 2: return "W";
		case 3: return "D";
		case 4: return "F";
		default: return "?";
	}
}

/**
 * @brief RingBuffer事件回调函数，内核过滤出磁盘IO完成事件后自动触发
 * 格式化打印块设备号、进程PID、进程名、起始扇区、扇区数量、读写类型、IO字节、IO延迟
 * @param ctx 回调自定义上下文，未使用
 * @param data 内核下发BlockIo_event事件数据指针
 * @param data_sz 事件结构体字节大小，未使用
 * @return int 固定返回0
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct BlockIo_event *e = data;
	(void)ctx;
	(void)data_sz;

	// 打印实时IO详情面板
	LOG("DEV=%-4d PID=%-6d %-16s SECT=%-8" PRIu64 " CNT=%-4u %s %-6" PRIu64 " B | ",
	    e->dev, e->pid, e->comm, e->sector, e->nr_sectors, rwbs_str(e->rwbs), e->bytes);
	// 彩色打印IO延迟（纳秒转微秒，区分低/高延迟高亮）
	log_col_us(e->latency_ns / 1000, 100, 1000);
	printf("\n");
	return 0;
}

/**
 * @brief 磁盘块IO监控主业务入口，完整管理BPF全生命周期
 * @param poll_timeout_ms ring_buffer阻塞轮询超时毫秒
 * @param enable 下发内核的监控总开关
 * @param target_pid PID过滤，0=监控所有进程，非0仅采集该TGID进程发起的块IO
 * @param min_latency_ns IO耗时过滤阈值，低于该纳秒值不上报实时事件
 * @return int 0=正常退出，非0=异常错误码
 */
int block_io_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid, bpf_u64_t min_latency_ns)
{
	struct block_io_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	const int key = 0;
	int err = 0;

	// 1. 打开并加载BPF骨架ELF，执行内核verifier校验BPF合法性
	skel = block_io_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "打开BPF程序失败\n");
		return 1;
	}
	g_skel = skel;

	// 组装监控控制参数，写入ctrl_map下发至内核所有tracepoint追踪点
	struct BlockIo_ctrl ctrl = {
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

	// 2. 创建RingBuffer，绑定内核rb环形缓冲区与事件处理回调handle_event
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "创建RingBuffer失败\n");
		goto cleanup;
	}

	// 3. 挂载全部tracepoint：block_rq_issue / block_rq_complete
	err = block_io_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载BPF程序失败\n");
		goto cleanup;
	}

	// 打印程序启动横幅与当前过滤规则
	log_banner("磁盘 IO 监控", enable);
	if (target_pid)
		LOG("过滤 PID=%d\n", target_pid);
	// 打印实时输出表头与分隔线
	LOG_HDR("%-5s %-7s %-16s %-9s %-5s %-3s %-8s   %s",
		"DEV", "PID", "COMM", "SECTOR", "CNT", "RW", "BYTES", "LATENCY");
	LOG_SEP();

	// 4. 主循环：阻塞轮询ringbuf，持续消费内核磁盘IO完成实时事件
	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { // 被信号中断，正常退出循环
			err = 0;
			break;
		}
		if (err < 0) { // 轮询底层出错，打印后跳出循环
			fprintf(stderr, "轮询事件失败: %s\n", strerror(-err));
			break;
		}
	}

	// 循环退出，读取内核全局IO统计并打印汇总面板
	print_stats();

cleanup:
	// 统一资源释放，防止句柄、探针泄漏
	g_skel = NULL;
	ring_buffer__free(rb);                // 销毁ringbuf事件通道
	block_io_bpf__destroy(skel);         // 卸载所有块IO追踪点、销毁BPF骨架
	return err < 0 ? -err : 0;
}
