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
#include "msgqueue.h"
#include "lock/msgqueue/skel.h"

// 全局BPF骨架指针，信号处理函数需要读取内核统计Map
static struct msgqueue_bpf *g_skel = NULL;

/**
 * @brief 程序退出时读取内核stats_map，打印消息队列收发全局汇总统计报表
 */
static void print_stats(void)
{
	// BPF骨架未初始化直接返回
	if (!g_skel)
		return;
	struct Msgqueue_stats s = {};
	int key = 0;
	// 读取全局统计数组唯一key=0条目；读取失败直接返回
	if (bpf_map__lookup_elem(g_skel->maps.stats_map, &key, sizeof(key),
				 &s, sizeof(s), 0))
		return;
	// 无任何收发事件，不打印统计面板
	if (!s.send_count && !s.recv_count)
		return;

	fprintf(stderr, "\n");
	printf(C_CYAN C_BOLD "══════ 消息队列统计 ══════\n" C_RESET);
	// 打印发送汇总：总次数、平均耗时、单次最大耗时
	if (s.send_count)
		printf("  发送: %" PRIu64 " 次  avg=%" PRIu64 " ns  max=%" PRIu64 " ns\n",
		       s.send_count, s.send_total_ns / s.send_count, s.send_max_ns);
	// 打印接收汇总：总次数、平均耗时、单次最大耗时
	if (s.recv_count)
		printf("  接收: %" PRIu64 " 次  avg=%" PRIu64 " ns  max=%" PRIu64 " ns\n",
		       s.recv_count, s.recv_total_ns / s.recv_count, s.recv_max_ns);
	printf(C_CYAN C_BOLD "════════════════════════════\n" C_RESET);
}

/**
 * @brief SIGINT(Ctrl+C)/SIGTERM 信号回调，捕获中断后打印统计并安全退出
 * @param sig 触发信号值，未使用
 */
static void sig_handler(int sig)
{
	(void)sig;
	print_stats();
	_exit(0);
}

/**
 * @brief RingBuffer事件回调函数，内核推送mq收发事件后libbpf自动调用
 * @param ctx 回调自定义上下文，未使用
 * @param data 内核下发Msgqueue_event事件数据指针
 * @param data_sz 事件结构体大小，未使用
 * @return int 固定返回0
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Msgqueue_event *e = data;
	(void)ctx;
	(void)data_sz;

	// 区分SEND/RECV打印不同颜色标识
	LOG("%-4s | PID=%-6d %-16s MQDES=%-4d LEN=%-6" PRIu64 " PRIO=%-4u | ",
	    e->type == MQ_EV_SEND ? C_GREEN "SEND" C_RESET : C_YELLOW "RECV" C_RESET,
	    e->pid, e->comm, e->mqdes, e->msg_len, e->msg_prio);
	// 彩色打印系统调用延迟，区分低/高延迟
	log_col_ns(e->delay_ns, 10000, 100000);
	printf("\n");
	return 0;
}

/**
 * @brief 消息队列监控主入口函数，完整管理BPF生命周期
 * @param poll_timeout_ms ringbuf阻塞轮询超时毫秒
 * @param enable 下发内核的监控总开关
 * @param target_pid PID过滤，0=监控全部进程，非0仅采集对应TGID进程
 * @param min_delay_ns 延迟过滤阈值，mq调用耗时低于该值不上报事件
 * @return int 0正常退出，非0代表异常错误码
 */
int msgqueue_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid, bpf_u64_t min_delay_ns)
{
	struct msgqueue_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	const int key = 0;
	int err = 0;

	// 1. 打开并加载BPF骨架ELF，内核verifier校验BPF程序
	skel = msgqueue_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "打开BPF程序失败\n");
		return 1;
	}
	g_skel = skel;

	// 组装监控控制参数，写入ctrl_map下发给内核BPF
	struct Msgqueue_ctrl ctrl = {
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

	// 注册中断信号，实现Ctrl+C优雅退出、打印统计
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 2. 创建RingBuffer，绑定内核rb环形缓冲区与事件回调handle_event
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "创建RingBuffer失败\n");
		goto cleanup;
	}

	// 3. 挂载所有kprobe/kretprobe探针（do_mq_timedsend / do_mq_timedreceive）
	err = msgqueue_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载BPF程序失败\n");
		goto cleanup;
	}

	// 打印启动横幅、PID过滤提示
	log_banner("消息队列延迟监控", enable);
	if (target_pid)
		LOG("过滤 PID=%d\n", target_pid);
	// 打印输出表头与分隔线
	LOG_HDR("%-6s %-7s %-16s %-6s %-7s %-5s   %s",
		"TYPE", "PID", "COMM", "MQDES", "LEN", "PRIO", "DELAY");
	LOG_SEP();

	// 4. 主循环：阻塞轮询ringbuf，持续消费内核mq收发事件
	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { // 被信号中断，正常退出循环
			err = 0;
			break;
		}
		if (err < 0) // 轮询出现错误，跳出循环
			break;
	}

	// 循环退出，读取内核统计并打印汇总面板
	print_stats();

cleanup:
	// 统一资源释放，防止句柄泄漏
	g_skel = NULL;
	ring_buffer__free(rb);                // 销毁ringbuf事件通道
	msgqueue_bpf__destroy(skel);         // 卸载探针、销毁BPF骨架
	return err < 0 ? -err : 0;
}
