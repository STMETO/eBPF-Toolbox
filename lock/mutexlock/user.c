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
#include "mutexlock.h"
#include "lock/mutexlock/skel.h"

// 全局BPF骨架指针，信号退出函数需要读取内核统计map
static struct mutexlock_bpf *g_skel = NULL;

/**
 * @brief 程序退出时读取内核stats_map，打印整机互斥锁竞争汇总统计
 * 仅存在竞争事件时才输出面板，无竞争不打印
 */
static void print_stats(void)
{
	// BPF骨架未初始化直接返回
	if (!g_skel)
		return;

	struct Mutexlock_stats s = {};
	int key = 0;
	// 读取全局统计数组唯一条目；读取失败 或 无任何锁竞争事件直接返回
	if (bpf_map__lookup_elem(g_skel->maps.stats_map, &key, sizeof(key),
				 &s, sizeof(s), 0) || !s.contention_count)
		return;

	fprintf(stderr, "\n");
	// 彩色打印统计表头
	printf(C_CYAN C_BOLD "══════ 互斥锁统计 ══════\n" C_RESET);
	printf("  竞争: %" PRIu64 " 次\n", s.contention_count);
	printf(C_CYAN C_BOLD "════════════════════════════\n" C_RESET);
}

/**
 * @brief SIGINT(Ctrl+C)/SIGTERM 信号捕获回调
 * 收到终止信号后先打印全局锁竞争统计，再安全退出程序，不丢失汇总指标
 * @param sig 触发的信号值，函数内未使用
 */
static void sig_handler(int sig)
{
	(void)sig;
	print_stats();
	_exit(0);
}

/**
 * @brief RingBuffer事件回调函数，内核捕获锁竞争后自动触发执行
 * 格式化打印锁地址、持有者进程、竞争阻塞进程及双方调度优先级
 * @param ctx 回调自定义上下文，未使用
 * @param data 内核下发的Mutexlock_event事件数据指针
 * @param data_sz 事件结构体字节大小，未使用
 * @return int 固定返回0
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Mutexlock_event *e = data;
	(void)ctx;
	(void)data_sz;

	// 打印锁内核地址、持有锁进程信息、红色标记阻塞竞争进程
	LOG("LOCK=0x%-16" PRIx64 " | OWNER: PID=%-6d %-16s PRIO=%-4d | "
	    C_RED "CONTENDER" C_RESET ": PID=%-6d %-16s PRIO=%-4d | WAIT: ",
	    e->ptr, e->owner_pid, e->owner_name, e->owner_prio,
	    e->contender_pid, e->contender_name, e->contender_prio);
	log_col_ns(e->contention_ns, 100000, 1000000); printf("\n");
	return 0;
}

/**
 * @brief 互斥锁竞争监控主业务入口，完整管理BPF全生命周期
 * @param poll_timeout_ms ring_buffer轮询阻塞超时时间(毫秒)
 * @param enable 下发给内核BPF的监控总开关
 * @param target_pid PID过滤，0=监控所有进程，非0仅采集该TGID进程产生的锁竞争
 * @param min_delay_ns 锁持有时长过滤阈值（当前内核逻辑预留未使用）
 * @return int 0=正常退出，非0=异常错误码
 */
int mutexlock_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid, bpf_u64_t min_delay_ns)
{
	struct mutexlock_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	const int key = 0;
	int err = 0;

	// 1. 打开并加载BPF骨架ELF，内核verifier校验BPF程序合法性
	skel = mutexlock_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "打开BPF程序失败\n");
		return 1;
	}
	g_skel = skel;

	// 组装监控控制参数，写入ctrl_map下发至内核所有探针
	struct Mutexlock_ctrl ctrl = {
		.enable = enable,
		.min_delay_ns = min_delay_ns,
		.target_pid = target_pid
	};
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "设置控制开关失败: %s\n", strerror(-err));
		goto cleanup;
	}

	// 注册中断信号捕获，实现Ctrl+C优雅退出并打印统计
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 2. 创建RingBuffer，绑定内核rb环形缓冲区与事件处理回调
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "创建RingBuffer失败\n");
		goto cleanup;
	}

	// 3. 挂载全部kprobe探针：mutex_lock / mutex_unlock / __mutex_lock_slowpath
	err = mutexlock_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载BPF程序失败\n");
		goto cleanup;
	}

	// 打印程序启动横幅与当前PID过滤规则
	log_banner("互斥锁竞争监控", enable);
	if (target_pid)
		LOG("过滤 PID=%d\n", target_pid);

	// 打印实时事件输出表头与分隔线
	LOG_HDR("%-20s %-7s %-16s %-5s   %-7s %-16s %-5s",
		"LOCK_ADDR", "OWNER", "O_NAME", "PRIO", "CTENDER", "C_NAME", "PRIO");
	LOG_SEP();

	// 4. 主循环：阻塞轮询ringbuf，持续消费内核下发的锁竞争实时事件
	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { // 被信号中断，正常退出循环
			err = 0;
			break;
		}
		if (err < 0) { // 轮询发生底层错误，跳出循环
			fprintf(stderr, "轮询事件失败: %s\n", strerror(-err));
			break;
		}
	}

	// 主循环退出，读取内核统计并打印整机锁竞争汇总
	print_stats();

cleanup:
	// 统一资源释放，防止句柄、探针泄漏
	g_skel = NULL;
	ring_buffer__free(rb);                // 销毁ringbuf事件通道
	mutexlock_bpf__destroy(skel);         // 卸载所有探针、销毁BPF骨架
	return err < 0 ? -err : 0;
}
