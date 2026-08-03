#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

#include "common/cli.h"
#include "common/logger.h"
#include "common/types.h"
#include "ipc/msgqueue/skel.h"
#include "msgqueue.h"

/* 当前模块的 skeleton，仅在 msgqueue_run() 生命周期内有效。 */
static struct msgqueue_bpf *g_skel;

/**
 * @brief 从 stats_map 读取并展示驻留时间统计。
 *
 * QUEUED 只包含真正经过 msg_insert 入队并在接收端开始交付的消息，因此
 * 平均值和最大值都是队列驻留时间。DIRECT 表示内核直接把消息交给等待
 * 中的接收者，它没有进入队列，不能混入驻留时间平均值。异常计数单独
 * 展示，方便判断高负载时关联 Map 或 ringbuf 是否造成观测缺口。
 */
static void print_stats(void)
{
	struct Msgqueue_stats stats = {};
	int key = 0;

	if (!g_skel)
		return;
	if (bpf_map__lookup_elem(g_skel->maps.stats_map, &key, sizeof(key),
				 &stats, sizeof(stats), 0))
		return;
	if (!stats.queued_count && !stats.direct_count &&
	    !stats.unmatched_count && !stats.tracking_drop_count &&
	    !stats.ringbuf_drop_count)
		return;

	fprintf(stderr, "\n");
	printf(C_CYAN C_BOLD "══════ POSIX 消息队列驻留统计 ══════\n" C_RESET);
	if (stats.queued_count) {
		printf("  已排队: %" PRIu64 " 条  avg=%" PRIu64
		       " ns  max=%" PRIu64 " ns\n",
		       stats.queued_count,
		       stats.queued_total_ns / stats.queued_count,
		       stats.queued_max_ns);
	}
	if (stats.direct_count)
		printf("  直接交付: %" PRIu64 " 条（未进入队列，驻留时间=0）\n",
		       stats.direct_count);
	if (stats.unmatched_count)
		printf("  无入队记录: %" PRIu64
		       " 条（可能在工具启动前已入队或 LRU 被淘汰）\n",
		       stats.unmatched_count);
	if (stats.tracking_drop_count)
		printf("  关联写入失败: %" PRIu64 " 条\n",
		       stats.tracking_drop_count);
	if (stats.ringbuf_drop_count)
		printf("  明细上报丢失: %" PRIu64 " 条\n",
		       stats.ringbuf_drop_count);
	printf(C_CYAN C_BOLD "══════════════════════════════════════\n" C_RESET);
}

/**
 * @brief 消费 BPF ringbuf 中的一条消息驻留事件。
 *
 * QUEUED 和 DIRECT 都通过内核消息对象关联发送、接收两端。data_sz 检查
 * 可以防止用户态和 BPF 事件 ABI 不一致时越界解析旧数据。
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Msgqueue_event *event = data;

	(void)ctx;
	if (data_sz < sizeof(*event)) {
		fprintf(stderr, "msgqueue 事件长度异常: %zu < %zu\n",
			data_sz, sizeof(*event));
		return 0;
	}

	LOG("%s | SEND=%d/%-16s fd=%-4d -> RECV=%d/%-16s fd=%-4d"
	    " | LEN=%-6" PRIu64 " PRIO=%-4u | ",
	    event->delivery_type == MQ_DELIVERY_DIRECT ?
		C_YELLOW "DIRECT" C_RESET : C_GREEN "QUEUED" C_RESET,
	    event->sender_pid, (const char *)event->sender_comm,
	    event->send_mqdes, event->receiver_pid,
	    (const char *)event->receiver_comm, event->recv_mqdes,
	    event->msg_len, event->msg_prio);
	log_col_ns(event->residence_ns, 100000, 1000000);
	printf("\n");
	return 0;
}

/**
 * @brief 加载、配置并运行 POSIX 消息队列驻留时间监控。
 *
 * BPF 程序通过 fentry/fexit 挂载 load_msg、msg_insert、store_msg 以及
 * do_mq_timed{send,receive}。这些挂载点共同以 struct msg_msg * 关联同一条
 * 消息，ringbuf 只负责传输完成的驻留事件。
 */
int msgqueue_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid,
		 bpf_u64_t min_delay_ns)
{
	struct msgqueue_bpf *skel = NULL;
	struct ring_buffer *ringbuf = NULL;
	struct Msgqueue_ctrl ctrl = {
		.enable = enable,
		.min_delay_ns = min_delay_ns,
		.target_pid = target_pid,
	};
	const int key = 0;
	int err;

	/*
	 * 把命令行 PID 解释为工具当前 namespace 可见的 TGID。BPF 侧会用
	 * 相同 dev/ino 转换发送者和接收者 PID，容器内外不会混用编号。
	 */
	err = app_get_pid_namespace(&ctrl.pidns_dev, &ctrl.pidns_ino);
	if (err) {
		fprintf(stderr, "读取 PID namespace 失败: %d\n", err);
		return -err;
	}

	/* 打开并加载 BPF ELF；此阶段内核 verifier 会检查所有关联逻辑。 */
	skel = msgqueue_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr,
			"加载消息队列驻留程序失败（需要内核 BTF 和 fentry/fexit）\n");
		return 1;
	}
	g_skel = skel;

	/* attach 前写入配置，避免探针刚挂载时短暂采集到未配置事件。 */
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err) {
		fprintf(stderr, "设置消息队列驻留监控参数失败: %d\n", err);
		goto cleanup;
	}

	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.rb),
				   handle_event, NULL, NULL);
	if (!ringbuf) {
		err = -ENOMEM;
		fprintf(stderr, "创建消息队列 ringbuf 消费器失败\n");
		goto cleanup;
	}

	err = msgqueue_bpf__attach(skel);
	if (err) {
		fprintf(stderr,
			"挂载消息队列内部函数失败: %d（请确认内核包含对应 BTF 函数）\n",
			err);
		goto cleanup;
	}

	log_banner("POSIX 消息队列驻留时间监控", enable);
	if (target_pid)
		LOG("过滤 PID=%d（发送者或接收者匹配）\n", target_pid);
	if (min_delay_ns)
		LOG("明细阈值=%" PRIu64 " ns（退出汇总不受阈值影响）\n",
		    min_delay_ns);
	LOG_HDR("%-7s %-31s %-31s %-10s %-6s   %s",
		"TYPE", "SENDER", "RECEIVER", "LEN", "PRIO", "RESIDENCE");
	LOG_SEP();

	while (!app_should_exit()) {
		err = ring_buffer__poll(ringbuf, poll_timeout_ms);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0)
			break;
	}

	print_stats();

cleanup:
	g_skel = NULL;
	ring_buffer__free(ringbuf);
	msgqueue_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
