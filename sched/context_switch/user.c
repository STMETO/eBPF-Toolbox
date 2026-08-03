#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common/cli.h"
#include "common/types.h"
#include "common/logger.h"
#include "context_switch.h"
#include "sched/context_switch/skel.h"

/**
 * @brief 全局BPF骨架指针，信号处理函数print_stats需要访问
 */
static struct context_switch_bpf *g_skel = NULL;

/* ── 信号处理：Ctrl+C 退出时打印全局统计 ──────────────────────── */
/**
 * @brief 读取内核PERCPU_ARRAY stats_map，聚合所有CPU统计并打印汇总面板
 * 程序收到SIGINT退出时调用
 */
static void print_stats(void)
{
	if (!g_skel)
		return;

	struct ContextSwitch_stats stats = {};
	int key = 0;
	// 获取系统所有possible cpu（包含离线CPU，libbpf标准接口）
	int ncpus = libbpf_num_possible_cpus();

	/*
	 * PERCPU_ARRAY lookup 会连续返回 possible CPU 的 value，每份 value 按
	 * 8 字节对齐。计数/总耗时求和；最大值则连同对应进程字段整组复制，
	 * 避免“最大耗时”和进程名来自不同 CPU。
	 *
	 * stride计算：向上对齐至8字节边界
	 * (size +7) & ~7 是业界标准向上8字节对齐算法
	 +7：不足 8 字节的部分补齐
	 & ~7：把低 3bit 清零，强制向下对齐到 8 倍数
	 */
	size_t stride = (sizeof(struct ContextSwitch_stats) + 7) & ~((size_t)7);
	void *values;

	if (ncpus <= 0)
		return;
	// 分配缓冲区：容纳所有CPU的per-cpu结构体副本
	values = calloc((size_t)ncpus, stride);
	if (!values)
		return;

	/*
	 * 一次性从内核读取全部CPU的per-cpu数据到values缓冲区
	 * key固定为0，PERCPU_ARRAY仅有单条key
	 */
	if (bpf_map_lookup_elem(bpf_map__fd(g_skel->maps.stats_map), &key, values)) {
		free(values);
		return;
	}

	// 遍历每个CPU的数据，聚合汇总
	for (int cpu = 0; cpu < ncpus; cpu++) {
		// 指针偏移：按stride跳转，拿到当前CPU对应的统计结构体起始地址
		const struct ContextSwitch_stats *v =
			(const struct ContextSwitch_stats *)((char *)values + (size_t)cpu * stride);

		// 可累加指标：直接求和
		stats.wakeups += v->wakeups;               // 成功记录的任务唤醒总数
		stats.count += v->count;                   // 成功上报ringbuf的调度延迟事件数
		stats.filtered_delay += v->filtered_delay; // 延迟低于阈值被过滤丢弃事件
		stats.ringbuf_dropped += v->ringbuf_dropped;// ringbuf满内核丢弃事件
		stats.map_update_failed += v->map_update_failed; // wakeup_map插入失败
		stats.unmatched_switches += v->unmatched_switches;// sched_switch找不到对应wakeup记录

		stats.total_ns += v->total_ns;              // 所有上报事件延迟总和(ns)

		/*
		 * 极值不能累加！每个CPU保存本CPU出现的最大延迟事件；
		 * 一旦发现更大延迟，整体拷贝pid、进程名等配套信息，保证信息一致性。
		 * 禁止只拷贝max_ns，否则进程名称可能来自其他CPU，数据错乱。
		 */
		if (v->max_ns > stats.max_ns) {
			stats.max_ns = v->max_ns;
			stats.max_prev_pid = v->max_prev_pid;
			stats.max_next_pid = v->max_next_pid;
			memcpy(stats.max_prev_comm, v->max_prev_comm, sizeof(stats.max_prev_comm));
			memcpy(stats.max_next_comm, v->max_next_comm, sizeof(stats.max_next_comm));
		}
	}
	free(values);

	// 全程无唤醒、无上报事件，不输出面板，保持日志整洁
	if (!stats.wakeups && !stats.count)
		return;

	// 计算平均调度延迟
	bpf_u64_t avg_ns = stats.count ? stats.total_ns / stats.count : 0;

	log_output_lock();
	printf("\n");
	printf(C_CYAN C_BOLD "══════ 调度等待统计 ══════\n" C_RESET);
	printf("  唤醒: %" PRIu64 "  上报: %" PRIu64 "  阈值过滤: %" PRIu64 "\n",
	       stats.wakeups, stats.count, stats.filtered_delay);
	if (stats.count) {
		printf("  平均: %" PRIu64 " ns  (", avg_ns);
		log_col_ns(avg_ns, 10000, 100000); // 根据阈值彩色打印延迟
		printf(")\n");
		printf("  最大: %" PRIu64 " ns  (", stats.max_ns);
		log_col_ns(stats.max_ns, 10000, 100000);
		printf(")\n");
		printf("        prev: TID=%d (%s) → next: TID=%d (%s)\n",
		       stats.max_prev_pid, stats.max_prev_comm,
		       stats.max_next_pid, stats.max_next_comm);
	}
	// 工具健康指标，用于排查丢事件、map异常
	printf("  健康: ringbuf_drop=%" PRIu64 " map_fail=%" PRIu64
	       " unmatched=%" PRIu64 "\n",
	       stats.ringbuf_dropped, stats.map_update_failed, stats.unmatched_switches);
	printf(C_CYAN C_BOLD "════════════════════════════\n" C_RESET);
	log_output_unlock();
}

/* ── ringbuf 事件回调：内核推送事件到达时触发 ─────────────────────────────────────── */
/**
 * @brief ringbuf事件回调，解析并打印单条调度延迟事件
 * @param ctx 自定义上下文（未使用）
 * @param data 指向内核下发的ContextSwitch_event
 * @param data_sz 事件长度
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct ContextSwitch_event *e = data;
	(void)ctx;
	(void)data_sz;

	const char *state_str;
	/*
	 * prev_state：让出CPU的任务切换前内核状态
	 * 内核task_struct::__state 常量映射
	 */
	switch (e->prev_state) {
		case 0x0000: state_str = "RUNNING";  break;   /* TASK_RUNNING */
		case 0x0001: state_str = "INTR";     break;   /* TASK_INTERRUPTIBLE 可中断睡眠 */
		case 0x0002: state_str = "UNINTR";   break;   /* TASK_UNINTERRUPTIBLE 不可中断睡眠(D状态) */
		case 0x0004: state_str = "STOPPED";  break;   /* __TASK_STOPPED */
		case 0x0008: state_str = "TRACED";   break;
		default:     state_str = "???";
	}

	log_output_lock();
	/*
	 * e->cpu: 当前发生上下文切换的CPU
	 * e->wakeup_cpu：next任务当初被唤醒时所在CPU，用于观察任务跨核迁移
	 * prev：让出CPU任务；next：获得CPU运行任务
	 * preempt=true：抢占式切换；false：自愿切换（主动sleep/时间片耗尽）
	 */
	LOG("CPU=%-2d WAKE_CPU=%-2d | PREV: TID=%-6d TGID=%-6d %-16s PRIO=%-4d [%-6s] | "
	    "NEXT: TID=%-6d TGID=%-6d %-16s PRIO=%-4d | ",
	    e->cpu, e->wakeup_cpu,
	    e->prev_pid, e->prev_tgid, e->prev_comm, e->prev_prio, state_str,
	    e->next_pid, e->next_tgid, e->next_comm, e->next_prio);

	log_col_ns(e->delay_ns, 10000, 100000); // 彩色打印调度延迟

	printf(" %s\n", e->preempt ? C_RED "[PREEMPT]" C_RESET : "[VOLUNTARY]");
	log_output_unlock();
	return 0;
}

/* ── 监控主入口函数 ──────────────────────────────────────────────── */
/**
 * @brief 调度延迟监控启动逻辑
 * @param poll_timeout_ms ringbuf轮询超时时间
 * @param enable 是否开启采集
 * @param target_pid 目标TGID过滤，0表示全部进程
 * @param min_delay_ns 最小调度延迟阈值，低于阈值丢弃事件
 * @return 执行返回码
 */
int context_switch_run(int poll_timeout_ms, bool enable,
		       bpf_s32_t target_pid, bpf_u64_t min_delay_ns)
{
	struct context_switch_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	const int key = 0;
	int err = 0;
	bpf_u64_t pid_ns_dev, pid_ns_ino;

	// 获取当前进程所在PID Namespace设备号、inode，下发给BPF用于容器PID转换
	err = app_get_pid_namespace(&pid_ns_dev, &pid_ns_ino);
	if (err) {
		fprintf(stderr, "读取 PID namespace 失败: %s\n", strerror(-err));
		return 1;
	}

	// 打开并加载BPF骨架（libbpf BTF CO-RE模式）
	skel = context_switch_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "打开BPF程序失败\n");
		return 1;
	}
	g_skel = skel;

	/* 填充全局控制参数，下发到内核ctrl_map */
	struct ContextSwitch_ctrl ctrl = {
		.enable       = enable,
		.min_delay_ns = min_delay_ns,
		.target_pid   = target_pid,
		.pid_ns_dev   = pid_ns_dev,
		.pid_ns_ino   = pid_ns_ino,
	};
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "设置控制开关失败: %s\n", strerror(-err));
		goto cleanup;
	}

	// 创建ringbuffer，绑定事件回调handle_event
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "创建RingBuffer失败\n");
		goto cleanup;
	}

	// 挂载所有tracepoint BPF程序（sched_wakeup / sched_switch等）
	err = context_switch_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载BPF程序失败\n");
		goto cleanup;
	}

	// 打印启动横幅与过滤条件
	log_output_lock();
	log_banner("调度等待延迟监控", enable);
	if (target_pid)
		LOG("过滤 PID=%d  阈值=%" PRIu64 " ns\n", target_pid, min_delay_ns);
	else if (min_delay_ns)
		LOG(" ALL PID  阈值=%" PRIu64 " ns\n", min_delay_ns);
	else
		LOG("ALL PID  阈值=无\n");
	LOG_HDR("%-3s %-4s %-7s %-7s %-16s %-5s %-7s   %-7s %-7s %-16s %-5s   %-10s %s",
		"CPU", "WCPU", "PREV", "TGID", "COMM", "PRIO", "STATE",
		"NEXT", "TGID", "COMM", "PRIO", "DELAY", "TYPE");
	LOG_SEP();
	log_output_unlock();

	// 主循环：持续轮询ringbuf等待内核事件
	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { // 收到信号中断轮询（Ctrl+C），正常退出
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "轮询事件失败: %s\n", strerror(-err));
			break;
		}
	}

	// 退出前打印汇总统计面板
	print_stats();

cleanup:
	g_skel = NULL;
	ring_buffer__free(rb);
	context_switch_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
