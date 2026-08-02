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

static struct context_switch_bpf *g_skel = NULL;

/* ── 信号处理：Ctrl+C 时打印全局统计 ──────────────────────── */
static void print_stats(void)
{
	if (!g_skel)
		return;

	struct ContextSwitch_stats stats = {};
	int key = 0;
	int ncpus = libbpf_num_possible_cpus();
	size_t stride = (sizeof(struct ContextSwitch_stats) + 7) & ~((size_t)7);
	void *values;

	if (ncpus <= 0)
		return;
	values = calloc((size_t)ncpus, stride);
	if (!values)
		return;
	if (bpf_map_lookup_elem(bpf_map__fd(g_skel->maps.stats_map), &key, values)) {
		free(values);
		return;
	}
	for (int cpu = 0; cpu < ncpus; cpu++) {
		const struct ContextSwitch_stats *v =
			(const struct ContextSwitch_stats *)((char *)values + (size_t)cpu * stride);
		stats.wakeups += v->wakeups;
		stats.count += v->count;
		stats.filtered_delay += v->filtered_delay;
		stats.ringbuf_dropped += v->ringbuf_dropped;
		stats.map_update_failed += v->map_update_failed;
		stats.unmatched_switches += v->unmatched_switches;
		stats.total_ns += v->total_ns;
		if (v->max_ns > stats.max_ns) {
			stats.max_ns = v->max_ns;
			stats.max_prev_pid = v->max_prev_pid;
			stats.max_next_pid = v->max_next_pid;
			memcpy(stats.max_prev_comm, v->max_prev_comm, sizeof(stats.max_prev_comm));
			memcpy(stats.max_next_comm, v->max_next_comm, sizeof(stats.max_next_comm));
		}
	}
	free(values);
	if (!stats.wakeups && !stats.count)
		return;

	bpf_u64_t avg_ns = stats.count ? stats.total_ns / stats.count : 0;

	log_output_lock();
	printf("\n");
	printf(C_CYAN C_BOLD "══════ 调度等待统计 ══════\n" C_RESET);
	printf("  唤醒: %" PRIu64 "  上报: %" PRIu64 "  阈值过滤: %" PRIu64 "\n",
	       stats.wakeups, stats.count, stats.filtered_delay);
	if (stats.count) {
		printf("  平均: %" PRIu64 " ns  (", avg_ns);
		log_col_ns(avg_ns, 10000, 100000);
		printf(")\n");
		printf("  最大: %" PRIu64 " ns  (", stats.max_ns);
		log_col_ns(stats.max_ns, 10000, 100000);
		printf(")\n");
		printf("        prev: TID=%d (%s) → next: TID=%d (%s)\n",
		       stats.max_prev_pid, stats.max_prev_comm,
		       stats.max_next_pid, stats.max_next_comm);
	}
	printf("  健康: ringbuf_drop=%" PRIu64 " map_fail=%" PRIu64
	       " unmatched=%" PRIu64 "\n",
	       stats.ringbuf_dropped, stats.map_update_failed, stats.unmatched_switches);
	printf(C_CYAN C_BOLD "════════════════════════════\n" C_RESET);
	log_output_unlock();
}

/* ── ringbuf 事件回调 ─────────────────────────────────────── */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct ContextSwitch_event *e = data;
	(void)ctx;
	(void)data_sz;

	const char *state_str;
	switch (e->prev_state) {
		case 0x0000: state_str = "RUNNING";  break;   /* TASK_RUNNING */
		case 0x0001: state_str = "INTR";     break;   /* TASK_INTERRUPTIBLE */
		case 0x0002: state_str = "UNINTR";   break;   /* TASK_UNINTERRUPTIBLE */
		case 0x0004: state_str = "STOPPED";  break;   /* __TASK_STOPPED */
		case 0x0008: state_str = "TRACED";   break;
		default:     state_str = "???";
	}

	log_output_lock();
	LOG("CPU=%-2d WAKE_CPU=%-2d | PREV: TID=%-6d TGID=%-6d %-16s PRIO=%-4d [%-6s] | "
	    "NEXT: TID=%-6d TGID=%-6d %-16s PRIO=%-4d | ",
	    e->cpu, e->wakeup_cpu,
	    e->prev_pid, e->prev_tgid, e->prev_comm, e->prev_prio, state_str,
	    e->next_pid, e->next_tgid, e->next_comm, e->next_prio);

	log_col_ns(e->delay_ns, 10000, 100000);

	printf(" %s\n", e->preempt ? C_RED "[PREEMPT]" C_RESET : "[VOLUNTARY]");
	log_output_unlock();
	return 0;
}

/* ── 入口函数 ──────────────────────────────────────────────── */
int context_switch_run(int poll_timeout_ms, bool enable,
		       bpf_s32_t target_pid, bpf_u64_t min_delay_ns)
{
	struct context_switch_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	const int key = 0;
	int err = 0;
	bpf_u64_t pid_ns_dev, pid_ns_ino;

	err = app_get_pid_namespace(&pid_ns_dev, &pid_ns_ino);
	if (err) {
		fprintf(stderr, "读取 PID namespace 失败: %s\n", strerror(-err));
		return 1;
	}

	skel = context_switch_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "打开BPF程序失败\n");
		return 1;
	}
	g_skel = skel;

	/* 设置控制参数 */
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

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "创建RingBuffer失败\n");
		goto cleanup;
	}

	err = context_switch_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载BPF程序失败\n");
		goto cleanup;
	}

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

	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "轮询事件失败: %s\n", strerror(-err));
			break;
		}
	}

	print_stats();

cleanup:
	g_skel = NULL;
	ring_buffer__free(rb);
	context_switch_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
