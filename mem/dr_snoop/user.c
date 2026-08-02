#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common/cli.h"
#include "common/logger.h"
#include "common/types.h"
#include "dr_snoop.h"
#include "mem/dr_snoop/skel.h"

static struct dr_snoop_bpf *g_skel;

static void print_stats(void)
{
	struct DrSnoop_stats total = {};
	int key = 0;
	int ncpus;
	size_t stride;
	void *values;

	if (!g_skel)
		return;
	ncpus = libbpf_num_possible_cpus();
	if (ncpus <= 0)
		return;
	/*
	 * PERCPU_ARRAY 避免多个 CPU 在 reclaim 路径上竞争同一缓存行；这里按
	 * 8 字节对齐读取每 CPU value，累计计数并选择携带完整上下文的最大值。
	 */
	stride = (sizeof(struct DrSnoop_stats) + 7) & ~((size_t)7);
	values = calloc((size_t)ncpus, stride);
	if (!values)
		return;
	if (bpf_map_lookup_elem(bpf_map__fd(g_skel->maps.stats_map), &key, values)) {
		free(values);
		return;
	}
	for (int cpu = 0; cpu < ncpus; cpu++) {
		const struct DrSnoop_stats *v =
			(const struct DrSnoop_stats *)((char *)values + (size_t)cpu * stride);
		total.attempted += v->attempted;
		total.completed += v->completed;
		total.filtered_delay += v->filtered_delay;
		total.ringbuf_dropped += v->ringbuf_dropped;
		total.map_update_failed += v->map_update_failed;
		total.lookup_missed += v->lookup_missed;
		total.total_ns += v->total_ns;
		total.total_reclaimed += v->total_reclaimed;
		if (v->max_ns > total.max_ns) {
			total.max_ns = v->max_ns;
			total.max_pid = v->max_pid;
			memcpy(total.max_comm, v->max_comm, sizeof(total.max_comm));
		}
	}
	free(values);
	if (!total.attempted && !total.completed)
		return;

	log_output_lock();
	printf("\n" C_CYAN C_BOLD "══════ Direct Reclaim 统计 ══════\n" C_RESET);
	printf("  开始: %" PRIu64 "  完成: %" PRIu64 "  阈值过滤: %" PRIu64 "\n",
	       total.attempted, total.completed, total.filtered_delay);
	if (total.completed)
		printf("  平均: %" PRIu64 " us  最大: %" PRIu64
		       " us (PID=%d %s)  回收页: %" PRIu64 "\n",
		       total.total_ns / total.completed / 1000, total.max_ns / 1000,
		       total.max_pid, total.max_comm, total.total_reclaimed);
	printf("  健康: ringbuf_drop=%" PRIu64 " map_fail=%" PRIu64
	       " lookup_miss=%" PRIu64 "\n",
	       total.ringbuf_dropped, total.map_update_failed, total.lookup_missed);
	printf(C_CYAN C_BOLD "══════════════════════════════════\n" C_RESET);
	log_output_unlock();
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct data_t *event = data;
	time_t wall_time;
	struct tm local_tm;
	char timestamp[32];
	bpf_u64_t delay_us;

	(void)ctx;
	if (data_sz < sizeof(*event))
		return 0;
	time(&wall_time);
	localtime_r(&wall_time, &local_tm);
	strftime(timestamp, sizeof(timestamp), "%H:%M:%S", &local_tm);
	delay_us = event->delta / 1000;
	log_output_lock();
	printf("%-8s %-16s PID=%-7u reclaimed=%-8" PRIu64 " latency=%" PRIu64 ".%03" PRIu64 "ms\n",
	       timestamp, event->name, (bpf_u32_t)(event->id >> 32),
	       event->nr_reclaimed, delay_us / 1000, delay_us % 1000);
	log_output_unlock();
	return 0;
}

int dr_snoop_run(int poll_timeout_ms, bool enable,
		 bpf_s32_t target_pid, bpf_u64_t min_delay_ns)
{
	struct dr_snoop_bpf *skel = NULL;
	struct ring_buffer *ring = NULL;
	struct DrSnoop_ctrl ctrl = {};
	const int key = 0;
	int err = 0;

	err = app_get_pid_namespace(&ctrl.pid_ns_dev, &ctrl.pid_ns_ino);
	if (err) {
		fprintf(stderr, "读取 PID namespace 失败: %s\n", strerror(-err));
		return 1;
	}
	ctrl.enable = enable;
	ctrl.min_delay_ns = min_delay_ns;
	ctrl.target_pid = target_pid;

	skel = dr_snoop_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "打开 direct reclaim BPF 程序失败\n");
		return 1;
	}
	g_skel = skel;
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err) {
		fprintf(stderr, "写入 direct reclaim 配置失败: %s\n", strerror(-err));
		goto cleanup;
	}
	ring = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!ring) {
		err = -ENOMEM;
		goto cleanup;
	}
	err = dr_snoop_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载 direct reclaim tracepoint 失败: %s\n", strerror(-err));
		goto cleanup;
	}

	log_output_lock();
	log_banner("Direct Reclaim 延迟监控", enable);
	if (target_pid)
		LOG("过滤 PID=%d  阈值=%" PRIu64 " ns\n", target_pid, min_delay_ns);
	else if (min_delay_ns)
		LOG("ALL PID  阈值=%" PRIu64 " ns\n", min_delay_ns);
	printf("%-8s %-16s %-11s %-18s %s\n", "TIME", "COMM", "PID", "RECLAIMED", "LATENCY");
	log_output_unlock();
	while (!app_should_exit()) {
		err = ring_buffer__poll(ring, poll_timeout_ms);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "轮询 direct reclaim 事件失败: %s\n", strerror(-err));
			break;
		}
	}
	print_stats();

cleanup:
	g_skel = NULL;
	ring_buffer__free(ring);
	dr_snoop_bpf__destroy(skel);
	return err < 0 ? -err : err;
}
