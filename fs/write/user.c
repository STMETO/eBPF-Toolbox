#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common/cli.h"
#include "common/logger.h"
#include "common/types.h"
#include "fs/write/skel.h"
#include "write.h"

/**
 * @brief 全局BPF骨架指针，用于在信号退出时打印统计信息
 */
static struct write_bpf *g_skel;

/**
 * @brief 汇总每CPU PERCPU_ARRAY统计数据并打印Write模块健康面板
 *
 * 原理：BPF侧stats_map为BPF_MAP_TYPE_PERCPU_ARRAY，每个CPU拥有独立结构体；
 * 用户态需要读取所有CPU副本，循环累加得到全局汇总指标。
 * stride 做8字节对齐，保证不同CPU的结构体副本边界正确划分。
 */
static void print_stats(void)
{
	struct Write_stats total = {};
	/* PERCPU数据读取时，每条记录强制向上对齐至8字节，防止内存越界 */
	const size_t stride = (sizeof(struct Write_stats) + 7) & ~((size_t)7);
	void *values;
	int ncpus;
	int key = 0;

	/* 未加载BPF骨架，直接返回 */
	if (!g_skel)
		return;
	/* 获取系统可用CPU总数 */
	ncpus = libbpf_num_possible_cpus();
	if (ncpus <= 0)
		return;
	/* 分配缓冲区存放所有CPU的统计副本 */
	values = calloc((size_t)ncpus, stride);
	if (!values)
		return;
	/* 一次性读取全部CPU统计数据到缓冲区 */
	if (bpf_map_lookup_elem(bpf_map__fd(g_skel->maps.stats_map), &key,
				values)) {
		free(values);
		return;
	}

	/* 遍历每个CPU，累加所有指标到total汇总结构体 */
	for (int cpu = 0; cpu < ncpus; cpu++) {
		const struct Write_stats *value =
			(const struct Write_stats *)((const char *)values +
						    (size_t)cpu * stride);

		total.attempted += value->attempted;
		total.completed += value->completed;
		total.submitted += value->submitted;
		total.failed += value->failed;
		total.filtered_pid += value->filtered_pid;
		total.filtered_self += value->filtered_self;
		total.filtered_delay += value->filtered_delay;
		total.ringbuf_dropped += value->ringbuf_dropped;
		total.map_update_failed += value->map_update_failed;
		total.lookup_missed += value->lookup_missed;
		total.path_lookup_failed += value->path_lookup_failed;
		total.total_ns += value->total_ns;

		/* 更新全局最大耗时记录，附带进程名与PID */
		if (value->max_ns > total.max_ns) {
			total.max_ns = value->max_ns;
			total.max_pid = value->max_pid;
			memcpy(total.max_comm, value->max_comm,
			       sizeof(total.max_comm));
		}
	}
	free(values);

	/* 完全没有观测流量，不输出统计面板，减少冗余打印 */
	if (!total.attempted && !total.filtered_pid)
		return;

	log_output_lock();
	/* 彩色标题输出 */
	printf("\n" C_CYAN C_BOLD "══════ Write 统计 ══════\n" C_RESET);
	printf("  尝试: %" PRIu64 "  完成: %" PRIu64 "  上报: %" PRIu64
	       "  失败: %" PRIu64 "\n",
	       total.attempted, total.completed, total.submitted, total.failed);

	/* 存在成功调用，计算平均延迟 */
	if (total.completed)
		printf("  平均: %" PRIu64 " ns  最大: %" PRIu64
		       " ns (PID=%d %s)\n",
		       total.total_ns / total.completed, total.max_ns,
		       total.max_pid, (const char *)total.max_comm);

	printf("  过滤: PID=%" PRIu64 " self=%" PRIu64 " 延迟=%" PRIu64
	       "  健康: ringbuf_drop=%" PRIu64 " map_fail=%" PRIu64
	       " lookup_miss=%" PRIu64 " name_miss=%" PRIu64 "\n",
	       total.filtered_pid, total.filtered_self, total.filtered_delay,
	       total.ringbuf_dropped, total.map_update_failed,
	       total.lookup_missed, total.path_lookup_failed);
	printf(C_CYAN C_BOLD "═══════════════════════\n" C_RESET);
	log_output_unlock();
}

/**
 * @brief ringbuf事件回调函数，BPF推送Write事件后触发
 * @param ctx 回调上下文（未使用）
 * @param data 指向BPF下发的Write_event结构体
 * @param data_sz 事件数据长度
 * @return 固定返回0
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Write_event *event = data;

	(void)ctx;
	/* 校验数据包长度，防止残缺事件导致内存越界 */
	if (data_sz < sizeof(*event)) {
		fprintf(stderr, "write 事件长度异常: %zu < %zu\n",
			data_sz, sizeof(*event));
		return 0;
	}

	log_output_lock();
	/* 打印基础字段：PID/TID/FD/请求字节/实际写入/进程名/文件名 */
	LOG("PID=%-6d TID=%-6d FD=%-4d REQ=%-8" PRIu64
	    " WROTE=%-8lld %-16s %s | ",
	    event->pid, event->tid, event->fd, event->requested_count,
	    (long long)event->bytes_written, (const char *)event->comm,
	    event->path_name_[0] ? (const char *)event->path_name_ : "(unknown)");

	/* write返回负数，解析errno字符串输出错误信息 */
	if (event->bytes_written < 0)
		printf("ERR=%s | ", strerror((int)-event->bytes_written));

	/* 带颜色打印延迟，阈值由logger内部宏控制（黄色/红色区分慢调用） */
	log_col_ns(event->latency_ns, 10000, 100000);
	printf("\n");
	log_output_unlock();
	return 0;
}

/**
 * @brief Write观测模块主入口函数
 * @param poll_timeout_ms ringbuf轮询等待超时(ms)
 * @param enable 是否启用采集
 * @param target_pid 指定观测PID，0代表全部进程
 * @param min_delay_ns 明细输出最小延迟阈值，低于阈值BPF不推送事件
 * @return 0正常退出，非0异常码
 */
int write_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid,
	      bpf_u64_t min_delay_ns)
{
	struct write_bpf *skel = NULL;
	struct ring_buffer *ringbuf = NULL;
	struct Write_ctrl ctrl = {
		.enable = enable,
		.min_delay_ns = min_delay_ns,
		.target_pid = target_pid,
		/* 填入当前进程PID，BPF用于过滤自身write，防日志自环风暴 */
		.self_pid = (bpf_s32_t)getpid(),
	};
	const int key = 0;
	int err;

	/* 获取当前进程PID命名空间dev+ino，下发BPF用于容器PID转换 */
	err = app_get_pid_namespace(&ctrl.pid_ns_dev, &ctrl.pid_ns_ino);
	if (err) {
		fprintf(stderr, "读取 PID namespace 失败: %s\n", strerror(-err));
		return 1;
	}

	/* 打开并加载BPF骨架（自动编译生成的skel） */
	skel = write_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "加载 Write BPF 程序失败\n");
		return 1;
	}
	g_skel = skel;

	/* 将运行控制参数下发至内核BPF ctrl_map */
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err) {
		fprintf(stderr, "设置 Write 控制参数失败: %d\n", err);
		goto cleanup;
	}

	/* 创建环形缓冲区消费句柄，绑定事件回调 */
	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.rb),
				   handle_event, NULL, NULL);
	if (!ringbuf) {
		err = -ENOMEM;
		fprintf(stderr, "创建 Write ringbuf 消费器失败\n");
		goto cleanup;
	}

	/* 挂载tracepoint探针 sys_enter_write / sys_exit_write */
	err = write_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载 Write tracepoint 失败: %d\n", err);
		goto cleanup;
	}

	/* 打印观测启动标题、过滤配置 */
	log_output_lock();
	log_banner("文件 Write 监控", enable);
	if (target_pid)
		LOG("过滤 PID=%d\n", target_pid);
	if (min_delay_ns)
		LOG("明细阈值=%" PRIu64 " ns（退出汇总不受阈值影响）\n",
		    min_delay_ns);
	LOG_HDR("%-7s %-7s %-5s %-9s %-9s %-16s   %s",
		"PID", "TID", "FD", "REQ", "WROTE", "COMM", "FILE");
	LOG_SEP();
	log_output_unlock();

	/* 主循环：持续轮询ringbuf，直到收到退出信号 */
	while (!app_should_exit()) {
		err = ring_buffer__poll(ringbuf, poll_timeout_ms);
		/* 被信号中断，正常退出 */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		/* ringbuf出现严重错误，终止循环 */
		if (err < 0)
			break;
	}

	/* 程序退出前打印汇总统计面板 */
	print_stats();

cleanup:
	/* 清理资源顺序：先ringbuf、再BPF骨架 */
	g_skel = NULL;
	ring_buffer__free(ringbuf);
	write_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
