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
#include "fs/read/skel.h"
#include "read.h"

/**
 * @brief 全局BPF骨架指针
 * 主要用于信号回调、程序退出阶段汇总打印统计信息
 */
static struct read_bpf *g_skel;

/**
 * @brief 合并 PERCPU stats_map 中所有CPU统计数据，打印Read模块汇总面板
 *
 * BPF_MAP_TYPE_PERCPU_ARRAY读取规则：
 * libbpf要求每个CPU对应的统计结构体缓冲区必须向上对齐至8字节；
 * 不能直接使用 ncpus * sizeof(struct Read_stats) 分配数组，否则CPU数据边界错位。
 * stride = 向上对齐到8字节的结构体占用长度，用于遍历每个CPU的统计副本。
 */
static void print_stats(void)
{
	struct Read_stats total = {};
	/* 计算对齐步长：向上取整至8字节 */
	const size_t stride = (sizeof(struct Read_stats) + 7) & ~((size_t)7);
	void *values;
	int ncpus;
	int key = 0;

	/* BPF骨架未初始化，直接返回 */
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
	/* 一次性读取全部CPU统计数据 */
	if (bpf_map_lookup_elem(bpf_map__fd(g_skel->maps.stats_map), &key,
				values)) {
		free(values);
		return;
	}

	/* 遍历每一颗CPU，累加所有指标到全局汇总结构体 */
	for (int cpu = 0; cpu < ncpus; cpu++) {
		const struct Read_stats *value =
			(const struct Read_stats *)((const char *)values +
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

		/* 记录全局最大耗时以及对应进程信息 */
		if (value->max_ns > total.max_ns) {
			total.max_ns = value->max_ns;
			total.max_pid = value->max_pid;
			memcpy(total.max_comm, value->max_comm,
			       sizeof(total.max_comm));
		}
	}
	free(values);

	/* 完全没有流量、也没有PID过滤事件，不打印统计面板，减少冗余输出 */
	if (!total.attempted && !total.filtered_pid)
		return;

	log_output_lock();
	printf("\n" C_CYAN C_BOLD "══════ Read 统计 ══════\n" C_RESET);
	printf("  尝试: %" PRIu64 "  完成: %" PRIu64 "  上报: %" PRIu64
	       "  失败: %" PRIu64 "\n",
	       total.attempted, total.completed, total.submitted, total.failed);
	/* 存在成功完成的调用，计算平均延迟 */
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
	printf(C_CYAN C_BOLD "══════════════════════\n" C_RESET);
	log_output_unlock();
}

/**
 * @brief ringbuf事件回调函数
 * BPF向用户态推送Read事件后触发，解析并打印单条read调用明细
 * @param ctx 回调上下文，未使用
 * @param data 指向BPF下发的Read_event结构体
 * @param data_sz 事件数据包长度
 * @return 固定返回0
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Read_event *event = data;

	(void)ctx;
	/* 数据包长度校验，防止残缺结构体导致内存越界崩溃 */
	if (data_sz < sizeof(*event)) {
		fprintf(stderr, "read 事件长度异常: %zu < %zu\n",
			data_sz, sizeof(*event));
		return 0;
	}

	log_output_lock();
	/* 打印基础字段：PID/TID/FD/请求字节/实际读取字节/进程名/文件名 */
	LOG("PID=%-6d TID=%-6d FD=%-4d REQ=%-8" PRIu64
	    " READ=%-8lld %-16s %s | ",
	    event->pid, event->tid, event->fd, event->requested_count,
	    (long long)event->bytes_read, (const char *)event->comm,
	    event->path_name_[0] ? (const char *)event->path_name_ : "(unknown)");
	/* read返回负数，解析errno字符串输出错误信息 */
	if (event->bytes_read < 0)
		printf("ERR=%s | ", strerror((int)-event->bytes_read));
	/* 带色彩打印延迟，内部阈值区分普通/慢速IO */
	log_col_ns(event->latency_ns, 10000, 100000);
	printf("\n");
	log_output_unlock();
	return 0;
}

/**
 * @brief Read文件监控模块主入口
 * @param poll_timeout_ms ringbuf轮询超时(ms)
 * @param enable 是否启用采集
 * @param target_pid 指定观测PID，0代表采集当前命名空间全部进程
 * @param min_delay_ns 明细输出延迟阈值，低于阈值BPF不推送事件
 * @return 0正常退出，非0异常码
 */
int read_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid,
	     bpf_u64_t min_delay_ns)
{
	struct read_bpf *skel = NULL;
	struct ring_buffer *ringbuf = NULL;
	struct Read_ctrl ctrl = {
		.enable = enable,
		.min_delay_ns = min_delay_ns,
		.target_pid = target_pid,
		/* 填入当前进程PID，BPF用于过滤自身read调用，防止日志自环风暴 */
		.self_pid = (bpf_s32_t)getpid(),
	};
	const int key = 0;
	int err;

	/* 获取当前进程PID命名空间dev/ino，下发BPF实现容器边界隔离 */
	err = app_get_pid_namespace(&ctrl.pid_ns_dev, &ctrl.pid_ns_ino);
	if (err) {
		fprintf(stderr, "读取 PID namespace 失败: %s\n", strerror(-err));
		return 1;
	}

	/* 打开并加载BPF骨架（由bpftool生成） */
	skel = read_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "加载 Read BPF 程序失败\n");
		return 1;
	}
	g_skel = skel;

	/* 将运行控制参数下发至内核ctrl_map */
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err) {
		fprintf(stderr, "设置 Read 控制参数失败: %d\n", err);
		goto cleanup;
	}

	/* 创建环形缓冲区消费实例，绑定事件回调 */
	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.rb),
				   handle_event, NULL, NULL);
	if (!ringbuf) {
		err = -ENOMEM;
		fprintf(stderr, "创建 Read ringbuf 消费器失败\n");
		goto cleanup;
	}

	/* 挂载 tracepoint：sys_enter_read / sys_exit_read */
	err = read_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载 Read tracepoint 失败: %d\n", err);
		goto cleanup;
	}

	/* 打印启动横幅、当前采集配置 */
	log_output_lock();
	log_banner("文件 Read 监控", enable);
	if (target_pid)
		LOG("过滤 PID=%d\n", target_pid);
	if (min_delay_ns)
		LOG("明细阈值=%" PRIu64 " ns（退出汇总不受阈值影响）\n",
		    min_delay_ns);
	LOG_HDR("%-7s %-7s %-5s %-9s %-9s %-16s   %s",
		"PID", "TID", "FD", "REQ", "READ", "COMM", "FILE");
	LOG_SEP();
	log_output_unlock();

	/* 主循环：持续轮询ringbuf，直到收到退出信号 */
	while (!app_should_exit()) {
		err = ring_buffer__poll(ringbuf, poll_timeout_ms);
		/* Ctrl+C触发信号中断，正常退出 */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		/* ringbuf发生严重错误，终止循环 */
		if (err < 0)
			break;
	}

	/* 程序退出前打印汇总统计面板 */
	print_stats();

cleanup:
	/* 资源释放顺序：先解除全局指针，销毁ringbuf，最后销毁BPF骨架 */
	g_skel = NULL;
	ring_buffer__free(ringbuf);
	read_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
