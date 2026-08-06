/*
slab_rate_run()
├─ 初始化阶段
│  ├─ app_get_pid_namespace() 获取pid ns dev/ino
│  ├─ 填充 SlabRate_ctrl 控制结构体
│  ├─ libbpf_num_possible_cpus() 获取possible CPU数量
│  ├─ 计算per‑cpu value对齐步长 value_stride
│  ├─ calloc 分配4块内存缓冲区
│  └─ slab_rate_bpf__open() 打开BPF skeleton
│     ├─ set_autoattach=false 禁用 *_node tracepoint自动挂载
│     ├─ slab_rate_bpf__load() BPF加载进入内核
│     ├─ bpf_map__update_elem() 更新 ctrl_map，下发配置到内核BPF
│     ├─ slab_rate_bpf__attach() 挂载普通tracepoint
│     ├─ attach_optional_raw_tracepoint() 条件挂载 handle_kmem_cache_alloc_node
│     └─ attach_optional_raw_tracepoint() 条件挂载 handle_kmalloc_node
├─ 打印启动Banner日志
├─ clock_gettime 获取窗口起始时间 window_start
├─ 【主循环 while(!app_should_exit())】
│  ├─ poll(NULL, 0, poll_timeout_ms) 定时等待，支持信号打断
│  ├─ 如果收到退出信号，跳出循环
│  ├─ clock_gettime 获取窗口结束 window_end
│  ├─ print_interval() 一轮采样输出
│  │  ├─ collect_samples()
│  │  │  ├─ bpf_map_get_next_key 遍历 slab_entries hash map所有key
│  │  │  └─ bpf_map_lookup_elem读取per‑cpu副本，跨CPU累加得到全局total统计
│  │  ├─ 遍历current采样列表
│  │  │  └─ find_previous() 在previous快照查找历史统计值(memcmp key)
│  │  ├─ 做差分 delta = 当前总计数 − 历史快照计数
│  │  ├─ qsort 按bytes_per_sec降序排序
│  │  ├─ format_xxx() 格式化速率字符串，输出表格（最多输出20行）
│  │  └─ memcpy current快照覆盖previous，作为下一轮基线
│  └─ window_start = window_end，滚动窗口，进入下一轮循环
├─ 循环退出后 print_stats()
│  ├─ 读取stats_map percpu array，聚合各个CPU健康统计
│  └─ 打印探针健康指标、内核兼容降级提示
└─ cleanup 统一资源释放
   ├─ bpf_link__destroy 销毁可选tracepoint link
   ├─ slab_rate_bpf__destroy() 销毁skeleton，卸载内核BPF
   ├─ free全部malloc缓冲区
   └─ 返回程序退出码

*/

#include <errno.h>           /* errno 错误号定义 */
#include <inttypes.h>        /* PRIu64 等格式化宏 */
#include <poll.h>            /* poll 系统调用，用于定时等待 */
#include <stdio.h>           /* 标准输入输出 */
#include <stdlib.h>          /* 内存分配、退出等 */
#include <string.h>          /* 字符串操作 */
#include <time.h>            /* 时间相关，clock_gettime */
#include <unistd.h>          /* POSIX API，access 等 */

#include <bpf/bpf.h>         /* bpf_map_* 用户态辅助函数 */
#include <bpf/libbpf.h>      /* libbpf 主头文件，skeleton、bpf_link 等 */

#include "common/cli.h"      /* 应用公共命令行接口 */
#include "common/logger.h"   /* 日志输出宏：LOG, log_banner, log_output_lock 等 */
#include "common/types.h"    /* 公共类型定义 */
#include "mem/slab_rate/skel.h" /* slab_rate BPF skeleton 自动生成头文件 */
#include "slab_rate.h"       /* slab_rate 共享结构：SlabRate_ctrl, SlabRate_key, ... */

/* 每个采样窗口按分配字节速率降序展示前 20 个热点。 */
#define OUTPUT_ROWS 20

/* 
 * 快照条目结构体：一个键及其在某一时刻的累计值（所有 CPU 合计）。
 * 用于存储两次相邻快照，计算差值。
 */
struct slab_sample {
	struct SlabRate_key key;      /* 聚合键（类型 + 大小/名称） */
	struct SlabRate_info total;   /* 该键对应的总计数和总字节数 */
};

/*
 * 排序用行结构体：包含键、本次窗口内的增量和计算出的速率。
 */
struct slab_row {
	struct SlabRate_key key;      /* 聚合键 */
	bpf_u64_t count_delta;        /* 窗口内分配次数增量 */
	bpf_u64_t bytes_delta;        /* 窗口内分配字节增量 */
	double allocs_per_sec;        /* 每秒分配次数 */
	double bytes_per_sec;         /* 每秒分配字节数 */
};

/*
 * 返回 1 表示 tracepoint 存在，0 表示已挂载的 tracefs 中确认不存在，-1
 * 表示当前环境没有可见的 tracefs。先检查文件可避免 libbpf 为新内核已删除
 * 的旧 *_node 事件打印预期内的 ENOENT；tracefs 不可见时仍允许尝试 attach。
 */
static int kmem_tracepoint_exists(const char *event)
{
	/* 常见的 tracefs 挂载点路径 */
	static const char *roots[] = {
		"/sys/kernel/tracing",
		"/sys/kernel/debug/tracing",
	};
	char events_dir[160];          /* 存放 events/kmem 目录路径 */
	char id_path[256];             /* 存放具体事件 id 文件路径 */
	bool tracefs_visible = false;  /* 标记是否至少有一个 tracefs 根目录可访问 */

	/* 遍历两个可能挂载点 */
	for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
		/* 拼接 events/kmem 目录路径 */
		snprintf(events_dir, sizeof(events_dir), "%s/events/kmem", roots[i]);
		/* 检查目录是否存在，不存在则尝试下一个路径 */
		if (access(events_dir, F_OK) != 0)
			continue;
		tracefs_visible = true;    /* 找到可用的 tracefs 根 */
		/* 拼接具体事件 id 文件的路径 */
		snprintf(id_path, sizeof(id_path), "%s/%s/id", events_dir, event);
		/* 如果 id 文件存在，则 tracepoint 存在，返回 1 */
		if (access(id_path, F_OK) == 0)
			return 1;
	}
	/* 如果至少看到了 tracefs 但事件 id 不存在，返回 0；否则返回 -1 */
	return tracefs_visible ? 0 : -1;
}

/*
 * 挂载可选的 raw tracepoint：先探测事件是否存在，存在则挂载，不存在则跳过。
 * 这样新内核因不存在这些事件而 attach 失败时不会视为错误。
 */
static int attach_optional_raw_tracepoint(struct bpf_program *program,
					  const char *event,
					  struct bpf_link **link)
{
	int available = kmem_tracepoint_exists(event);  /* 探测事件存在性 */
	int err;

	/* 确认事件不存在（非 tracefs 不可见），直接返回成功，不做挂载 */
	if (available == 0)
		return 0;
	/* 尝试挂载 raw tracepoint */
	*link = bpf_program__attach_raw_tracepoint(program, event);
	err = libbpf_get_error(*link);    /* 获取错误码（无错误返回 0） */
	if (!err)
		return 0;                     /* 挂载成功 */
	*link = NULL;
	/* 
	 * 如果 tracefs 不可见，之前返回 -1，attach 可能报其他错误；
	 * 这里仅把 ENOENT 视为正常（事件不存在），其他错误向上传递。
	 */
	return err == -ENOENT ? 0 : err;
}

/*
 * qsort 排序比较函数：按 bytes_per_sec 降序排列。
 * 使得分配字节速率最高的条目排在前面。
 */
static int sort_by_bytes_rate(const void *left, const void *right)
{
	const struct slab_row *a = left;
	const struct slab_row *b = right;

	/* b 比 a 大则 b 排前面（降序） */
	return b->bytes_per_sec > a->bytes_per_sec ? 1 :
	       b->bytes_per_sec < a->bytes_per_sec ? -1 : 0;
}

/*
 * 计算两个单调时钟时间点之间的纳秒差值。
 * 将秒和纳秒分别转换为纳秒再相减，避免借位问题。
 */
static bpf_u64_t elapsed_ns(const struct timespec *start,
			    const struct timespec *end)
{
	/* CLOCK_MONOTONIC 不会倒退，先各自转为纳秒再相减可避开借位歧义。 */
	return ((bpf_u64_t)end->tv_sec * 1000000000ULL + end->tv_nsec) -
	       ((bpf_u64_t)start->tv_sec * 1000000000ULL + start->tv_nsec);
}

/* 速率使用二进制字节单位，避免大数把表格列宽撑乱。 */
static void format_byte_rate(double bytes_per_sec, char *buf, size_t len)
{
	static const char *units[] = {"B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"};
	int unit = 0;

	/* 当速率 >= 1024 时逐级向更大单位转换，最多到 TiB/s */
	while (bytes_per_sec >= 1024.0 && unit < 4) {
		bytes_per_sec /= 1024.0;
		unit++;
	}
	/* 格式化为保留一位小数的字符串 */
	snprintf(buf, len, "%.1f %s", bytes_per_sec, units[unit]);
}

/* 格式化分配次数速率，采用千进制单位（K, M, G） */
static void format_alloc_rate(double allocs_per_sec, char *buf, size_t len)
{
	static const char *units[] = {"/s", "K/s", "M/s", "G/s"};
	int unit = 0;

	while (allocs_per_sec >= 1000.0 && unit < 3) {
		allocs_per_sec /= 1000.0;
		unit++;
	}
	snprintf(buf, len, "%.1f %s", allocs_per_sec, units[unit]);
}

/*
 * 根据键的类型，将聚合键格式化为可读字符串。
 * 具名缓存显示名字，kmalloc 和降级缓存显示大小类名。
 */
static void format_cache_name(const struct SlabRate_key *key,
			      char *buf, size_t len)
{
	if (key->kind == SLAB_RATE_KMALLOC)
		/* 通用 kmalloc 分配，显示 kmalloc-<size> */
		snprintf(buf, len, "kmalloc-%" PRIu64, key->alloc_size);
	else if (key->kind == SLAB_RATE_CACHE_SIZE)
		/* 降级路径的具名缓存，显示 kmem_cache-<size> */
		snprintf(buf, len, "kmem_cache-%" PRIu64, key->alloc_size);
	else
		/* 具名缓存，直接打印名称字符串（最多 CACHE_NAME_SIZE 个字符） */
		snprintf(buf, len, "%.*s", CACHE_NAME_SIZE, key->name);
}

/*
 * 在上一个快照数组中查找与指定 key 匹配的条目，返回其累计值指针。
 * 若未找到返回 NULL。
 */
static const struct SlabRate_info *find_previous(
	const struct slab_sample *previous, int previous_count,
	const struct SlabRate_key *key)
{
	for (int i = 0; i < previous_count; i++) {
		/* 比较键是否完全一致（包括 kind、size、name） */
		if (!memcmp(&previous[i].key, key, sizeof(*key)))
			return &previous[i].total;
	}
	return NULL;
}

/*
 * 读取 PERCPU_HASH 时，内核要求用户缓冲区按 8 字节对齐后的 value 大小乘
 * possible CPU 数量分配。本函数合并全部 CPU 副本，得到每个键的累计值。
 */
static int collect_samples(int map_fd, int ncpus, size_t value_stride,
			   void *percpu_values, struct slab_sample *samples,
			   int *sample_count)
{
	struct SlabRate_key current_key;         /* 当前遍历到的键 */
	struct SlabRate_key next_key;            /* 下一次迭代的键 */
	const struct SlabRate_key *previous_key = NULL; /* 遍历游标，初始为 NULL */
	int count = 0;

	/* 遍历整个 hash map：循环获取下一个 key，直到返回 ENOENT */
	while (bpf_map_get_next_key(map_fd, previous_key, &next_key) == 0) {
		struct SlabRate_info total = {};   /* 用于累加所有 CPU 副本的总和 */

		current_key = next_key;             /* 保存当前 key */
		/* 根据 key 查找 per-CPU 值的原始缓冲区 */
		if (bpf_map_lookup_elem(map_fd, &current_key, percpu_values) == 0) {
			/* 遍历每个 possible CPU，累加其 value */
			for (int cpu = 0; cpu < ncpus; cpu++) {
				const struct SlabRate_info *cpu_value =
					/* 每个 CPU 副本按 value_stride 间隔存放 */
					(const void *)((char *)percpu_values +
						       (size_t)cpu * value_stride);

				total.count += cpu_value->count;
				total.allocated_bytes += cpu_value->allocated_bytes;
			}
			/* 超出最大条目数，返回错误 */
			if (count >= SLAB_RATE_MAX_ENTRIES)
				return -E2BIG;
			/* 保存键和汇总后的值到快照数组 */
			samples[count].key = current_key;
			samples[count].total = total;
			count++;
		} else if (errno != ENOENT) {
			/* 查找失败且不是 key 不存在，返回错误 */
			return -errno;
		}

		/* Map 条目不会在采集期间删除，因此 current_key 可安全作为游标。 */
		previous_key = &current_key;
	}
	/* 退出循环如果不是 ENOENT 则返回错误 */
	if (errno != ENOENT)
		return -errno;
	*sample_count = count;
	return 0;
}

/*
 * BPF Map 保留累计值，用户态用相邻快照做差。这样不会像“读完即删”那样
 * 在删除与重新创建键的窗口中丢失分配事件，也不会破坏 Hash Map 遍历游标。
 */
static int print_interval(struct slab_rate_bpf *skel,
			  struct slab_sample *previous, int *previous_count,
			  struct slab_sample *current, struct slab_row *rows,
			  int ncpus, size_t value_stride, void *percpu_values,
			  bpf_u64_t interval_ns, bpf_s32_t target_pid)
{
	char cache_name[CACHE_NAME_SIZE + 32];  /* 格式化后的缓存名称或大小类 */
	char alloc_rate[24];                    /* 分配速率字符串 */
	char byte_rate[24];                     /* 字节速率字符串 */
	char timestamp[16];                     /* 时间戳字符串 */
	double seconds = (double)interval_ns / 1000000000.0; /* 窗口时长（秒） */
	int current_count = 0;                 /* 当前快照条目数 */
	int row_count = 0;                     /* 有效行数（有分配增量的） */
	int map_fd;
	int err;

	if (seconds <= 0.0)
		return 0;                           /* 窗口时间为 0，跳过输出 */
	map_fd = bpf_map__fd(skel->maps.slab_entries); /* 获取 slab_entries map 的文件描述符 */
	/* 采集当前所有键的最新累计值到 current 数组 */
	err = collect_samples(map_fd, ncpus, value_stride, percpu_values,
			      current, &current_count);
	if (err)
		return err;

	/* 遍历当前快照，计算与上一次的差值，并构建行数据 */
	for (int i = 0; i < current_count; i++) {
		/* 查找该键在上一快照中的累计值 */
		const struct SlabRate_info *old =
			find_previous(previous, *previous_count, &current[i].key);
		bpf_u64_t old_count = old ? old->count : 0;
		bpf_u64_t old_bytes = old ? old->allocated_bytes : 0;

		/* 计数理论上只增不减；防御 Map 被外部重建或 64 位回绕。 */
		if (current[i].total.count < old_count ||
		    current[i].total.allocated_bytes < old_bytes)
			continue;
		/* 填充行数据 */
		rows[row_count].key = current[i].key;
		rows[row_count].count_delta = current[i].total.count - old_count;
		rows[row_count].bytes_delta =
			current[i].total.allocated_bytes - old_bytes;
		/* 如果分配次数增量为 0，跳过（可能只释放了，但代码不做释放统计） */
		if (!rows[row_count].count_delta)
			continue;
		/* 计算速率 */
		rows[row_count].allocs_per_sec =
			(double)rows[row_count].count_delta / seconds;
		rows[row_count].bytes_per_sec =
			(double)rows[row_count].bytes_delta / seconds;
		row_count++;
	}

	/* 按字节速率降序排序 */
	qsort(rows, row_count, sizeof(*rows), sort_by_bytes_rate);
	/* 输出时间戳和标题头 */
	log_ts(timestamp, sizeof(timestamp));
	log_output_lock();   /* 获取输出锁，保证多线程不交错 */
	printf("\n" C_CYAN C_BOLD "[%s] slab 分配速率  窗口=%.1f ms  PID=",
	       timestamp, seconds * 1000.0);
	if (target_pid)
		printf("%d\n" C_RESET, target_pid);
	else
		printf("ALL\n" C_RESET);
	printf("%-40s %12s %14s %10s\n",
	       "CACHE / SIZE CLASS", "ALLOCS/s", "BYTES/s", "AVG SIZE");

	/* 只显示前 OUTPUT_ROWS 条，不超过实际行数 */
	int show = row_count < OUTPUT_ROWS ? row_count : OUTPUT_ROWS;
	for (int i = 0; i < show; i++) {
		bpf_u64_t average = rows[i].bytes_delta / rows[i].count_delta; /* 平均每次分配字节数 */

		format_cache_name(&rows[i].key, cache_name, sizeof(cache_name));
		format_alloc_rate(rows[i].allocs_per_sec, alloc_rate, sizeof(alloc_rate));
		format_byte_rate(rows[i].bytes_per_sec, byte_rate, sizeof(byte_rate));
		printf("%-40s %12s %14s %8" PRIu64 " B\n",
		       cache_name, alloc_rate, byte_rate, average);
	}
	if (!row_count)
		printf("  （本窗口没有匹配的 slab 分配）\n");
	printf("  注：这是分配吞吐，不是当前 slab 占用量；未跟踪释放。\n");
	log_output_unlock();

	/* 将当前快照保存为“上一快照”，供下次窗口使用 */
	memcpy(previous, current, (size_t)current_count * sizeof(*current));
	*previous_count = current_count;
	return 0;
}

/*
 * 打印采集器自身统计信息（events_seen、alloc_failed 等），从 stats_map 聚合所有 CPU 副本。
 */
static void print_stats(struct slab_rate_bpf *skel, int ncpus)
{
	struct SlabRate_stats total = {};         /* 汇总全部 CPU 的统计值 */
	bpf_u32_t key = 0;                        /* stats_map 只用下标 0 */
	/* 计算对齐后的 stats value 大小，用于分配 per-CPU 缓冲区 */
	size_t stats_stride = (sizeof(struct SlabRate_stats) + 7U) & ~7U;
	void *stats_values;

	/* stats value 按 8 字节对齐后，为所有 possible CPU 分配读取缓冲区。 */
	stats_values = calloc((size_t)ncpus, stats_stride);
	if (!stats_values)
		return;
	/* 读取 per-CPU 数组的一个元素（索引 0），得到所有 CPU 的副本连续存放的缓冲区 */
	if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats_map), &key,
				stats_values)) {
		free(stats_values);
		return;
	}
	/* 遍历所有 CPU，累加各统计字段 */
	for (int cpu = 0; cpu < ncpus; cpu++) {
		const struct SlabRate_stats *value =
			(const void *)((char *)stats_values + (size_t)cpu * stats_stride);

		total.events_seen += value->events_seen;
		total.alloc_failed += value->alloc_failed;
		total.filtered_pid += value->filtered_pid;
		total.map_update_failed += value->map_update_failed;
		total.name_read_failed += value->name_read_failed;
		total.size_fallback += value->size_fallback;
	}
	free(stats_values);

	log_output_lock();
	printf("\n" C_CYAN C_BOLD "══════ Slab Rate 统计 ══════\n" C_RESET);
	printf("  观察事件: %" PRIu64 "  分配失败: %" PRIu64
	       "  PID过滤: %" PRIu64 "\n",
	       total.events_seen, total.alloc_failed, total.filtered_pid);
	printf("  健康: map_fail=%" PRIu64 " name_read_fail=%" PRIu64 "\n",
	       total.map_update_failed, total.name_read_failed);
	if (total.size_fallback)
		printf("  兼容模式: %" PRIu64
		       " 次具名 cache 分配按大小档位聚合（旧内核无 cache 指针）\n",
		       total.size_fallback);
	printf(C_CYAN C_BOLD "═════════════════════════════\n" C_RESET);
	log_output_unlock();
}

/*
 * 主运行函数：初始化、加载 BPF、进入采样循环、退出时打印统计。
 * 参数：
 *   poll_timeout_ms 轮询间隔（毫秒），控制采样窗口大小
 *   enable          是否启用采集
 *   target_pid      过滤的目标 PID（0 表示全部）
 *   min_delay_ns    延迟相关参数（slab_rate 不适用，仅打印提示）
 */
int slab_rate_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid,
		  bpf_u64_t min_delay_ns)
{
	struct slab_sample *previous = NULL;   /* 上一次采样快照 */
	struct slab_sample *current = NULL;    /* 当前采样快照 */
	struct slab_row *rows = NULL;          /* 排序行数组 */
	struct slab_rate_bpf *skel = NULL;     /* BPF skeleton 对象 */
	struct bpf_link *cache_node_link = NULL; /* 可选 kmem_cache_alloc_node 挂载链接 */
	struct bpf_link *kmalloc_node_link = NULL;/* 可选 kmalloc_node 挂载链接 */
	struct SlabRate_ctrl ctrl = {};         /* 控制参数，下发给 BPF */
	struct timespec window_start;           /* 窗口起始时间 */
	struct timespec window_end;             /* 窗口结束时间 */
	void *percpu_values = NULL;             /* 读取 PERCPU_HASH 用的缓冲区 */
	size_t value_stride;                    /* 对齐后单个 CPU value 的大小 */
	bpf_u32_t key = 0;                      /* 写入 ctrl_map 的下标 */
	int previous_count = 0;                 /* 上一次快照条目数 */
	int ncpus;                              /* 系统 possible CPU 数量 */
	int err;

	/* 获取当前进程的 PID 命名空间标识（dev 和 inode），用于容器内 PID 转换 */
	err = app_get_pid_namespace(&ctrl.pid_ns_dev, &ctrl.pid_ns_ino);
	if (err) {
		fprintf(stderr, "slab_rate: 读取 PID namespace 失败: %s\n",
			strerror(-err));
		return 1;
	}
	ctrl.enable = enable;            /* 设置采集开关 */
	ctrl.target_pid = target_pid;    /* 设置 PID 过滤值 */

	ncpus = libbpf_num_possible_cpus(); /* 获取内核的 possible CPU 数量 */
	if (ncpus <= 0) {
		fprintf(stderr, "slab_rate: 无法获取 possible CPU 数量\n");
		return 1;
	}
	/* 计算 SlabRate_info 对齐到 8 字节后的大小，作为 per-CPU 值步长 */
	value_stride = (sizeof(struct SlabRate_info) + 7U) & ~7U;
	/* 分配快照数组，最大可能条目数为 map 最大容量 */
	previous = calloc(SLAB_RATE_MAX_ENTRIES, sizeof(*previous));
	current = calloc(SLAB_RATE_MAX_ENTRIES, sizeof(*current));
	rows = calloc(SLAB_RATE_MAX_ENTRIES, sizeof(*rows));
	/* 分配 per-CPU 值的读取缓冲区：cpu 数量 × 对齐后 value 大小 */
	percpu_values = calloc((size_t)ncpus, value_stride);
	if (!previous || !current || !rows || !percpu_values) {
		fprintf(stderr, "slab_rate: 分配用户态快照缓冲区失败\n");
		err = -ENOMEM;
		goto cleanup;
	}

	/* 打开 BPF skeleton，加载 BPF 程序到内核 */
	skel = slab_rate_bpf__open();
	if (!skel) {
		fprintf(stderr, "slab_rate: 打开 BPF 程序失败\n");
		err = -EINVAL;
		goto cleanup;
	}
	/*
	 * *_node 事件只存在于旧内核。禁止 skeleton 自动 attach，待主程序挂载
	 * 后手动尝试；事件不存在返回 ENOENT 时视为正常的新内核行为。
	 */
	bpf_program__set_autoattach(skel->progs.handle_kmem_cache_alloc_node, false);
	bpf_program__set_autoattach(skel->progs.handle_kmalloc_node, false);
	/* 加载 BPF 程序及 maps 到内核，并进行校验 */
	err = slab_rate_bpf__load(skel);
	if (err) {
		fprintf(stderr, "slab_rate: 加载 BPF 程序失败: %s\n", strerror(-err));
		goto cleanup;
	}
	/* 将控制参数写入 ctrl_map[0]，供 BPF 端读取 */
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err) {
		fprintf(stderr, "slab_rate: 更新 ctrl_map 失败: %s\n",
			strerror(-err));
		goto cleanup;
	}
	/* 挂载主 tracepoint (kmem_cache_alloc 和 kmem/kmalloc) */
	err = slab_rate_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "slab_rate: 挂载 slab tracepoint 失败: %s\n",
			strerror(-err));
		goto cleanup;
	}

	/* 手动挂载可选的 raw_tp/kmem_cache_alloc_node */
	err = attach_optional_raw_tracepoint(
		skel->progs.handle_kmem_cache_alloc_node, "kmem_cache_alloc_node",
		&cache_node_link);
	if (err) {
		fprintf(stderr, "slab_rate: 挂载可选 kmem_cache_alloc_node 失败: %s\n",
			strerror(-err));
		goto cleanup;
	}
	/* 手动挂载可选的 raw_tp/kmalloc_node */
	err = attach_optional_raw_tracepoint(
		skel->progs.handle_kmalloc_node, "kmalloc_node", &kmalloc_node_link);
	if (err) {
		fprintf(stderr, "slab_rate: 挂载可选 kmalloc_node 失败: %s\n",
			strerror(-err));
		goto cleanup;
	}
	err = 0;

	/* 输出启动横幅，加锁保证原子输出 */
	log_output_lock();
	log_banner("Slab allocation rate", enable);
	if (target_pid)
		LOG("过滤 current PID=%d（表示分配执行上下文，不表示对象所有者）\n",
		    target_pid);
	if (min_delay_ns)
		LOG("提示: slab_rate 没有延迟指标，忽略 -d=%" PRIu64 " ns\n",
		    min_delay_ns);
	log_output_unlock();

	/* 记录第一个窗口的起始时间 */
	clock_gettime(CLOCK_MONOTONIC, &window_start);
	err = 0;
	/* 主循环：每隔 poll_timeout_ms 毫秒输出一次速率 */
	while (!app_should_exit()) {
		/* poll(NULL, 0, ms) 支持毫秒窗口，并可被退出信号及时中断。 */
		int wait_err = poll(NULL, 0, poll_timeout_ms);

		if (wait_err < 0 && errno != EINTR) {
			err = -errno;   /* poll 出错（非信号中断） */
			break;
		}
		if (app_should_exit())
			break;
		/* 获取当前时间作为窗口结束 */
		clock_gettime(CLOCK_MONOTONIC, &window_end);
		/* 计算差值并输出 */
		err = print_interval(skel, previous, &previous_count, current, rows,
				     ncpus, value_stride, percpu_values,
				     elapsed_ns(&window_start, &window_end), target_pid);
		if (err)
			break;
		/* 下一窗口起始 = 当前窗口结束 */
		window_start = window_end;
	}

	/* 程序退出前打印采集器内部统计 */
	print_stats(skel, ncpus);

cleanup:
	/* 销毁可选 tracepoint 的链接 */
	bpf_link__destroy(kmalloc_node_link);
	bpf_link__destroy(cache_node_link);
	/* 销毁 skeleton，自动 detach 和清理 */
	slab_rate_bpf__destroy(skel);
	/* 释放动态分配的缓冲区 */
	free(percpu_values);
	free(rows);
	free(current);
	free(previous);
	/* 返回 0 表示成功，失败则返回正错误码 */
	return err < 0 ? -err : err;
}