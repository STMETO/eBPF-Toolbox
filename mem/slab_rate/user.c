#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common/cli.h"
#include "common/types.h"
#include "slab_rate.h"
#include "slab_rate.h"
#include "mem/slab_rate/skel.h"
#include "common/logger.h"

// 每次刷新只展示占用内存TOP20的slab缓存
#define OUTPUT_ROWS 20

/**
 * qsort 排序回调函数：按累计分配总字节 size 降序排序
 * @param a 数组前一个元素指针
 * @param b 数组后一个元素指针
 * @return 正数交换、负数不交换、0相等
 */
static int sort_by_size(const void *a, const void *b)
{
	struct SlabRate_info *sa = (struct SlabRate_info *)a;
	struct SlabRate_info *sb = (struct SlabRate_info *)b;
	// sb.size更大则返回1，实现从大到小排序
	return (sb->size > sa->size) ? 1 : ((sb->size < sa->size) ? -1 : 0);
}

/**
 * 读取内核hash表、排序并打印slab统计结果
 * @param skel BPF骨架对象，用于获取slab_entries map fd
 * @return 0成功，负数系统错误码失败
 */
static int print_stat(struct slab_rate_bpf *skel)
{
	// 本地缓存数组，最大容纳内核hash全部10240条记录
	static struct SlabRate_info values[10240];
	// hash表key：slab缓存名字符串指针
	char *key = NULL, **prev_key = NULL;
	// 获取内核slab_entries哈希表文件描述符
	int fd = bpf_map__fd(skel->maps.slab_entries);
	int rows = 0, err = 0;

	// 打印输出表头
	printf("%-32s %8s %12s\n", "CACHE", "ALLOCS", "BYTES");

	// 第一轮遍历：读取hash表所有条目存入本地数组
	while (1) {
		// 从上一个key位置查找下一个hash键
		err = bpf_map_get_next_key(fd, prev_key, &key);
		// ENOENT：无更多key，遍历完成退出循环
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			return err;
		}
		// 根据key读取对应的slab统计数据
		err = bpf_map_lookup_elem(fd, &key, &values[rows++]);
		if (err)
			return err;
		// 更新上一次key指针，作为下一轮遍历起点
		prev_key = &key;
		// 达到数组最大容量，停止读取
		if (rows >= 10240)
			break;
	}

	// 将读取到的slab数据按总分配字节降序排序
	qsort(values, rows, sizeof(struct SlabRate_info), sort_by_size);
	// 实际展示行数：不足20条全展示，超过只展示TOP20
	int show = rows < OUTPUT_ROWS ? rows : OUTPUT_ROWS;
	// 循环打印TOP N slab缓存统计
	for (int i = 0; i < show; i++)
		printf("%-32s %8" PRIu64 " %12" PRIu64 "\n", values[i].name, values[i].count, values[i].size);
	printf("\n");

	// --------------------------
	// 清空内核hash表，实现增量统计
	// 本轮统计完成后删除所有条目，下一轮只统计新产生的分配事件
	// --------------------------
	prev_key = NULL;
	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, &key);
		// 无更多key，删除完成
		if (err)
			break;
		// 删除当前遍历到的hash条目
		err = bpf_map_delete_elem(fd, &key);
		if (err)
			return err;
		prev_key = &key;
	}
	return 0;
}

/**
 * slab分配统计主运行入口
 * @param poll_timeout_ms 刷新间隔毫秒数，内部转为sleep秒级休眠
 * @param enable true开启内核slab采集，false关闭
 * @return 0正常退出，正数/负数代表错误
 */
int slab_rate_run(int poll_timeout_ms, bool enable)
{
	struct slab_rate_bpf *skel = NULL;
	// 下发到ctrl_map的采集开关配置
	struct SlabRate_ctrl ctrl = { .enable = enable };
	// 控制数组MAP固定key=0
	const int key = 0;
	int err = 0;

	// 1. 打开BPF字节码并加载到内核，自动创建ctrl_map、slab_entries
	skel = slab_rate_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed SlabRate BPF skeleton open&load\n");
		return 1;
	}

	// 2. 更新控制MAP，下发采集开关给内核BPF探针
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Update ctrl_map failed\n");
		goto cleanup;
	}

	// 3. 将kprobe挂载到内核 kmem_cache_alloc 函数，开始捕获slab分配
	err = slab_rate_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "BPF kprobe attach failed\n");
		goto cleanup;
	}

	// 主循环：持续刷新打印slab统计，直到收到退出信号(Ctrl+C)
	while (!app_should_exit()) {
		// 休眠：超过1000ms按秒休眠，不足1s固定休眠1s
		sleep(poll_timeout_ms > 1000 ? poll_timeout_ms / 1000 : 1);
		// 清屏，刷新界面
		system("clear");
		// 读取、排序、打印当前slab分配统计
		err = print_stat(skel);
		if (err)
			break;
	}

cleanup:
	// 统一资源回收：卸载kprobe、销毁内核MAP、释放骨架内存
	slab_rate_bpf__destroy(skel);
	// 错误码转正后返回上层调用
	return err < 0 ? -err : 0;
}
