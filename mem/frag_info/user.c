#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common/cli.h"
#include "common/types.h"
#include "frag_info.h"
#include "frag_info.h"
#include "mem/frag_info/skel.h"
#include "common/logger.h"

// 排序回调：用于order_entry数组排序，先按zone地址、再按页order升序
static int compare_entries(const void *a, const void *b);
// 碎片评分A：衡量当前order下内存碎片化严重程度，数值越大碎片越严重
static int __fragmentation_index(unsigned int order, unsigned long total,
				 unsigned long suitable, unsigned long free);
// 碎片评分B：不可用空闲占比（当前order规格下，无法凑出目标连续块的空闲内存比例）
static int unusable_free_index(unsigned int order, unsigned long total,
			       unsigned long suitable, unsigned long free);

// 组合存储结构：一条zone+order对应的主键 + 碎片统计数据
struct order_entry {
	struct order_zone okey;    // 复合key：zone指针 + order页阶
	struct ctg_info oinfo;     // 该key对应的空闲碎片统计指标
};

/**
 * 遍历并打印nodes哈希表：输出所有NUMA节点基础信息
 * @param fd nodes哈希map的文件描述符
 */
static void print_nodes(int fd)
{
	struct pgdat_info pinfo;
	__u64 key = 0, next_key;
	printf(" Node ID          PGDAT_PTR       NR_ZONES \n");
	// 遍历hash表所有key：从key=0开始，循环获取下一个有效key
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		// 根据key读取对应NUMA节点信息
		bpf_map_lookup_elem(fd, &next_key, &pinfo);
		printf(" %5d       0x%llx  %5d\n", pinfo.node_id, pinfo.pgdat_ptr, pinfo.nr_zones);
		key = next_key;
	}
}

/**
 * 遍历并打印zones哈希表：输出所有内存域zone基础元数据
 * @param fd zones哈希map的文件描述符
 */
static void print_zones(int fd)
{
	struct zone_info zinfo;
	__u64 key = 0, next_key;
	printf("%-20s %-20s %-25s %-20s %-20s\n", " COMM", "ZONE_PTR", "ZONE_PFN", "SUM_PAGES", "FACT_PAGES");
	// 循环遍历全部zone条目
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &zinfo);
		// 打印zone名称、内核地址、起始物理页号、总跨度页数、实际有效页数
		printf(" %-15s 0x%-25llx %-25llu %-20llu %-15llu\n",
		       zinfo.comm, zinfo.zone_ptr, zinfo.zone_start_pfn,
		       zinfo.spanned_pages, zinfo.present_pages);
		key = next_key;
	}
}

/**
 * 遍历orders哈希表，读取所有zone+order碎片数据，排序后格式化打印
 * @param fd orders复合键哈希map文件描述符
 */
static void print_orders(int fd)
{
	struct order_zone okey = {};
	struct ctg_info oinfo;
	// 临时数组缓存所有统计条目，最多容纳256组zone+order数据
	struct order_entry entries[256];
	int entry_count = 0;

	// 第一步：遍历整张orders哈希表，把所有数据读到本地数组缓存
	while (bpf_map_get_next_key(fd, &okey, &okey) == 0) {
		if (bpf_map_lookup_elem(fd, &okey, &oinfo) == 0) {
			entries[entry_count].okey = okey;
			entries[entry_count].oinfo = oinfo;
			entry_count++;
		}
	}

	// 按自定义规则排序：先zone地址从小到大，同zone再按order从小到大
	qsort(entries, entry_count, sizeof(struct order_entry), compare_entries);
	// 打印表头：基础指标 + 两个碎片打分
	printf(" Order     Zone_PTR                Free Pages         Free Blocks Total    Free Blocks Suitable      SCOREA     SCOREB\n");
	for (int i = 0; i < entry_count; i++) {
		// 计算碎片打分A：碎片化指数
		int res = __fragmentation_index(entries[i].okey.order,
			entries[i].oinfo.free_blocks_total, entries[i].oinfo.free_blocks_suitable,
			entries[i].oinfo.free_pages);
		// 计算碎片打分B：不可用空闲占比，放大1000倍存整数
		int tmp = unusable_free_index(entries[i].okey.order,
			entries[i].oinfo.free_blocks_total, entries[i].oinfo.free_blocks_suitable,
			entries[i].oinfo.free_pages);
		// 拆分整数为 整数部分.小数部分（保留3位）
		int part2 = tmp / 1000, dec2 = tmp % 1000;
		// 输出一行完整统计
		printf(" %-8u 0x%-25llx %-20lu %-20lu %-20lu %d   %d.%03d\n",
		       entries[i].okey.order, entries[i].okey.zone_ptr, entries[i].oinfo.free_pages,
		       entries[i].oinfo.free_blocks_total, entries[i].oinfo.free_blocks_suitable,
		       res, part2, dec2);
	}
}

/**
 * frag_info工具主运行入口，对应头文件声明 int frag_info_run()
 * @param poll_timeout_ms 预留参数（当前代码未使用）
 * @param enable 采集总开关（预留参数，当前未做开关控制逻辑）
 * @return 0正常退出，非0异常错误码
 */
int frag_info_run(int poll_timeout_ms, bool enable)
{
	// libbpf自动生成的BPF骨架对象，管理ebpf字节码、map、探针挂载
	struct frag_info_bpf *skel = NULL;
	int err = 0;

	// 入参预留占位，当前版本未实现开关/超时控制逻辑
	(void)poll_timeout_ms;
	(void)enable;

	// 1. 打开并加载BPF字节码到内核
	skel = frag_info_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "Failed FragInfo\n"); return 1; }

	// 2. 挂载kprobe钩子 get_page_from_freelist
	err = frag_info_bpf__attach(skel);
	if (err) { fprintf(stderr, "Attach fail\n"); goto cleanup; }

	// 主循环：程序持续运行，每秒打印一版全量内存碎片快照
	while (!app_should_exit()) {
		sleep(1);
		// 打印NUMA节点列表
		print_nodes(bpf_map__fd(skel->maps.nodes));
		printf("\n");
		// 打印所有zone基础信息
		print_zones(bpf_map__fd(skel->maps.zones));
		printf("\n");
		// 打印各zone各阶空闲碎片统计+碎片打分
		print_orders(bpf_map__fd(skel->maps.orders));
		printf("\n");
	}

cleanup:
	// 资源释放：卸载BPF、销毁骨架、释放内核map资源
	frag_info_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}

/**
 * qsort排序比较函数
 * 排序优先级：
 * 1. 先按zone内核虚拟地址升序，不同zone分开
 * 2. 同一zone内，按order页阶从小到大排序（0~MAX_ORDER）
 */
static int compare_entries(const void *a, const void *b)
{
	struct order_entry *ea = (struct order_entry *)a, *eb = (struct order_entry *)b;
	if (ea->okey.zone_ptr != eb->okey.zone_ptr)
		return (ea->okey.zone_ptr < eb->okey.zone_ptr) ? -1 : 1;
	return (ea->okey.order < eb->okey.order) ? -1 : 1;
}

/**
 * 碎片打分SCOREA：碎片化严重程度指数
 * 逻辑：当不存在能满足当前order的大块空闲时，计算平均每块空闲能提供多少份目标连续内存
 * 返回值：
 * -1000：存在足够大块空闲，碎片风险极低
 * 正数：数值越大，碎片越严重，空闲内存全是碎小块
 */
static int __fragmentation_index(unsigned int order, unsigned long total,
				 unsigned long suitable, unsigned long free)
{
	// 非法阶数 / 无任何空闲块，直接返回0
	if (order > MAX_ORDER || !total) return 0;
	// 存在可用大块，标记碎片风险极低，固定返回-1000
	if (suitable) return -1000;
	// 目标单块需要的页数 2^order
	unsigned long requested = 1UL << order;
	// 总空闲页数 *1000 / 单块需求页数 / 总空闲块数
	// 放大1000转为整数，避免浮点精度丢失
	double res1 = (double)(free * 1000ULL) / requested;
	return (int)(res1 / total);
}

/**
 * 碎片打分SCOREB：不可用空闲内存占比（放大1000倍整数）
 * 含义：当前zone内，总空闲内存中，无法拼接出目标order连续块的内存占比
 * 返回值范围 0~1000：数值越大，无效碎内存占比越高
 */
static int unusable_free_index(unsigned int order, unsigned long total,
			       unsigned long suitable, unsigned long free)
{
	// 无空闲内存，全部不可用，返回1000（100%）
	if (free == 0) return 1000;
	// suitable << order：等效可分配出的目标规格总页数
	unsigned long usable_pages = suitable << order;
	// 总空闲页 - 可用连续页 = 零散无效碎页
	unsigned long res1 = free - usable_pages;
	// 碎页 / 总空闲页 *1000，转为千分比整数
	return (int)((res1 * 1000ULL) / free);
}
