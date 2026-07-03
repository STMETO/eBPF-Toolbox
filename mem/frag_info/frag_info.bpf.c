/*
本 eBPF 模块基于 kprobe 捕获内核物理页分配行为，实时采集系统 NUMA 节点、内存域（zone）及各阶连续空闲页分布信息，
统计不同页阶的空闲块数量与可分配连续内存容量，用于**监控系统物理内存碎片化状态、定位大页分配失败与内存规整问题。
*/

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "frag_info.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ctrl_map数组Map唯一下标
const int ctrl_key = 0;
/**
 * @brief 全局控制数组Map，存储采集开关enable
 * 类型：定长数组，仅1个元素
 * value：FragInfo_ctrl启停控制结构体
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct FragInfo_ctrl);
} ctrl_map SEC(".maps");

/**
 * @brief 内联工具函数：读取全局采集开关配置
 * @return 成功返回FragInfo_ctrl指针，失败NULL
 */
static __always_inline struct FragInfo_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
}

/**
 * @brief zones哈希表：存储所有zone内存域基础元数据快照
 * key：zone内核虚拟地址u64
 * value：zone_info zone完整基础信息
 * max_entries：最大缓存102400个zone节点，足够多NUMA多zone场景
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 102400);
	__type(key, u64);
	__type(value, struct zone_info);
} zones SEC(".maps");

/**
 * @brief nodes哈希表：存储所有NUMA内存节点pgdat信息
 * key：pgdat内核虚拟地址u64
 * value：pgdat_info NUMA节点信息
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 102400);
	__type(key, u64);
	__type(value, struct pgdat_info);
} nodes SEC(".maps");

/**
 * @brief orders复合键哈希表：按zone+order维度存储连续页碎片统计
 * key：order_zone 二元组合（zone指针+页阶order）
 * value：ctg_info 当前zone该阶数下连续空闲块统计
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 102400);
	__type(key, struct order_zone);
	__type(value, struct ctg_info);
} orders SEC(".maps");

/**
 * @brief 统计单个内存域zone的空闲内存碎片数据
 * @param zone 要统计的内存域对象
 * @param suitable_order 目标连续页阶，比如需要8页连续内存就传3
 * @param info 输出：统计好的碎片指标结果
 * 逻辑说明：
 * 1. 遍历当前zone所有大小的空闲内存块（1页、2页、4页…最大1024页）
 * 2. 累加统计三个关键指标：
 *    free_pages：当前zone全部空闲内存总页数
 *    free_blocks_total：空闲内存一共碎成了多少块，数字越大碎片越严重
 *    free_blocks_suitable：能拆分出多少份「suitable_order大小」的连续内存，
 *                           大块空闲内存可以拆分，所以会折算等效数量，数值越小越容易分配大内存失败
 */
 static void fill_contig_page_info(struct zone *zone, unsigned int suitable_order,
	struct contig_page_info *info)
{
	unsigned int order;
	// 先把统计数值清零，防止上次数据干扰
	info->free_pages = 0;
	info->free_blocks_total = 0;
	info->free_blocks_suitable = 0;

	// 循环遍历所有尺寸的空闲内存块，从1页到最大1024页
	for (order = 0; order <= MAX_ORDER; order++) {
		unsigned long blocks;
		unsigned long nr_free;
		// 读取当前尺寸空闲块一共有多少块
		nr_free = BPF_CORE_READ(&zone->free_area[order], nr_free);
		blocks = nr_free;

		// 累计：所有空闲块总数量
		info->free_blocks_total += blocks;
		// 累计：当前尺寸所有块加起来的总页数（块数 × 每块页数）
		info->free_pages += blocks << order;

		// 只有比目标尺寸更大/相等的空闲块，才能拆分出需要的连续内存
		// 一块大内存能拆成多份目标大小，折算等效可用块数量
		if (order >= suitable_order)
			info->free_blocks_suitable += blocks << (order - suitable_order);
	}
}


/**
 * @brief kprobe钩子：捕获内核页分配入口get_page_from_freelist
 * 触发时机：只要内核从伙伴系统空闲链表拿物理内存，就会执行这段采集逻辑
 * 功能：遍历当前NUMA节点全部内存域zone，批量计算每个zone各阶空闲碎片数据，存入BPF哈希表给用户态读取监控
 * @param gfp_mask 分配内存的类型标记（区分DMA/NORMAL/可迁移内存等）
 * @param order 本次业务申请内存需要的连续页阶（0=单页、3=8连续页）
 * @param alloc_flags 分配流程控制标记，内核内部使用
 * @param ac 分配上下文结构体，存着本次分配优先使用哪个zone、zonelist等核心信息
 */
 SEC("kprobe/get_page_from_freelist")
 int BPF_KPROBE(get_page_from_freelist, gfp_t gfp_mask, unsigned int order, int alloc_flags,
			const struct alloc_context *ac)
 {
	 // 临时存储NUMA节点信息、单个zone基础信息
	 struct pgdat_info node_info = {};
	 struct zone_info zone_data = {};
 
	 struct pglist_data *pgdat;  // NUMA节点内核结构体指针
	 struct zoneref *zref;       // zone引用对象，用来遍历节点下所有zone
	 struct zone *z;             // 单个内存域zone指针
	 int i;                      // zone循环下标
	 unsigned int a_order;       // 循环遍历所有页阶0~MAX_ORDER
 
	 // ========== 步骤1：获取本次内存分配对应的NUMA节点，存入nodes哈希表 ==========
	 // 从分配上下文拿到本次分配首选zone，再找到该zone所属的NUMA节点pgdat
	 pgdat = BPF_CORE_READ(ac, preferred_zoneref, zone, zone_pgdat);
	 // 提取NUMA节点基础信息：节点编号、节点下zone数量、节点内核地址
	 node_info.node_id = BPF_CORE_READ(pgdat, node_id);
	 node_info.nr_zones = BPF_CORE_READ(pgdat, nr_zones);
	 node_info.pgdat_ptr = (u64)pgdat;
	 u64 key = (u64)pgdat;
	 // 写入nodes哈希表缓存，用户态可以读取所有NUMA节点信息
	 bpf_map_update_elem(&nodes, &key, &node_info, BPF_ANY);
 
	 // ========== 步骤2：循环遍历当前NUMA节点下全部zone内存域 ==========
	 for (i = 0; i < __MAX_NR_ZONES; i++) {
		 // 取出节点zone列表里第i个zone引用
		 zref = &pgdat->node_zonelists[0]._zonerefs[i];
		 z = BPF_CORE_READ(zref, zone);
		 // 指针为空代表后面没有zone了，直接结束循环
		 if ((u64)z == 0) break;
 
		 // 填充当前zone的基础描述信息
		 zone_data.zone_ptr = (u64)z;
		 u64 zone_key = (u64)z;
		 zone_data.zone_start_pfn = BPF_CORE_READ(z, zone_start_pfn); // zone起始物理页号
		 zone_data.spanned_pages = BPF_CORE_READ(z, spanned_pages);   // zone整体占用总页数（含内存空洞）
		 zone_data.present_pages = BPF_CORE_READ(z, present_pages);   // zone实际可用有效页数
		 // 读取zone名字字符串，如 "NORMAL" "DMA"，方便用户态展示识别
		 bpf_probe_read_kernel_str(zone_data.comm, sizeof(zone_data.comm), BPF_CORE_READ(z, name));
 
		 // ========== 步骤3：遍历0~10所有页阶，计算该zone每种尺寸内存碎片统计 ==========
		 for (a_order = 0; a_order <= MAX_ORDER; ++a_order) {
			 zone_data.order = a_order;
			 // 组装复合主键：哪个zone + 哪个页阶，用来唯一定位一条碎片统计数据
			 struct order_zone order_key = {};
			 order_key.order = a_order;
			 if ((u64)z == 0) break;
			 order_key.zone_ptr = (u64)z;
 
			 // 调用之前的统计函数，计算当前zone、当前a_order对应的碎片三大指标
			 struct contig_page_info ctg_info = {};
			 fill_contig_page_info(z, a_order, &ctg_info);
			 // 把统计结果存入orders哈希表，供用户态读取展示碎片数据
			 bpf_map_update_elem(&orders,&order_key,&ctg_info,BPF_ANY);
		 }
		 // 将zone基础信息存入zones哈希表缓存
		 bpf_map_update_elem(&zones, &zone_key, &zone_data, BPF_ANY);
	 }
 
	 return 0;
 }
 