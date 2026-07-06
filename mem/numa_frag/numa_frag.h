#ifndef __FRAG_INFO_H
#define __FRAG_INFO_H
#include "common/types.h"

// 内核最大页阶，Linux内存管理默认MAX_ORDER=10，对应2^10=1024连续物理页
#define MAX_ORDER 10

// 统一64位无符号整数类型，适配BPF内核态与用户态跨层兼容
typedef bpf_u64_t u64;

/**
 * @struct order_zone
 * @brief 页阶+zone指针二元结构体，用于哈希map复合key存储
 * @param order 内存分配阶数，代表2^order个连续物理页
 * @param zone_ptr 内核struct zone虚拟地址指针，唯一标识一个内存zone
 */
struct order_zone {
	unsigned int order;
	u64 zone_ptr;
};

/**
 * @struct ctg_info
 * @brief 内存碎片统计核心数据结构，描述某一zone某一阶的空闲块分布
 * @param free_pages 该阶所有空闲页总数量（块数 × 2^order）
 * @param free_blocks_total 当前zone当前阶全部空闲连续内存块总数
 * @param free_blocks_suitable 满足分配掩码、可用于业务分配的空闲块数量
 */
struct ctg_info {
	unsigned long free_pages;
	unsigned long free_blocks_total;
	unsigned long free_blocks_suitable;
};

/**
 * @struct zone_info
 * @brief 单个内存域zone基础信息结构体，kprobe采集zone基础元数据
 * @param zone_ptr 内核struct zone虚拟地址，唯一标识zone
 * @param zone_start_pfn zone起始物理页帧号
 * @param spanned_pages zone覆盖的总物理页数量
 * @param present_pages zone内有效可用物理页（剔除预留/空洞页）
 * @param comm 触发内存分配的进程名称，用于定位内存泄漏/碎片来源进程
 * @param order 当前内存分配使用的页阶
 */
struct zone_info {
	u64 zone_ptr;
	u64 zone_start_pfn;
	u64 spanned_pages;
	u64 present_pages;
	char comm[32];
	unsigned int order;
};

/**
 * @struct pgdat_info
 * @brief NUMA节点pgdat元数据结构体，kprobe捕获get_page_from_freelist时的NUMA节点信息
 * @param pgdat_ptr 内核pglist_data结构体虚拟地址，唯一标识NUMA节点
 * @param nr_zones 当前NUMA节点包含的内存域数量（DMA/DMA32/NORMAL/MOVABLE等）
 * @param node_id NUMA节点编号，多核多内存架构区分不同物理内存节点
 */
struct pgdat_info {
	u64 pgdat_ptr;
	int nr_zones;
	int node_id;
};

/**
 * @struct FragInfo_ctrl
 * @brief BPF控制MAP存储结构体，用户态下发开关控制ebpf采集启停
 * @param enable 布尔开关，true开启内存碎片采集，false停止采集
 */
struct FragInfo_ctrl { bpf_bool_t enable; };

/* 用户态对外接口声明，仅用户程序可见，BPF内核态跳过该段 */
#ifndef __BPF__
#include <stdbool.h>
/**
 * @brief NUMA内存碎片采集主入口函数
 * @param poll_timeout_ms 碎片数据读取超时时间，单位毫秒
 * @param enable 采集总开关，true启动ebpf探针，false卸载探针停止采集
 * @return int 0成功，负数为错误码（探针加载失败、map创建失败、读取超时等）
 */
int numa_frag_info_run(int poll_timeout_ms, bool enable);
#endif

#endif
