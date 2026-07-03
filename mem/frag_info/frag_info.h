#ifndef __FRAG_INFO_H
#define __FRAG_INFO_H
#include "common/types.h"

// Linux 内存页阶最大值，内核默认 MAX_ORDER=10，代表最大 2^10=1024 连续页块
#define MAX_ORDER 10

// 统一别名，简化内核64位无符号页计数/指针类型书写
typedef bpf_u64_t u64;

/**
 * @brief Hash表orders的复合key：zone内存域指针 + 页阶order二元组合键
 * @field order 内存块阶数 0~MAX_ORDER，2^order个连续物理页
 * @field zone_ptr struct zone内核虚拟地址，唯一标识一个内存域zone
 */
struct order_zone {
	unsigned int order;
	u64 zone_ptr;
};

/**
 * @brief 单个zone、单个order维度的连续空闲页统计信息
 * @field free_pages 该阶数及所有低阶空闲页总页数
 * @field free_blocks_total 当前zone全部阶数空闲块总数量
 * @field free_blocks_suitable 满足不小于当前order的可用连续块等效数量
 */
struct ctg_info {
	unsigned long free_pages;
	unsigned long free_blocks_total;
	unsigned long free_blocks_suitable;
};

/**
 * @brief 单个内存域zone基础元数据快照
 * @field zone_ptr 内核struct zone虚拟地址，作为zones哈希表key
 * @field zone_start_pfn 当前zone起始物理页帧号
 * @field spanned_pages zone覆盖总物理页数
 * @field present_pages zone中实际存在可用物理页数（排除空洞）
 * @field comm zone名称字符串（DMA/NORMAL/HIGHMEM等）
 * @field order 当前遍历的页阶0~MAX_ORDER
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
 * @brief 单个NUMA内存节点pgdat基础信息
 * @field pgdat_ptr struct pglist_data内核虚拟地址，nodes哈希表key
 * @field nr_zones 当前NUMA节点包含zone数量
 * @field node_id NUMA节点编号
 */
struct pgdat_info {
	u64 pgdat_ptr;
	int nr_zones;
	int node_id;
};

/**
 * @brief 全局监控总开关控制结构体
 * @field enable true开启内存碎片采集，false关闭采集
 */
struct FragInfo_ctrl { bpf_bool_t enable; };

/* 用户态编译时可见，BPF内核程序跳过此段 */
#ifndef __BPF__
#include <stdbool.h>
/**
 * @brief frag_info用户态主运行入口
 * @param poll_timeout_ms 环形缓冲区轮询超时毫秒
 * @param enable 全局采集开关
 * @return 0正常，非0异常错误码
 */
int frag_info_run(int poll_timeout_ms, bool enable);
#endif

#endif
