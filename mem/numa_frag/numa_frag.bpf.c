/*
	统计 NUMA 节点内存碎片
	半成品
*/

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "numa_frag.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 全局常量：ctrl_map固定key，仅存储单条控制配置
const int ctrl_key = 0;

/**
 * @map ctrl_map
 * @type BPF_MAP_TYPE_ARRAY 定长数组map，固定1个元素，用于全局开关控制
 * @max_entries 仅1项，存储全局采集开关
 * @key 数组下标int，固定使用ctrl_key=0访问
 * @value FragInfo_ctrl 采集启停控制结构体，用户态下发开关
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct FragInfo_ctrl);
} ctrl_map SEC(".maps");

/**
 * @brief 内联工具函数：快速获取全局采集控制配置
 * @return 成功返回FragInfo_ctrl指针，空指针代表未初始化/未下发配置
 */
static __always_inline struct FragInfo_ctrl *get_ctrl(void)
{ 
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key); 
}

/**
 * @map nodes
 * @type BPF_MAP_TYPE_HASH 哈希表，存储所有触发分配的NUMA节点元数据
 * @max_entries 最大存储102400个节点，足够覆盖多NUMA服务器场景
 * @key u64 pglist_data结构体虚拟地址，作为节点唯一主键
 * @value pgdat_info NUMA节点基础信息（节点ID、zone数量、pgdat指针）
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 102400);
	__type(key, u64);
	__type(value, struct pgdat_info);
} nodes SEC(".maps");

/**
 * @kprobe get_page_from_freelist
 * 挂载内核页分配核心函数钩子，捕获物理内存分配事件
 * 函数入参对应内核原型：
 * gfp_mask: 内存分配掩码（可分配zone、回收策略、迁移类型）
 * order: 分配页阶，2^order连续物理页
 * alloc_flags: 分配额外控制标志
 * ac: 分配上下文，包含首选zone、NUMA节点、分配约束
 */
SEC("kprobe/get_page_from_freelist")
int BPF_KPROBE(get_page_from_freelist, gfp_t gfp_mask, unsigned int order, int alloc_flags,
	       const struct alloc_context *ac)
{
	// 初始化NUMA节点信息缓存结构体
	struct pgdat_info node_info = {};
	struct pglist_data *pgdat;

	// CORE安全读取：从分配上下文获取首选zone，再拿到zone归属的NUMA pgdat
	pgdat = BPF_CORE_READ(ac, preferred_zoneref, zone, zone_pgdat);
	// 读取NUMA节点编号
	node_info.node_id = BPF_CORE_READ(pgdat, node_id);
	// 读取该NUMA节点下总zone数量
	node_info.nr_zones = BPF_CORE_READ(pgdat, nr_zones);
	// 保存pgdat内核虚拟地址作为唯一标识
	node_info.pgdat_ptr = (u64)pgdat;
	// 使用pgdat虚拟地址作为哈希map主键
	u64 key = (u64)pgdat;
    
	// BPF_NOEXIST：仅不存在时插入，避免重复覆盖同一NUMA节点信息，减少map写入开销
	bpf_map_update_elem(&nodes, &key, &node_info, BPF_NOEXIST);

	return 0;
}
