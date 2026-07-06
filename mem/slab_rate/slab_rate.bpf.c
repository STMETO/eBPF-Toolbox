/*
 * eBPF内核探针程序：内核Slab分配统计采集器
 * 挂载点：kprobe/kmem_cache_alloc，捕获所有内核slab内存分配行为
 * 核心能力：
 * 1. 提供全局开关ctrl_map，用户态下发enable控制采集启停，关闭时无性能损耗；
 * 2. 使用HASH表slab_entries，以slab缓存名称指针为key，聚合统计每类缓存；
 * 3. 每条分配事件累加对应缓存的分配次数count、累计分配总字节size；
 * 4. 自动新建未出现过的slab缓存条目，拷贝缓存名称存入结构体供用户态展示；
 * 数据输出：HASH表存储周期增量数据，由用户态定时遍历读取、清空；
 * 适用场景：排查内核高频内存分配、内核slab内存热点、内核内存泄漏；
 * 局限：仅捕获内存分配，未监控释放，无法计算当前存活内核内存；
 * 许可证：Dual BSD/GPL，允许使用kprobe追踪内核函数。
 */


#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "slab_rate.h"

#define MAX_ENTRIES 10240

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 控制MAP固定查询key
const int ctrl_key = 0;

/**
 * 控制MAP：全局采集开关
 * 类型：数组MAP，仅1个元素
 * key固定0，value存储采集启停开关 SlabRate_ctrl
 * 用户态写入enable标记，内核探针读取判断是否采集
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct SlabRate_ctrl);
} ctrl_map SEC(".maps");

// 全局零值模板，用于新建hash条目时初始化
static struct SlabRate_info zero_value = {};

/**
 * Slab统计哈希表
 * key：slab缓存名称字符串指针 const char*
 * value：该slab缓存的分配计数、总分配字节大小、缓存名
 * 作用：统计每种kmalloc/slab缓存的分配次数与总分配内存
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, char *);
	__type(value, struct SlabRate_info);
} slab_entries SEC(".maps");

/**
 * 内联工具函数：获取全局采集控制开关
 * @return 指向ctrl_map的控制结构体指针，空代表未初始化
 */
static __always_inline struct SlabRate_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
}

/**
 * 公共采集逻辑函数，kmem_cache_alloc探针共用
 * @param cachep 当前分配使用的slab缓存结构体指针
 * @return 0 正常返回
 */
static int probe_entry(struct kmem_cache *cachep)
{
	// 获取全局开关，未开启采集直接退出
	struct SlabRate_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	struct SlabRate_info *vp;
	// CO-RE读取slab缓存名称字符串指针
	const char *name = BPF_CORE_READ(cachep, name);

	// 根据缓存名指针查询hash表，查看是否已有统计记录
	vp = bpf_map_lookup_elem(&slab_entries, &name);
	if (!vp) {
		// hash中无该缓存条目，插入一条零初始化记录
		bpf_map_update_elem(&slab_entries, &name, &zero_value, BPF_ANY);
		// 再次查询获取新建条目指针
		vp = bpf_map_lookup_elem(&slab_entries, &name);
		// 创建失败直接返回，丢弃本次统计
		if (!vp)
			return 0;
		// 从内核空间读取缓存名称，拷贝到value的name数组中
		bpf_probe_read_kernel(&vp->name, sizeof(vp->name), name);
	}

	// 分配次数+1
	vp->count++;
	// 累加本次slab缓存单块大小，累计总分配内存
	vp->size += BPF_CORE_READ(cachep, size);
	return 0;
}

/**
 * kprobe挂载点：内核 kmem_cache_alloc
 * 触发时机：内核slab分配内存时（kmalloc/kzalloc底层统一调用）
 * 参数 cachep：本次分配使用的slab缓存对象
 * 功能：进入公共统计逻辑，累加该slab缓存分配计数与总内存
 */
SEC("kprobe/kmem_cache_alloc")
int BPF_KPROBE(kmem_cache_alloc, struct kmem_cache *cachep)
{
	return probe_entry(cachep);
}
