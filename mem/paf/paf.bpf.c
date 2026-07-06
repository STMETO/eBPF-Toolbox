
/**
 * paf.bpf.c - Page Alloc Freelist 内存水位监控eBPF探针
 * 功能：挂载内核页分配核心函数 get_page_from_freelist，每次物理内存分配时采集目标zone实时内存水位并上报用户态
 * 采集指标：zone三层生效水位(min/low/high，已叠加watermark_boost抬升偏移)、zone总有效页数、本次分配GFP掩码
 * 架构：
 *  1. ctrl_map：数组MAP存储采集开关enable，用户态控制探针启停
 *  2. rb：256KB环形缓冲区，低延迟流式推送水位事件至用户态
 *  缺陷说明：当前未采集zone指针、NUMA节点ID、zone类型标识，无法区分多zone/多NUMA节点来源；event内protection字段预留未赋值
 *  业务用途：提前识别内存回收压力、持续kswapd后台回收、水位击穿min阻塞分配、OOM前置预警
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "paf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ctrl_map 数组MAP固定索引，全局仅一条控制配置
const int ctrl_key = 0;

/**
 * @map ctrl_map
 * 类型：BPF_MAP_TYPE_ARRAY 定长数组，读写性能最优
 * max_entries=1：仅存储一条全局采集开关
 * key：数组下标int，固定使用 ctrl_key=0 访问
 * value：Paf_ctrl 采集启停控制结构体
 * 作用：用户态下发enable开关，控制水位采集探针启停
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Paf_ctrl);
} ctrl_map SEC(".maps");

/**
 * @map rb
 * 类型：BPF_MAP_TYPE_RINGBUF 环形缓冲区
 * 缓冲区大小 256KB，用于内核向用户态实时推送内存水位事件
 * 流式低延迟输出，相比哈希表轮询CPU开销更低
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
 * @brief 内联工具函数，快速读取全局采集开关配置
 * @return 成功返回Paf_ctrl指针，空指针代表未下发控制配置
 */
static __always_inline struct Paf_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
}

/**
 * @kprobe get_page_from_freelist
 * 挂载内核物理页分配核心函数，每次从空闲页列表分配内存时触发
 * 内核函数原型：
 * get_page_from_freelist(gfp_t gfp_mask, unsigned int order, int alloc_flags, const struct alloc_context *ac)
 * @param gfp_mask 内存分配掩码，标识可分配zone、回收策略、迁移类型等
 * @param order 分配页阶，代表2^order连续物理页
 * @param alloc_flags 内存分配额外控制标识
 * @param ac 分配上下文，包含首选zone、NUMA节点、水位相关信息
 */
SEC("kprobe/get_page_from_freelist")
int BPF_KPROBE(get_page_from_freelist, gfp_t gfp_mask, unsigned int order,
	       int alloc_flags, const struct alloc_context *ac)
{
	// 读取全局采集开关，未开启采集直接返回，减少无效内核开销
	struct Paf_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	struct Paf_event *e;
	unsigned long boost, min, low, high;

	// CORE安全读取当前分配首选zone的水位提升值、三层基础水位
	// watermark_boost：内存水位提升偏移，防止频繁内存回收
	// _watermark[0] = min 最低水位，低于该水位触发直接回收
	// _watermark[1] = low 低水位，达到后开始后台异步回收
	// _watermark[2] = high 高水位，回收完成目标水位
	boost = BPF_CORE_READ(ac, preferred_zoneref, zone, watermark_boost);
	min = BPF_CORE_READ(ac, preferred_zoneref, zone, _watermark[0]);
	low = BPF_CORE_READ(ac, preferred_zoneref, zone, _watermark[1]);
	high = BPF_CORE_READ(ac, preferred_zoneref, zone, _watermark[2]);

	// 从环形缓冲区预留内存，存放水位事件；缓冲区满则丢弃本次事件
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	// zone内当前有效物理总页数
	e->present = BPF_CORE_READ(ac, preferred_zoneref, zone, present_pages);
	// 实际生效水位 = 基础水位 + boost偏移
	e->min = min + boost;
	e->low = low + boost;
	e->high = high + boost;
	// 记录本次内存分配使用的GFP掩码标识
	e->flag = (int)gfp_mask;

	// 推送完整水位事件至环形缓冲区，供用户态读取展示
	bpf_ringbuf_submit(e, 0);
	return 0;
}
