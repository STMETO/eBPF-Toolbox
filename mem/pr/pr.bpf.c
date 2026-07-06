/**
 * pr.bpf.c - Page Reclaim 页面回收监控eBPF探针
 * 功能：kprobe 挂载内核页面回收核心函数 shrink_page_list，捕获每次页面回收扫描行为
 * 采集指标：本次计划回收页数、实际回收页数、未排队脏页、设备拥塞计数、回写中页面数
 * 架构：
 *  1. ctrl_map 数组MAP：存储采集开关 enable，用户态动态启停探针
 *  2. rb 256KB RingBuffer：低延迟流式推送回收事件至用户态
 * 适用场景：排查内存回收慢、kswapd频繁触发、IO拥塞阻塞页面回收等内存瓶颈问题
 */

 /**
 * 代码现存缺陷：
 * 1. 非标准CO-RE读取：通过硬编码内存偏移取 scan_control 后续字段，内核结构体布局变更后数据会错乱
 * 2. 缺少定位维度：未采集NUMA节点、zone、触发进程信息，无法区分回收压力来源
 * 3. 无事件丢失统计：RingBuffer 缓冲区满时直接丢弃事件，无丢失计数上报
 * 4. 缺少pgdat/zone绑定信息，多NUMA多内存域场景无法区分数据归属
 */


#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "pr.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

/**
 * @map ctrl_map
 * 类型：BPF_MAP_TYPE_ARRAY 定长数组，读写性能高
 * max_entries=1：仅存储一条控制结构体
 * key：数组下标int，固定使用 ctrl_key=0 访问
 * value：Pr_ctrl 采集启停开关
 * 作用：用户态写入enable布尔值，控制页面回收探针是否采集事件
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Pr_ctrl);
} ctrl_map SEC(".maps");

/**
 * @map rb
 * 类型：BPF_MAP_TYPE_RINGBUF 环形缓冲区
 * 缓冲区大小256KB，内核流式推送页面回收事件到用户态
 * 低延迟、无轮询CPU损耗，适合实时监控回收行为
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
 * @brief 内联工具函数，快速读取全局采集开关配置
 * @return 成功返回Pr_ctrl指针，空指针代表未下发控制配置
 */
static __always_inline struct Pr_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
}

/**
 * @kprobe shrink_page_list
 * 挂载内核页面回收核心函数，kswapd/直接回收时都会调用该函数扫描回收页面
 * 内核原型：
 * unsigned long shrink_page_list(struct list_head *page_list, struct pglist_data *pgdat, struct scan_control *sc)
 * @param page_list 待扫描回收的页面链表
 * @param pgdat 当前回收归属的NUMA节点pgdat
 * @param sc 页面扫描控制结构体，包含回收目标、已回收数量、脏页/回写阻塞统计等核心指标
 */
SEC("kprobe/shrink_page_list")
int BPF_KPROBE(shrink_page_list, struct list_head *page_list,
	       struct pglist_data *pgdat, struct scan_control *sc)
{
	// 读取全局开关，未开启采集直接返回，减少内核无效开销
	struct Pr_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	struct Pr_event *e;
	unsigned long y;
	unsigned int *a;

	// 从环形缓冲区预留内存存放回收事件；缓冲区满则丢弃本次事件
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	// 本次扫描计划需要回收的页面总数 nr_to_reclaim
	e->reclaim = BPF_CORE_READ(sc, nr_to_reclaim);
	// 本次扫描已经成功回收的页面数量 nr_reclaimed
	y = BPF_CORE_READ(sc, nr_reclaimed);
	e->reclaimed = y;

	/*
	 * 内核struct scan_control结构体后续连续内存字段偏移读取：
	 * sc结构体内存布局：nr_to_reclaim(u64) | nr_reclaimed(u64) | unqueued_dirty(u32) | congested(u32) | writeback(u32)
	 * 指针偏移绕过前两个u64，直接读取后面三个u32统计值
	 * unqueued_dirty：未入队的脏页面数量
	 * congested：回写设备拥塞标记计数
	 * writeback：处于回写中的页面数量
	 */
	a = (unsigned int *)(&y + 1);
	e->unqueued_dirty = *(a + 1);
	e->congested = *(a + 2);
	e->writeback = *(a + 3);

	// 将完整页面回收事件提交至环形缓冲区，供用户态读取展示
	bpf_ringbuf_submit(e, 0);
	return 0;
}
