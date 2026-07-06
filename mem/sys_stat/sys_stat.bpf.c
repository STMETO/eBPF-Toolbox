/*
 * eBPF内核探针程序：整机全局内存vm_stat采集工具
 * 挂载点：kprobe/get_page_from_freelist
 * 触发时机：内核从空闲页列表分配物理内存时，抓取当前zone全局内存统计vm_stat
 * 功能：读取pgdat->vm_stat页面计数，换算KB后封装事件通过ringbuf发给用户态
 * 用途：监控整机全局内存水位、脏页、slab、shmem、匿名/文件缓存分布
 * 与前面工具区分：
 *  proc_stat：单进程粒度 用户态内存RSS/VMSIZE
 *  slab_rate：内核slab分配吞吐量统计
 *  sys_stat：整机全局系统内存大盘指标
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "sys_stat.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 控制MAP固定查询key
const int ctrl_key = 0;

/**
 * 控制MAP：数组MAP，全局采集开关
 * 用户态写入enable布尔值，内核探针读取判断是否采集
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct SysStat_ctrl);
} ctrl_map SEC(".maps");

/**
 * Ringbuf环形缓冲区
 * 高性能无锁队列，内核推送整机内存事件，用户态poll读取
 * 缓冲区大小256KB，高并发内存分配场景可扩容防止丢事件
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
 * 内联工具函数：读取全局采集控制开关
 * @return ctrl结构体指针，空代表未初始化MAP
 */
static __always_inline struct SysStat_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
}

/**
 * kprobe挂载点：get_page_from_freelist
 * 内核函数作用：物理内存分配时，从zone空闲页链表取出物理页
 * 入参：
 *  gfp_mask: 内存分配标识
 *  order: 分配阶（2^order连续物理页）
 *  alloc_flags: 分配控制标记
 *  ac: 分配上下文，包含目标zone、pgdat指针
 * 采集逻辑：读取pgdat->vm_stat全局页面计数器，填充整机内存指标推送ringbuf
 */
SEC("kprobe/get_page_from_freelist")
int BPF_KPROBE(get_page_from_freelist_second, gfp_t gfp_mask, unsigned int order,
	       int alloc_flags, const struct alloc_context *ac)
{
	// 获取全局采集开关，关闭则直接返回不采集
	struct SysStat_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	struct SysStat_event *e;
	// CO-RE链式读取：分配上下文 → zone → pgdat → vm_stat页面计数数组
	unsigned long *t = (unsigned long *)BPF_CORE_READ(ac, preferred_zoneref, zone, zone_pgdat, vm_stat);

	// 从ringbuf预留内存存储事件，分配失败则丢弃本次采样
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/*
	 * vm_stat数组内每项单位为【4KB页】，代码直接 ×4 换算为KB存入事件
	 * 下标对应内核enum vm_stat_item枚举项
	 */
	// LRU匿名页
	e->anon_inactive = t[0] * 4;
	e->anon_active = t[1] * 4;
	// LRU文件缓存页
	e->file_inactive = t[2] * 4;
	e->file_active = t[3] * 4;
	e->unevictable = t[4] * 4;

	// Slab可回收/不可回收内存
	e->slab_reclaimable = t[5] * 4;
	e->slab_unreclaimable = t[6] * 4;

	// 脏页、回写页面
	e->file_dirty = t[20] * 4;
	e->writeback = t[21] * 4;
	e->writeback_temp = t[22] * 4;

	// 共享内存、透明大页、NFS
	e->shmem = t[23] * 4;
	e->shmem_thps = t[24] * 4;
	e->pmdmapped = t[25] * 4;
	e->anon_thps = t[26] * 4;
	e->unstable_nfs = t[27] * 4;

	// 文件/匿名映射页
	e->anon_mapped = t[17] * 4;
	e->file_mapped = t[18] * 4;

	// 其他可回收内核杂项内存
	e->kernel_misc_reclaimable = t[29] * 4;

	// 将填充完成的整机内存事件提交到环形缓冲区，用户态可接收
	bpf_ringbuf_submit(e, 0);
	return 0;
}
