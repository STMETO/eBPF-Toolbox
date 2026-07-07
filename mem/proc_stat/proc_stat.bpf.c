#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "proc_stat.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

/**
 * 控制MAP：全局开关控制器
 * 类型：数组MAP，仅1个entry，key固定0，value为ProcStat_ctrl
 * 作用：用户态下发开关 enable，控制kprobe是否采集进程数据
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);    // MAP类型：数组
	__uint(max_entries, 1);              // 仅存放1条控制配置
	__type(key, int);                    // key类型int，固定0访问
	__type(value, struct ProcStat_ctrl); // 存储采集开关配置
} ctrl_map SEC(".maps");

/**
 * 环形缓冲区MAP：向用户态投递采集事件
 * 类型：ringbuf，高性能无锁事件队列，相比perf buffer更低开销
 * 大小：256KB，可根据业务调整，过小会丢事件
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
 * 内联工具函数：获取全局采集控制配置
 * @return 指向ctrl_map中控制结构体指针，空表示未初始化
 */
static __always_inline struct ProcStat_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
}

/**
 * kprobe 挂载点：finish_task_switch
 * 触发时机：内核完成进程上下文切换时（从prev进程切走时）
 * 参数prev：被切换出去的旧进程 task_struct 指针
 * 功能：采集进程内存、调度统计指标，封装事件推送ringbuf给用户态
 */
SEC("kprobe/finish_task_switch")
int BPF_KPROBE(finish_task_switch, struct task_struct *prev)
{
	// 1. 获取全局采集开关，未开启则直接退出不采集
	struct ProcStat_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	struct ProcStat_event *e;
	struct percpu_counter rss = {}; // 未实际使用，仅变量占位

	// 读取被切换进程PID
	pid_t p_pid = BPF_CORE_READ(prev, pid);

	// 从ringbuf预留一块内存存放事件，大小为事件结构体
		/* kernel threads have mm == NULL, skip */
		if (!BPF_CORE_READ(prev, mm)) return 0;
		/* skip kernel threads (mm == NULL) */
		if (!BPF_CORE_READ(prev, mm))
			return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) // 环形缓冲区满/分配失败，丢弃本次事件
		return 0;

	// 填充进程基础信息
	e->pid = p_pid;
	// total_vm：进程全部虚拟内存页面数（单位：页）
	e->vsize = BPF_CORE_READ(prev, mm, total_vm);
	// data_vm：数据段虚拟内存页数
	e->Vdata = BPF_CORE_READ(prev, mm, data_vm);
	// stack_vm：用户栈虚拟内存页数
	e->Vstk = BPF_CORE_READ(prev, mm, stack_vm);

	// 调度统计：自愿上下文切换次数、非自愿上下文切换次数
	e->nvcsw = BPF_CORE_READ(prev, nvcsw);
	e->nivcsw = BPF_CORE_READ(prev, nivcsw);

	/**
	 * 读取 mm->rss_stat 四个RSS统计计数器
	 * rss_stat 内核结构体顺序固定：
	 * 0: rss_file  文件缓存页（文件映射、库文件等）
	 * 1: rss_anon  匿名内存（堆、私有分配、栈匿名区）
	 * 2: rss_swap  交换出去的匿名页
	 * 3: rss_shmem 共享内存、tmpfs映射页
	 */
	unsigned long long rss_count[4];
	// CO-RE安全读取rss_stat整块数据，兼容不同内核结构体偏移
	bpf_core_read(&rss_count, sizeof(rss_count), &prev->mm->rss_stat);
	long long *t = (long long *)rss_count;

	// 拆分四类内存指标存入事件
	e->rssfile = *t;
	e->rssanon = *(t + 1);
	e->vswap = *(t + 2);
	e->rssshmem = *(t + 3);

	// 进程常驻内存总大小 = 匿名页 + 文件页 + 共享内存页（不含swap）
	e->size = *t + *(t + 1) + *(t + 3);

	// 将事件提交到环形缓冲区，用户态可poll读取
	bpf_ringbuf_submit(e, 0);
	return 0;
}
