#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "oom_killer.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// ctrl_map 数组MAP固定下标，仅存储一条全局控制配置
const int ctrl_key = 0;

/**
 * @map ctrl_map
 * 类型：BPF_MAP_TYPE_ARRAY 定长数组，性能最优，用于全局开关控制
 * max_entries=1：只保存一条控制结构体
 * key：数组下标int，固定使用 ctrl_key=0
 * value：OomKiller_ctrl 采集启停开关
 * 作用：用户态写入 enable 布尔值，控制OOM事件采集开启/关闭
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct OomKiller_ctrl);
} ctrl_map SEC(".maps");

/**
 * @map rb
 * 类型：BPF_MAP_TYPE_RINGBUF 环形缓冲区
 * max_entries=256*1024：缓冲区总大小256KB
 * 作用：BPF内核态向用户态实时推送OOM杀死进程事件，流式低延迟
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
 * @brief 内联工具函数，快速读取全局采集开关配置
 * @return 成功返回OomKiller_ctrl指针，空指针代表用户态未下发配置
 */
static __always_inline struct OomKiller_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
}

/**
 * @kprobe oom_kill_process
 * 挂载内核OOM杀手核心函数钩子，当系统内存不足触发杀死进程时执行
 * 内核函数原型：
 * void oom_kill_process(struct oom_control *oc, const char *message)
 * @param oc OOM控制结构体，包含本次待杀死的进程、内存水位等信息
 * @param message OOM触发日志描述字符串
 */
SEC("kprobe/oom_kill_process")
int BPF_KPROBE(oom_kill_process, struct oom_control *oc, const char *message)
{
	// 读取全局开关，未开启采集则直接退出，不执行后续逻辑
	struct OomKiller_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	struct OomKiller_event *e;
	// 从环形缓冲区预留一块内存存放事件数据，大小为事件结构体大小
	// 预留失败（缓冲区满）直接丢弃本次OOM事件
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	struct task_struct *p;
	// 读取oc->chosen：本次被OOM杀手选中杀死的进程task_struct指针
	bpf_probe_read(&p, sizeof(p), &oc->chosen);
	// 读取被杀死进程PID
	bpf_probe_read(&e->oomkill_pid, sizeof(e->oomkill_pid), &p->pid);
	// 读取被杀死进程名称 comm
	bpf_probe_read(&e->comm, sizeof(e->comm), &p->comm);

	// bpf_get_current_task() 获取当前触发OOM逻辑的内核上下文进程
	struct task_struct *trigger_task = (struct task_struct *)bpf_get_current_task();
	// 记录触发OOM检测的进程PID
	e->triggered_pid = BPF_CORE_READ(trigger_task, pid);

	// 读取触发进程的地址空间mm结构体
	struct mm_struct *mm = BPF_CORE_READ(trigger_task, mm);
	// total_vm：进程总虚拟内存页数，mm为空（内核线程无用户地址空间）则置0
	e->mem_pages = mm ? BPF_CORE_READ(mm, total_vm) : 0;

	// 将填充完成的事件提交到环形缓冲区，用户态可同步读取
	bpf_ringbuf_submit(e, 0);
	return 0;
}
