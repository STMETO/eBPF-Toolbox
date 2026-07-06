// eBPF程序必须包含的内核类型定义
#include <vmlinux.h>

// eBPF核心帮助函数库
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// 包含我们自己定义的共用结构体
#include "preempt.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ========================== 全局常量定义 ==========================
const int ctrl_key = 0;

// ========================== eBPF MAP 定义 ==========================

/*
 * 1. 抢占时间记录 map
 * 作用：记录被抢占进程的开始时间
 * key：进程 PID
 * value：抢占开始时间戳（纳秒）
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, bpf_s32_t);
	__type(value, bpf_u64_t);
} preemptTime SEC(".maps");

/*
 * 2. 全局控制 map
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Preempt_Delay_ctrl);
} ctrl_map SEC(".maps");

/*
 * 3. 环形缓冲区（ringbuf）
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// ========================== 工具函数 ==========================

static inline struct Preempt_Delay_ctrl *get_ctrl(void)
{
	struct Preempt_Delay_ctrl *ctrl;
	ctrl = bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
	if (!ctrl || !ctrl->enable)
		return NULL;
	return ctrl;
}

// ========================== 挂载点 ==========================

/*
 * tp_btf/sched_switch
 * 触发时机：内核进程切换时
 * 作用：当进程被强制抢占时，记录被抢占的开始时间
 *
 * preempt：是不是因为抢占而切换
 * prev：要被换出去的进程
 * next：要换进来的进程
 */
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch_preempt, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	struct Preempt_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	if (!preempt)
		return 0;

	bpf_u64_t start_time = bpf_ktime_get_ns();
	bpf_s32_t prev_pid = (bpf_s32_t)BPF_CORE_READ(prev, pid);

	bpf_map_update_elem(&preemptTime, &prev_pid, &start_time, BPF_ANY);
	return 0;
}

/*
 * kprobe/finish_task_switch.isra.0
 * 触发时机：进程切换完成后
 * 作用：计算进程被抢占的耗时，通过 ringbuf 发给用户态
 *
 * 注意：高版本内核 GCC 优化后函数名会变，
 * 必须用 .isra.0 后缀才能正确挂载
 */
SEC("kprobe/finish_task_switch.isra.0")
int BPF_KPROBE(finish_task_switch, struct task_struct *prev)
{
	struct Preempt_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	bpf_u64_t end_time = bpf_ktime_get_ns();
	bpf_s32_t pid = (bpf_s32_t)BPF_CORE_READ(prev, pid);

	bpf_u64_t *val = bpf_map_lookup_elem(&preemptTime, &pid);
	if (!val)
		return 0;

	bpf_u64_t delta = end_time - *val;

	/* ===== 发送事件到用户态 ===== */
	struct Preempt_Delay_event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->prev_pid = pid;
	e->next_pid = (bpf_s32_t)(bpf_get_current_pid_tgid() >> 32);
	e->duration = delta;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);

	/* 清理临时数据 */
	bpf_map_delete_elem(&preemptTime, &pid);
	return 0;
}
