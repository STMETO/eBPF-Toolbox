#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "context_switch.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

/* ── PERCPU 中间存储：tp_btf/sched_switch 写入，finish_task_switch 读取 ── */
struct start_val {
	bpf_s32_t prev_pid, next_pid;
	bpf_s32_t prev_tgid, next_tgid;
	bpf_s32_t prev_prio, next_prio;
	bpf_s32_t prev_state, cpu;
	bpf_bool_t preempt;
	bpf_u64_t start_ts;
	bpf_s8_t  prev_comm[TASK_COMM_LEN];
	bpf_s8_t  next_comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct start_val);
} start_map SEC(".maps");

/* ── 控制 map ────────────────────────────────────────────── */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct ContextSwitch_ctrl);
} ctrl_map SEC(".maps");

/* ── 全局统计 map ────────────────────────────────────────── */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct ContextSwitch_stats);
} stats_map SEC(".maps");

/* ── 环形缓冲区 ──────────────────────────────────────────── */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* ── 获取控制配置 ────────────────────────────────────────── */
static inline struct ContextSwitch_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
}

/* ── 判断是否应跳过该事件 ────────────────────────────────── */
static inline bool should_skip(struct ContextSwitch_ctrl *ctrl,
			       bpf_s32_t prev_pid, bpf_s32_t next_pid,
			       bpf_u64_t delay_ns)
{
	if (!ctrl || !ctrl->enable)
		return true;

	/* PID 过滤：target_pid != 0 时只收集涉及该 PID 的切换 */
	if (ctrl->target_pid != 0 &&
	    prev_pid != ctrl->target_pid &&
	    next_pid != ctrl->target_pid)
		return true;

	/* 延迟阈值过滤：低于 min_delay_ns 的轻量切换直接丢弃 */
	if (ctrl->min_delay_ns != 0 && delay_ns < ctrl->min_delay_ns)
		return true;

	return false;
}

/* ── tp_btf/sched_switch：记录切换前的全部上下文 ────────────
 *   PERCPU 确保多核并发互不干扰
 */
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch_capture, bool preempt,
	     struct task_struct *prev, struct task_struct *next)
{
	struct ContextSwitch_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	int key = 0;
	struct start_val *v = bpf_map_lookup_elem(&start_map, &key);
	if (!v)
		return 0;

	v->start_ts    = bpf_ktime_get_ns();
	v->cpu         = bpf_get_smp_processor_id();
	v->preempt     = preempt;

	v->prev_pid    = BPF_CORE_READ(prev, pid);
	v->next_pid    = BPF_CORE_READ(next, pid);
	v->prev_tgid   = BPF_CORE_READ(prev, tgid);
	v->next_tgid   = BPF_CORE_READ(next, tgid);
	v->prev_prio   = BPF_CORE_READ(prev, prio);
	v->next_prio   = BPF_CORE_READ(next, prio);
	v->prev_state  = BPF_CORE_READ(prev, __state);

	bpf_probe_read_kernel_str(&v->prev_comm, sizeof(v->prev_comm), prev->comm);
	bpf_probe_read_kernel_str(&v->next_comm, sizeof(v->next_comm), next->comm);

	return 0;
}

/* ── kprobe/finish_task_switch：计算延迟、过滤、发送 ──────── */
SEC("kprobe/finish_task_switch.isra.0")
int BPF_KPROBE(finish_task_switch, struct task_struct *prev)
{
	struct ContextSwitch_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	int key = 0;
	struct start_val *v = bpf_map_lookup_elem(&start_map, &key);
	if (!v || v->start_ts == 0)
		return 0;

	bpf_u64_t end_ts  = bpf_ktime_get_ns();
	bpf_u64_t delay_ns = end_ts - v->start_ts;

	/* 过滤 */
	if (should_skip(ctrl, v->prev_pid, v->next_pid, delay_ns)) {
		v->start_ts = 0;  /* 标记已消费 */
		return 0;
	}

	/* ── 发送 ringbuf 事件 ── */
	struct ContextSwitch_event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		v->start_ts = 0;
		return 0;
	}

	e->ts_ns       = end_ts;
	e->delay_ns    = delay_ns;
	e->cpu         = v->cpu;
	e->prev_pid    = v->prev_pid;
	e->next_pid    = v->next_pid;
	e->prev_tgid   = v->prev_tgid;
	e->next_tgid   = v->next_tgid;
	e->prev_prio   = v->prev_prio;
	e->next_prio   = v->next_prio;
	e->prev_state  = v->prev_state;
	e->preempt     = v->preempt;
	__builtin_memcpy(e->prev_comm, v->prev_comm, TASK_COMM_LEN);
	__builtin_memcpy(e->next_comm, v->next_comm, TASK_COMM_LEN);

	bpf_ringbuf_submit(e, 0);

	/* ── 更新全局统计 ── */
	struct ContextSwitch_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
	if (stats) {
		stats->count++;
		stats->total_ns += delay_ns;
		if (delay_ns > stats->max_ns) {
			stats->max_ns = delay_ns;
			stats->max_prev_pid = v->prev_pid;
			stats->max_next_pid = v->next_pid;
			__builtin_memcpy(stats->max_prev_comm, v->prev_comm, TASK_COMM_LEN);
			__builtin_memcpy(stats->max_next_comm, v->next_comm, TASK_COMM_LEN);
		}
	} else {
		struct ContextSwitch_stats new_stats = {};
		new_stats.count = 1;
		new_stats.total_ns = delay_ns;
		new_stats.max_ns = delay_ns;
		new_stats.max_prev_pid = v->prev_pid;
		new_stats.max_next_pid = v->next_pid;
		__builtin_memcpy(new_stats.max_prev_comm, v->prev_comm, TASK_COMM_LEN);
		__builtin_memcpy(new_stats.max_next_comm, v->next_comm, TASK_COMM_LEN);
		bpf_map_update_elem(&stats_map, &key, &new_stats, BPF_ANY);
	}

	v->start_ts = 0;  /* 标记已消费 */
	return 0;
}
