#ifndef __PREEMPT_DELAY_H
#define __PREEMPT_DELAY_H

#include "common/types.h"

/*
 * 抢占延迟监控
 *
 * 探针：
 *   tp_btf/sched_switch (preempt=true)  → 记录被抢占进程的全部上下文
 *   kprobe/finish_task_switch.isra.0    → 计算延迟、过滤、发送
 */

/* ── 控制结构体 ─────────────────────────────────────────── */
struct Preempt_ctrl {
	bpf_bool_t enable;
	bpf_u64_t  min_delay_ns;   // 最小延迟阈值(ns)
	bpf_s32_t  target_pid;     // 目标 PID，0=全部
};

/* ── 输出事件 ────────────────────────────────────────────── */
struct Preempt_event {
	bpf_u64_t ts_ns;
	bpf_u64_t delay_ns;
	bpf_s32_t cpu;
	bpf_s32_t prev_pid, next_pid;
	bpf_s32_t prev_tgid, next_tgid;
	bpf_s32_t prev_prio, next_prio;
	bpf_s32_t prev_state;
	bpf_s8_t  prev_comm[TASK_COMM_LEN];
	bpf_s8_t  next_comm[TASK_COMM_LEN];
};

/* ── 全局统计 ────────────────────────────────────────────── */
struct Preempt_stats {
	bpf_u64_t count, total_ns, max_ns;
	bpf_s32_t max_prev_pid, max_next_pid;
	bpf_s8_t  max_prev_comm[TASK_COMM_LEN];
	bpf_s8_t  max_next_comm[TASK_COMM_LEN];
};

#ifndef __BPF__
#include <stdbool.h>
int preempt_run(int poll_timeout_ms, bool enable,
		bpf_s32_t target_pid, bpf_u64_t min_delay_ns);
#endif

#endif
