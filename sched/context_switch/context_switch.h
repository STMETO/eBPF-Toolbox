#ifndef __CONTEXT_SWITCH_H
#define __CONTEXT_SWITCH_H

#include "common/types.h"

/*
 * 进程切换延迟监控
 *
 * 探针：
 *   tp_btf/sched_switch              → 记录 prev/next 全部信息
 *   kprobe/finish_task_switch.isra.0 → 计算延迟、过滤、发送事件、更新统计
 *
 * 特性：
 *   - PERCPU 存储，零多核竞态
 *   - PID 过滤 (-p)、延迟阈值过滤 (-d)
 *   - 事件携带 prev/next 的 PID/TGID/comm/prio/state/CPU
 *   - 退出时打印全局统计摘要
 */

/* ── 控制结构体 ─────────────────────────────────────────── */
struct ContextSwitch_ctrl {
	bpf_bool_t enable;         // 监控开关
	bpf_u64_t  min_delay_ns;   // 最小延迟阈值(ns)，低于此值不上报
	bpf_s32_t  target_pid;     // 目标 PID，0=监控全部
};

/* ── 输出事件结构体 ──────────────────────────────────────── */
struct ContextSwitch_event {
	bpf_u64_t ts_ns;           // 事件时间戳（纳秒）
	bpf_u64_t delay_ns;        // 切换耗时（纳秒）
	bpf_s32_t cpu;             // 发生在哪个 CPU
	bpf_s32_t prev_pid;        // 被换下进程的 PID
	bpf_s32_t next_pid;        // 换入进程的 PID
	bpf_s32_t prev_tgid;       // 被换下进程的 TGID
	bpf_s32_t next_tgid;       // 换入进程的 TGID
	bpf_s32_t prev_prio;       // 被换下进程的优先级
	bpf_s32_t next_prio;       // 换入进程的优先级
	bpf_s32_t prev_state;      // 被换下进程的状态（TASK_RUNNING=可运行, TASK_INTERRUPTIBLE=睡眠等）
	bpf_bool_t preempt;        // true=抢占切换  false=自愿切换
	bpf_s8_t  prev_comm[TASK_COMM_LEN]; // 被换下进程名
	bpf_s8_t  next_comm[TASK_COMM_LEN]; // 换入进程名
};

/* ── 全局统计（Ctrl+C 时打印） ───────────────────────────── */
struct ContextSwitch_stats {
	bpf_u64_t count;           // 采样次数
	bpf_u64_t total_ns;        // 累计延迟(ns)
	bpf_u64_t max_ns;          // 最大延迟(ns)
	bpf_s32_t max_prev_pid;    // 最大延迟时的 prev PID
	bpf_s32_t max_next_pid;    // 最大延迟时的 next PID
	bpf_s8_t  max_prev_comm[TASK_COMM_LEN];
	bpf_s8_t  max_next_comm[TASK_COMM_LEN];
};

#ifndef __BPF__
#include <stdbool.h>
int context_switch_run(int poll_timeout_ms, bool enable,
		       bpf_s32_t target_pid, bpf_u64_t min_delay_ns);
#endif

#endif
