#include "common/types.h"
#ifndef COMMON_REGISTRY_H
#define COMMON_REGISTRY_H

#include "common/cli.h"

/* 统一函数签名: 所有模块的 run() 都是 4 参数 */
typedef int (*run_fn)(int poll_timeout_ms, bool enable,
		      bpf_s32_t target_pid, bpf_u64_t min_delay_ns);

struct module_entry {
	const char    *name;
	enum app_mode  mode;
	run_fn         run;
};

/* 所有模块声明 (按需引入) */
int context_switch_run(int, bool, bpf_s32_t, bpf_u64_t);
int preempt_run(int, bool, bpf_s32_t, bpf_u64_t);
int mutexlock_run(int, bool, bpf_s32_t, bpf_u64_t);
int msgqueue_run(int, bool, bpf_s32_t, bpf_u64_t);
int syscall_run(int, bool, bpf_s32_t, bpf_u64_t);
int open_run(int, bool, bpf_s32_t, bpf_u64_t);
int read_run(int, bool, bpf_s32_t, bpf_u64_t);
int write_run(int, bool, bpf_s32_t, bpf_u64_t);
int block_io_run(int, bool, bpf_s32_t, bpf_u64_t);
int dr_snoop_run(int, bool, bpf_s32_t, bpf_u64_t);
int oom_killer_run(int, bool, bpf_s32_t, bpf_u64_t);
int slab_rate_run(int, bool, bpf_s32_t, bpf_u64_t);
int tcp_monitor_run(int, bool, bpf_s32_t, bpf_u64_t);
int udp_monitor_run(int, bool, bpf_s32_t, bpf_u64_t);

/* ══════ 模块注册表 (增删模块只需改这一张表) ══════ */
static const struct module_entry MODULE_TABLE[] = {
	{"context",       APP_MODE_CONTEXT_SWITCH, context_switch_run},
	{"preempt",       APP_MODE_PREEMPT,         preempt_run},
	/* 锁、IPC 与系统调用是三个独立领域，不再共用 lock 目录语义。 */
	{"mutexlock",     APP_MODE_MUTEXLOCK,       mutexlock_run},
	{"msgqueue",      APP_MODE_MSGQUEUE,        msgqueue_run},
	{"syscall",       APP_MODE_SYSCALL,         syscall_run},
	{"fs_open",       APP_MODE_FS_OPEN,         open_run},
	{"fs_read",       APP_MODE_FS_READ,         read_run},
	{"fs_write",      APP_MODE_FS_WRITE,        write_run},
	{"block_io",      APP_MODE_BLOCK_IO,        block_io_run},
	{"dr_snoop",      APP_MODE_DR_SNOOP,        dr_snoop_run},
	{"oom_killer",    APP_MODE_OOM_KILLER,      oom_killer_run},
	{"slab_rate",     APP_MODE_SLAB_RATE,       slab_rate_run},
	{"tcp_monitor",   APP_MODE_TCP_MONITOR,     tcp_monitor_run},
	{"udp_monitor",   APP_MODE_UDP_MONITOR,     udp_monitor_run},
	{NULL, APP_MODE_UNSET, NULL},
};

#define MODULE_COUNT ((int)(sizeof(MODULE_TABLE)/sizeof(MODULE_TABLE[0]) - 1))

#endif
