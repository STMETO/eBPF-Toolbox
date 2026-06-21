#ifndef __OOM_KILLER_H
#define __OOM_KILLER_H
#include "common/types.h"
struct OomKiller_ctrl { bpf_bool_t enable; };
struct OomKiller_event {
	bpf_u32_t triggered_pid;
	bpf_u32_t oomkill_pid;
	bpf_u32_t mem_pages;
	char comm[TASK_COMM_LEN];
};
/* 用户态入口 */
#ifndef __BPF__
#include <stdbool.h>
int oom_killer_run(int poll_timeout_ms, bool enable);
#endif

#endif
