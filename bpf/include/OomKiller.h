#ifndef __OOM_KILLER_H
#define __OOM_KILLER_H
#include "common.h"
struct OomKiller_ctrl { bpf_bool_t enable; };
struct OomKiller_event {
	bpf_u32_t triggered_pid;
	bpf_u32_t oomkill_pid;
	bpf_u32_t mem_pages;
	char comm[TASK_COMM_LEN];
};
#endif
