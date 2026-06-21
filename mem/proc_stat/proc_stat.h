#ifndef __PROC_STAT_H
#define __PROC_STAT_H
#include "common/types.h"
struct ProcStat_ctrl { bpf_bool_t enable; };
struct ProcStat_event {
	bpf_s32_t pid; bpf_s64_t nvcsw; bpf_s64_t nivcsw;
	bpf_s64_t vsize; bpf_s64_t size;
	bpf_s64_t rssanon; bpf_s64_t rssfile; bpf_s64_t rssshmem;
	bpf_s64_t vswap; bpf_s64_t Hpages; bpf_s64_t Vdata; bpf_s64_t Vstk; bpf_s64_t VPTE;
};
/* 用户态入口 */
#ifndef __BPF__
#include <stdbool.h>
int proc_stat_run(int poll_timeout_ms, bool enable);
#endif

#endif
