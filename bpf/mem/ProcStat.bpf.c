#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ProcStat.h"
char LICENSE[] SEC("license") = "Dual BSD/GPL";
const int ctrl_key = 0;
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
	__type(key, int); __type(value, struct ProcStat_ctrl);
} ctrl_map SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256 * 1024);
} rb SEC(".maps");
static __always_inline struct ProcStat_ctrl *get_ctrl(void)
{ return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key); }

SEC("kprobe/finish_task_switch")
int BPF_KPROBE(finish_task_switch, struct task_struct *prev)
{
	struct ProcStat_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable) return 0;
	struct ProcStat_event *e; struct percpu_counter rss = {};
	pid_t p_pid = BPF_CORE_READ(prev, pid);
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;
	e->pid = p_pid;
	e->vsize = BPF_CORE_READ(prev, mm, total_vm);
	e->Vdata = BPF_CORE_READ(prev, mm, data_vm);
	e->Vstk = BPF_CORE_READ(prev, mm, stack_vm);
	e->nvcsw = BPF_CORE_READ(prev, nvcsw);
	e->nivcsw = BPF_CORE_READ(prev, nivcsw);
	/* Read rss_stat counters directly - kernel version compatibility */
	unsigned long long rss_count[4];
	bpf_core_read(&rss_count, sizeof(rss_count), &prev->mm->rss_stat);
	long long *t = (long long *)rss_count;
	e->rssfile = *t; e->rssanon = *(t + 1); e->vswap = *(t + 2); e->rssshmem = *(t + 3);
	e->size = *t + *(t + 1) + *(t + 3);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
