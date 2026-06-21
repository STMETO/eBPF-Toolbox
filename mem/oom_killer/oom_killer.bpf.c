#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "oom_killer.h"
char __license[] SEC("license") = "Dual MIT/GPL";
const int ctrl_key = 0;
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
	__type(key, int); __type(value, struct OomKiller_ctrl);
} ctrl_map SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256 * 1024);
} rb SEC(".maps");
static __always_inline struct OomKiller_ctrl *get_ctrl(void)
{ return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key); }

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(oom_kill_process, struct oom_control *oc, const char *message)
{
	struct OomKiller_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable) return 0;

	struct OomKiller_event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;

	struct task_struct *p;
	bpf_probe_read(&p, sizeof(p), &oc->chosen);
	bpf_probe_read(&e->oomkill_pid, sizeof(e->oomkill_pid), &p->pid);
	bpf_probe_read(&e->comm, sizeof(e->comm), &p->comm);

	struct task_struct *trigger_task = (struct task_struct *)bpf_get_current_task();
	e->triggered_pid = BPF_CORE_READ(trigger_task, pid);

	struct mm_struct *mm = BPF_CORE_READ(trigger_task, mm);
	e->mem_pages = mm ? BPF_CORE_READ(mm, total_vm) : 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}
