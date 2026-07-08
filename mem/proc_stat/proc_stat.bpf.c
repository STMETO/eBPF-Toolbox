#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "proc_stat.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
const int ck = 0;

struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, int); __type(value, struct ProcStat_ctrl); } ctrl_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, int); __type(value, struct ProcStat_stats); } stats_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256 * 1024); } rb SEC(".maps");

static inline struct ProcStat_ctrl *get_ctrl(void) { return bpf_map_lookup_elem(&ctrl_map, &ck); }

SEC("kprobe/finish_task_switch.isra.0")
int BPF_KPROBE(finish_task_switch, struct task_struct *prev)
{
	struct ProcStat_ctrl *c = get_ctrl();
	if (!c || !c->enable) return 0;

	u64 pt = bpf_get_current_pid_tgid();
	s32 pid = pt >> 32;
	if (pid == 0) return 0;  /* skip idle */
	if (c->target_pid != 0 && pid != c->target_pid) return 0;

	struct ProcStat_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;

	e->pid = pid;
	e->vsize = 0; e->size = 0; e->Vdata = 0; e->Vstk = 0;
	e->nvcsw = 0; e->nivcsw = 0;
	e->rssanon = 0; e->rssfile = 0; e->rssshmem = 0; e->vswap = 0;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);

	struct ProcStat_stats *st = bpf_map_lookup_elem(&stats_map, &ck);
	if (!st) { struct ProcStat_stats z = {}; bpf_map_update_elem(&stats_map, &ck, &z, BPF_ANY); st = bpf_map_lookup_elem(&stats_map, &ck); }
	if (st) { st->count++; if (st->count == 1) { st->max_pid = pid; } }
	return 0;
}
