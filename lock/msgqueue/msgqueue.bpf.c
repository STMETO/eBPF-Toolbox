#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "msgqueue.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
const int ctrl_key = 0;

struct mq_start { bpf_u64_t start_ts; bpf_s32_t mqdes; bpf_u64_t msg_len; bpf_u32_t msg_prio; bpf_u32_t is_send; };

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
	__type(key, int); __type(value, struct mq_start);
} start_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
	__type(key, int); __type(value, struct Msgqueue_ctrl);
} ctrl_map SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
	__type(key, int); __type(value, struct Msgqueue_stats);
} stats_map SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static inline struct Msgqueue_ctrl *get_ctrl(void)
{ return bpf_map_lookup_elem(&ctrl_map, &ctrl_key); }
static inline bool pid_skip(struct Msgqueue_ctrl *c, bpf_s32_t pid)
{ return !c || !c->enable || (c->target_pid != 0 && pid != c->target_pid); }

static void submit(struct mq_start *v, bpf_s32_t pid, bpf_u32_t type)
{
	int key = 0;
	struct Msgqueue_ctrl *c = get_ctrl();
	u64 now = bpf_ktime_get_ns();
	u64 delay = now - v->start_ts;
	if (pid_skip(c, pid)) return;
	if (c->min_delay_ns && delay < c->min_delay_ns) return;

	struct Msgqueue_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return;
	e->type = type; e->ts_ns = now; e->delay_ns = delay;
	e->pid = pid; e->mqdes = v->mqdes; e->msg_len = v->msg_len; e->msg_prio = v->msg_prio;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);

	struct Msgqueue_stats *st = bpf_map_lookup_elem(&stats_map, &key);
	if (!st) { struct Msgqueue_stats z = {}; bpf_map_update_elem(&stats_map, &key, &z, BPF_ANY); st = bpf_map_lookup_elem(&stats_map, &key); }
	if (st) {
		if (type == MQ_EV_SEND) { st->send_count++; st->send_total_ns += delay; if (delay > st->send_max_ns) st->send_max_ns = delay; }
		else { st->recv_count++; st->recv_total_ns += delay; if (delay > st->recv_max_ns) st->recv_max_ns = delay; }
	}
}

SEC("kprobe/do_mq_timedsend")
int BPF_KPROBE(mq_send_enter, mqd_t mqdes, const char *u_msg_ptr, size_t msg_len, unsigned int msg_prio, struct timespec64 *ts)
{
	struct Msgqueue_ctrl *c = get_ctrl(); if (!c || !c->enable) return 0;
	int key = 0; struct mq_start *v = bpf_map_lookup_elem(&start_map, &key);
	if (!v) return 0;
	v->start_ts = bpf_ktime_get_ns(); v->mqdes = (bpf_s32_t)mqdes;
	v->msg_len = msg_len; v->msg_prio = msg_prio;
	return 0;
}
SEC("kretprobe/do_mq_timedsend")
int BPF_KRETPROBE(mq_send_exit, int ret)
{
	struct Msgqueue_ctrl *c = get_ctrl(); if (!c || !c->enable) return 0;
	int key = 0; struct mq_start *v = bpf_map_lookup_elem(&start_map, &key);
	if (!v || v->start_ts == 0) return 0;
	bpf_s32_t pid = bpf_get_current_pid_tgid();
	submit(v, pid, MQ_EV_SEND); v->start_ts = 0;
	return 0;
}
SEC("kprobe/do_mq_timedreceive")
int BPF_KPROBE(mq_recv_enter, mqd_t mqdes, const char *u_msg_ptr, size_t msg_len, unsigned int msg_prio, struct timespec64 *ts)
{
	struct Msgqueue_ctrl *c = get_ctrl(); if (!c || !c->enable) return 0;
	int key = 0; struct mq_start *v = bpf_map_lookup_elem(&start_map, &key);
	if (!v) return 0;
	v->start_ts = bpf_ktime_get_ns(); v->mqdes = (bpf_s32_t)mqdes;
	v->msg_len = msg_len; v->msg_prio = msg_prio; v->is_send = 0;
	return 0;
}
SEC("kretprobe/do_mq_timedreceive")
int BPF_KRETPROBE(mq_recv_exit, int ret)
{
	struct Msgqueue_ctrl *c = get_ctrl(); if (!c || !c->enable) return 0;
	int key = 0; struct mq_start *v = bpf_map_lookup_elem(&start_map, &key);
	if (!v || v->start_ts == 0) return 0;
	bpf_s32_t pid = bpf_get_current_pid_tgid();
	submit(v, pid, MQ_EV_RECV); v->start_ts = 0;
	return 0;
}
