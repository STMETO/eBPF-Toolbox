#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "block_io.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
const int ctrl_key = 0;

/* 用 dev+sector 关联 issue→complete */
struct io_key { bpf_s32_t dev; bpf_u64_t sector; };
struct io_start { bpf_u64_t start_ts; bpf_s32_t pid; bpf_s32_t rwbs; bpf_u64_t bytes; bpf_u32_t nr_sectors; bpf_s8_t comm[TASK_COMM_LEN]; };

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, struct io_key); __type(value, struct io_start); } io_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, int); __type(value, struct BlockIo_ctrl); } ctrl_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, int); __type(value, struct BlockIo_stats); } stats_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256 * 1024); } rb SEC(".maps");

static inline struct BlockIo_ctrl *get_ctrl(void) { return bpf_map_lookup_elem(&ctrl_map, &ctrl_key); }

static int enc(char c) { switch(c){case'R':return 1;case'W':return 2;case'D':return 3;case'F':return 4;default:return 5;} }

/* ── block_rq_issue: 记录开始 ─────────────────────────────── */
SEC("tracepoint/block/block_rq_issue")
int trace_issue(struct trace_event_raw_block_rq_completion *ctx)
{
	struct BlockIo_ctrl *c = get_ctrl();
	if (!c || !c->enable) return 0;
	struct io_key k = {.dev = (bpf_s32_t)ctx->dev, .sector = ctx->sector};
	struct io_start v = {};
	v.start_ts = bpf_ktime_get_ns();
	v.pid = (bpf_s32_t)(bpf_get_current_pid_tgid() >> 32);
	v.rwbs = ctx->rwbs[0]; v.nr_sectors = ctx->nr_sector; v.bytes = (u64)ctx->nr_sector * 512;
	bpf_get_current_comm(&v.comm, sizeof(v.comm));
	bpf_map_update_elem(&io_map, &k, &v, BPF_ANY);
	return 0;
}

/* ── block_rq_complete: 计算延迟 ──────────────────────────── */
SEC("tracepoint/block/block_rq_complete")
int trace_complete(struct trace_event_raw_block_rq_completion *ctx)
{
	struct BlockIo_ctrl *c = get_ctrl();
	if (!c || !c->enable) return 0;
	struct io_key k = {.dev = (bpf_s32_t)ctx->dev, .sector = ctx->sector};
	struct io_start *v = bpf_map_lookup_elem(&io_map, &k);
	if (!v) return 0;

	u64 now = bpf_ktime_get_ns();
	u64 lat = now - v->start_ts;
	if (c->target_pid != 0 && v->pid != c->target_pid) { bpf_map_delete_elem(&io_map, &k); return 0; }
	if (c->min_latency_ns && lat < c->min_latency_ns) { bpf_map_delete_elem(&io_map, &k); return 0; }

	struct BlockIo_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) { bpf_map_delete_elem(&io_map, &k); return 0; }
	e->type = BLOCK_IO_EV_COMPLETE; e->ts_ns = now; e->latency_ns = lat;
	e->pid = v->pid; e->dev = k.dev; e->sector = k.sector;
	e->nr_sectors = v->nr_sectors; e->rwbs = enc(v->rwbs); e->bytes = v->bytes;
	__builtin_memcpy(e->comm, v->comm, TASK_COMM_LEN);
	bpf_ringbuf_submit(e, 0);

	struct BlockIo_stats *st = bpf_map_lookup_elem(&stats_map, &ctrl_key);
	if (!st) { struct BlockIo_stats z = {}; bpf_map_update_elem(&stats_map, &ctrl_key, &z, BPF_ANY); st = bpf_map_lookup_elem(&stats_map, &ctrl_key); }
	if (st) { st->complete_cnt++; st->total_lat_ns += lat; if (lat > st->max_lat_ns) st->max_lat_ns = lat; }
	bpf_map_delete_elem(&io_map, &k);
	return 0;
}
