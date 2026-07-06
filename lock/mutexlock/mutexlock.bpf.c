#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "mutexlock.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
const int ctrl_key = 0;

/* 锁统计信息 */
struct mutex_info {
	bpf_u64_t locked_total, locked_max, contended_total, acquire_time, ptr;
	bpf_s32_t count, last_owner;
	bpf_s8_t  last_name[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
	__type(key, bpf_u64_t); __type(value, struct mutex_info);
} kmutex_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
	__type(key, int); __type(value, struct Mutexlock_ctrl);
} ctrl_map SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
	__type(key, int); __type(value, struct Mutexlock_stats);
} stats_map SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static inline struct Mutexlock_ctrl *get_ctrl(void)
{ return bpf_map_lookup_elem(&ctrl_map, &ctrl_key); }

static void init_mutex_info(struct mutex_info *info, bpf_u64_t addr, bpf_u64_t ts, bpf_s32_t pid)
{
	info->locked_total = 0; info->locked_max = 0; info->contended_total = 0;
	info->count = 0; info->last_owner = pid; info->acquire_time = ts; info->ptr = addr;
	__builtin_memset(info->last_name, 0, sizeof(info->last_name));
	bpf_get_current_comm(&info->last_name, sizeof(info->last_name));
}

/* kprobe/mutex_lock: 记录获取时间 */
SEC("kprobe/mutex_lock")
int BPF_KPROBE(mutex_lock_trace, struct mutex *lock)
{
	struct Mutexlock_ctrl *c = get_ctrl();
	if (!c || !c->enable) return 0;
	bpf_u64_t addr = (bpf_u64_t)lock; bpf_u64_t ts = bpf_ktime_get_ns();
	struct mutex_info *info = bpf_map_lookup_elem(&kmutex_map, &addr);
	if (info) info->acquire_time = ts;
	else { struct mutex_info ni; init_mutex_info(&ni, addr, ts, 0); bpf_map_update_elem(&kmutex_map, &addr, &ni, BPF_ANY); }
	return 0;
}

/* kprobe/mutex_unlock: 计算持有时间 */
SEC("kprobe/mutex_unlock")
int BPF_KPROBE(mutex_unlock_trace, struct mutex *lock)
{
	struct Mutexlock_ctrl *c = get_ctrl();
	if (!c || !c->enable) return 0;
	bpf_u64_t addr = (bpf_u64_t)lock; bpf_u64_t ts = bpf_ktime_get_ns();
	bpf_s32_t pid = bpf_get_current_pid_tgid();
	struct mutex_info *info = bpf_map_lookup_elem(&kmutex_map, &addr);
	if (info) { u64 held = ts - info->acquire_time; info->locked_total += held; if (held > info->locked_max) info->locked_max = held; info->last_owner = pid; bpf_get_current_comm(&info->last_name, sizeof(info->last_name)); }
	return 0;
}

/* kprobe/__mutex_lock_slowpath: 竞争事件 */
SEC("kprobe/__mutex_lock_slowpath")
int BPF_KPROBE(mutex_slowpath_trace, struct mutex *lock)
{
	struct Mutexlock_ctrl *c = get_ctrl();
	if (!c || !c->enable) return 0;
	bpf_u64_t addr = (bpf_u64_t)lock;
	bpf_s32_t pid = bpf_get_current_pid_tgid();
	if (c->target_pid != 0 && pid != c->target_pid) return 0;

	struct Mutexlock_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;
	e->ptr = addr; e->contender_pid = pid;
	bpf_get_current_comm(&e->contender_name, sizeof(e->contender_name));
	long owner; bpf_probe_read_kernel(&owner, sizeof(owner), &lock->owner);
	struct task_struct *owner_task = (struct task_struct *)(owner & ~0x1L);
	struct task_struct *ctask = (struct task_struct *)bpf_get_current_task();
	bpf_probe_read_kernel(&e->contender_prio, sizeof(e->contender_prio), &ctask->prio);
	if (owner_task) {
		bpf_probe_read_kernel(&e->owner_pid, sizeof(e->owner_pid), &owner_task->pid);
		bpf_probe_read_kernel_str(&e->owner_name, sizeof(e->owner_name), owner_task->comm);
		bpf_probe_read_kernel(&e->owner_prio, sizeof(e->owner_prio), &owner_task->prio);
	} else { e->owner_pid = 0; __builtin_memset(e->owner_name, 0, sizeof(e->owner_name)); }
	bpf_ringbuf_submit(e, 0);

	/* stats */
	struct Mutexlock_stats *st = bpf_map_lookup_elem(&stats_map, &ctrl_key);
	if (!st) { struct Mutexlock_stats z = {}; bpf_map_update_elem(&stats_map, &ctrl_key, &z, BPF_ANY); st = bpf_map_lookup_elem(&stats_map, &ctrl_key); }
	if (st) { st->contention_count++; }
	return 0;
}
