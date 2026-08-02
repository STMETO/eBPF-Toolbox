#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "mutexlock.h"
#include "common/pid_namespace.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

/* Linux mutex owner 指针低位保存 WAITERS/HANDOFF/PICKUP 标志。 */
#define MUTEX_OWNER_FLAGS 0x7UL

struct contention_data {
	bpf_u64_t addr;
	bpf_u64_t enter_ts;
	bpf_s32_t owner_pid;
	bpf_s32_t owner_tgid;
	bpf_s32_t contender_pid;
	bpf_s32_t contender_tgid;
	bpf_s32_t owner_prio;
	bpf_s32_t contender_prio;
	bpf_s8_t owner_name[TASK_COMM_LEN];
	bpf_s8_t contender_name[TASK_COMM_LEN];
};

/* slowpath 可能睡眠并迁移 CPU，必须按线程而不是按 CPU 关联入口和返回。 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, bpf_u64_t);
	__type(value, struct contention_data);
} contention_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Mutexlock_ctrl);
} ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Mutexlock_stats);
} stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline struct Mutexlock_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
}

static __always_inline struct Mutexlock_stats *get_stats(void)
{
	return bpf_map_lookup_elem(&stats_map, &ctrl_key);
}

SEC("kprobe/__mutex_lock_slowpath")
int BPF_KPROBE(mutex_slowpath_entry, struct mutex *lock)
{
	struct Mutexlock_ctrl *ctrl = get_ctrl();
	struct Mutexlock_stats *stats;
	struct contention_data data = {};
	struct task_struct *owner_task;
	bpf_u64_t pid_tgid;
	unsigned long owner;

	if (!ctrl || !ctrl->enable)
		return 0;

	pid_tgid = app_current_pid_tgid_ns(ctrl->pid_ns_dev, ctrl->pid_ns_ino);
	if (!pid_tgid)
		return 0;
	data.contender_pid = (bpf_s32_t)pid_tgid;
	data.contender_tgid = (bpf_s32_t)(pid_tgid >> 32);
	if (ctrl->target_pid && data.contender_tgid != ctrl->target_pid)
		return 0;

	stats = get_stats();
	if (stats)
		stats->attempted++;

	data.addr = (bpf_u64_t)lock;
	data.enter_ts = bpf_ktime_get_ns();
	data.contender_prio = BPF_CORE_READ((struct task_struct *)bpf_get_current_task(), prio);
	bpf_get_current_comm(data.contender_name, sizeof(data.contender_name));

	/*
	 * mutex owner 是 task_struct 指针与 WAITERS/HANDOFF/PICKUP 三个低位标志
	 * 的组合。这里记录的是进入慢路径瞬间的 owner 快照；等待期间 owner
	 * 仍可能发生交接，因此它用于定位线索而不是完整持锁历史。
	 */
	owner = (unsigned long)BPF_CORE_READ(lock, owner.counter);
	owner_task = (struct task_struct *)(owner & ~MUTEX_OWNER_FLAGS);
	if (owner_task) {
		data.owner_pid = app_task_tid_ns(owner_task, ctrl->pid_ns_ino);
		data.owner_tgid = app_task_tgid_ns(owner_task, ctrl->pid_ns_ino);
		data.owner_prio = BPF_CORE_READ(owner_task, prio);
		bpf_probe_read_kernel_str(data.owner_name, sizeof(data.owner_name), owner_task->comm);
	}

	if (bpf_map_update_elem(&contention_map, &pid_tgid, &data, BPF_ANY) && stats)
		stats->map_update_failed++;
	return 0;
}

SEC("kretprobe/__mutex_lock_slowpath")
int BPF_KRETPROBE(mutex_slowpath_exit)
{
	struct Mutexlock_ctrl *ctrl = get_ctrl();
	struct Mutexlock_stats *stats = get_stats();
	struct contention_data *data;
	struct Mutexlock_event *event;
	bpf_u64_t pid_tgid;
	bpf_u64_t wait_ns;

	if (!ctrl)
		return 0;
	pid_tgid = app_current_pid_tgid_ns(ctrl->pid_ns_dev, ctrl->pid_ns_ino);
	if (!pid_tgid)
		return 0;

	data = bpf_map_lookup_elem(&contention_map, &pid_tgid);
	if (!data) {
		bpf_s32_t tgid = (bpf_s32_t)(pid_tgid >> 32);
		if (ctrl && ctrl->enable && stats &&
		    (!ctrl->target_pid || ctrl->target_pid == tgid))
			stats->lookup_missed++;
		return 0;
	}

	if (!ctrl || !ctrl->enable ||
	    (ctrl->target_pid && data->contender_tgid != ctrl->target_pid)) {
		bpf_map_delete_elem(&contention_map, &pid_tgid);
		return 0;
	}

	/* slowpath 返回意味着竞争者已经取得锁，区间即实际慢路径等待耗时。 */
	wait_ns = bpf_ktime_get_ns() - data->enter_ts;
	if (ctrl->min_delay_ns && wait_ns < ctrl->min_delay_ns) {
		if (stats)
			stats->filtered_delay++;
		bpf_map_delete_elem(&contention_map, &pid_tgid);
		return 0;
	}

	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event) {
		if (stats)
			stats->ringbuf_dropped++;
		bpf_map_delete_elem(&contention_map, &pid_tgid);
		return 0;
	}

	event->ptr = data->addr;
	event->owner_pid = data->owner_pid;
	event->owner_tgid = data->owner_tgid;
	event->contender_pid = data->contender_pid;
	event->contender_tgid = data->contender_tgid;
	event->owner_prio = data->owner_prio;
	event->contender_prio = data->contender_prio;
	event->contention_ns = wait_ns;
	__builtin_memcpy(event->owner_name, data->owner_name, TASK_COMM_LEN);
	__builtin_memcpy(event->contender_name, data->contender_name, TASK_COMM_LEN);

	if (stats) {
		stats->contention_count++;
		stats->wait_total_ns += wait_ns;
		if (wait_ns > stats->wait_max_ns) {
			stats->wait_max_ns = wait_ns;
			stats->max_lock_addr = data->addr;
			stats->max_owner_pid = data->owner_pid;
			stats->max_contender_pid = data->contender_pid;
			__builtin_memcpy(stats->max_owner_name, data->owner_name, TASK_COMM_LEN);
			__builtin_memcpy(stats->max_contender_name, data->contender_name, TASK_COMM_LEN);
		}
	}

	bpf_ringbuf_submit(event, 0);
	bpf_map_delete_elem(&contention_map, &pid_tgid);
	return 0;
}
