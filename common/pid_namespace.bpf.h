#ifndef COMMON_PID_NAMESPACE_BPF_H
#define COMMON_PID_NAMESPACE_BPF_H

/* 最深嵌套 32 层足以覆盖内核允许的 PID namespace 层级。 */
#define APP_PIDNS_MAX_LEVEL 32

/*
 * 获取指定 PID namespace 中当前线程的 TGID/TID。
 * 返回 0 表示当前任务在该 namespace 中不可见，调用方应跳过该事件。
 */
static __always_inline bpf_u64_t
app_current_pid_tgid_ns(bpf_u64_t dev, bpf_u64_t ino)
{
	struct bpf_pidns_info info = {};

	if (!ino)
		return bpf_get_current_pid_tgid();
	if (bpf_get_ns_current_pid_tgid(dev, ino, &info, sizeof(info)) < 0)
		return 0;
	return ((bpf_u64_t)info.tgid << 32) | info.pid;
}

/* 从 task_struct 的 struct pid 层级中解析指定 namespace 可见的 PID。 */
static __always_inline bpf_s32_t
app_pid_nr_in_ns(struct pid *pid, bpf_u64_t ino)
{
	bpf_u32_t level;

	if (!pid || !ino)
		return 0;
	level = BPF_CORE_READ(pid, level);
	if (level >= APP_PIDNS_MAX_LEVEL)
		return 0;

#pragma unroll
	for (int i = 0; i < APP_PIDNS_MAX_LEVEL; i++) {
		struct upid upid = {};
		bpf_u32_t inum;

		if (i > level)
			break;
		bpf_core_read(&upid, sizeof(upid), &pid->numbers[i]);
		if (!upid.ns)
			continue;
		inum = BPF_CORE_READ(upid.ns, ns.inum);
		if ((bpf_u64_t)inum == ino)
			return upid.nr;
	}
	return 0;
}

static __always_inline bpf_s32_t
app_task_tid_ns(struct task_struct *task, bpf_u64_t ino)
{
	struct pid *pid;

	if (!task)
		return 0;
	pid = BPF_CORE_READ(task, thread_pid);
	return app_pid_nr_in_ns(pid, ino);
}

static __always_inline bpf_s32_t
app_task_tgid_ns(struct task_struct *task, bpf_u64_t ino)
{
	struct task_struct *leader;
	struct pid *pid;

	if (!task)
		return 0;
	leader = BPF_CORE_READ(task, group_leader);
	if (!leader)
		return 0;
	pid = BPF_CORE_READ(leader, thread_pid);
	return app_pid_nr_in_ns(pid, ino);
}

#endif
