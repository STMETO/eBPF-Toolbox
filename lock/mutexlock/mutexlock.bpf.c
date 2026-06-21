// eBPF程序必须包含的内核类型定义
#include <vmlinux.h>

// eBPF核心帮助函数库
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// 包含我们自己定义的共用结构体
#include "mutexlock.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ========================== 全局常量定义 ==========================
const int ctrl_key = 0;

// ========================== 内部结构体定义 ==========================

/*
 * 互斥锁统计信息结构体（内部使用，存储于 map 中）
 * 记录每把锁的累计持有时间、竞争次数等统计信息
 */
struct mutex_info {
	bpf_u64_t locked_total;            // 锁被持有的总时间
	bpf_u64_t locked_max;              // 锁被持有的最长时间
	bpf_u64_t contended_total;         // 锁发生竞争的总时间
	bpf_s32_t count;                   // 记录锁被争用的总次数
	bpf_s32_t last_owner;              // 最后一次持有该锁的线程 ID
	bpf_s8_t  last_name[TASK_COMM_LEN]; // 最后一次持有该锁的线程名称
	bpf_u64_t acquire_time;            // 锁每次被获取的时间戳
	bpf_u64_t ptr;                     // 锁的地址
};

/*
 * trylock 暂存信息结构体（内部使用）
 * trylock 必须等函数返回才知结果，先把信息暂存
 */
struct trylock_info {
	bpf_u64_t __mutex;                 // 用户态 mutex 指针
	bpf_u64_t start_time;              // trylock 调用时间戳
};

// ========================== eBPF MAP 定义 ==========================

/*
 * 1. 内核态互斥锁信息 map
 * key：锁地址  value：struct mutex_info
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, bpf_u64_t);
	__type(value, struct mutex_info);
} kmutex_info_map SEC(".maps");

/*
 * 2. 用户态互斥锁信息 map
 * key：锁地址  value：struct mutex_info
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, bpf_u64_t);
	__type(value, struct mutex_info);
} umutex_info_map SEC(".maps");

/*
 * 3. trylock 暂存 map
 * key：pid_tgid  value：struct trylock_info
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, bpf_u64_t);
	__type(value, struct trylock_info);
} trylock_map SEC(".maps");

/*
 * 4. 全局控制 map
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct MutexLock_Delay_ctrl);
} ctrl_map SEC(".maps");

/*
 * 5. 环形缓冲区（ringbuf）
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// ========================== 工具函数 ==========================

/*
 * 获取监控开关状态
 */
static inline struct MutexLock_Delay_ctrl *get_ctrl(void)
{
	struct MutexLock_Delay_ctrl *ctrl;
	ctrl = bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
	if (!ctrl || !ctrl->enable)
		return NULL;
	return ctrl;
}

/*
 * 初始化互斥锁统计信息
 */
static inline void init_mutex_info(struct mutex_info *info, bpf_u64_t lock_addr,
				    bpf_u64_t ts, bpf_s32_t pid)
{
	info->locked_total = 0;
	info->locked_max = 0;
	info->contended_total = 0;
	info->count = 0;
	info->last_owner = pid;
	info->acquire_time = ts;
	info->ptr = lock_addr;
	__builtin_memset(info->last_name, 0, sizeof(info->last_name));
	bpf_get_current_comm(&info->last_name, sizeof(info->last_name));
}

/*
 * 更新锁持有者信息
 */
static inline void update_mutex_info(struct mutex_info *info, bpf_u64_t ts, bpf_s32_t pid)
{
	info->acquire_time = ts;
	info->last_owner = pid;
	bpf_get_current_comm(&info->last_name, sizeof(info->last_name));
}

// ========================== 挂载点：内核态互斥锁 ==========================

/*
 * kprobe/mutex_lock
 * 触发时机：内核线程调用 mutex_lock() 申请锁
 * 作用：记录锁获取时间，为后续统计做准备
 */
SEC("kprobe/mutex_lock")
int BPF_KPROBE(trace_mutex_lock, struct mutex *lock)
{
	struct MutexLock_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	bpf_u64_t lock_addr = (bpf_u64_t)lock;
	bpf_u64_t ts = bpf_ktime_get_ns();

	struct mutex_info *info = bpf_map_lookup_elem(&kmutex_info_map, &lock_addr);
	if (info) {
		info->acquire_time = ts;
	} else {
		struct mutex_info new_info;
		init_mutex_info(&new_info, lock_addr, ts, 0);
		bpf_map_update_elem(&kmutex_info_map, &lock_addr, &new_info, BPF_ANY);
	}
	return 0;
}

/*
 * kprobe/mutex_trylock
 * 触发时机：内核调用 mutex_trylock() 尝试加锁
 * 作用：只有加锁成功才记录获取时间
 */
SEC("kprobe/mutex_trylock")
int BPF_KPROBE(trace_mutex_trylock, struct mutex *lock)
{
	struct MutexLock_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	int ret = PT_REGS_RC(ctx);
	if (ret != 0) {
		bpf_u64_t lock_addr = (bpf_u64_t)lock;
		bpf_u64_t ts = bpf_ktime_get_ns();

		struct mutex_info *info = bpf_map_lookup_elem(&kmutex_info_map, &lock_addr);
		if (info) {
			info->acquire_time = ts;
		} else {
			struct mutex_info new_info;
			init_mutex_info(&new_info, lock_addr, ts, 0);
			bpf_map_update_elem(&kmutex_info_map, &lock_addr, &new_info, BPF_ANY);
		}
	}
	return 0;
}

/*
 * kprobe/__mutex_lock_slowpath
 * 触发时机：锁被占用，发生竞争（慢路径）
 * 作用：记录竞争事件，通过 ringbuf 发给用户态
 */
SEC("kprobe/__mutex_lock_slowpath")
int BPF_KPROBE(trace_mutex_lock_slowpath, struct mutex *lock)
{
	struct MutexLock_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	bpf_u64_t lock_addr = (bpf_u64_t)lock;
	bpf_u64_t ts = bpf_ktime_get_ns();

	/* ===== 构造竞争事件并发送到用户态 ===== */
	struct MutexLock_Delay_event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	bpf_s32_t pid = (bpf_s32_t)bpf_get_current_pid_tgid();
	struct task_struct *owner_task, *contender_task;
	long owner;

	e->contender_pid = pid;
	e->ptr = lock_addr;
	bpf_get_current_comm(&e->contender_name, sizeof(e->contender_name));

	bpf_probe_read_kernel(&owner, sizeof(owner), &lock->owner);

	/* 内核 mutex 最低位是标记位，需要去掉 */
	owner_task = (struct task_struct *)(owner & ~0x1L);
	contender_task = (struct task_struct *)bpf_get_current_task();

	bpf_probe_read_kernel(&e->contender_prio, sizeof(e->contender_prio),
			      &contender_task->prio);

	if (owner_task) {
		bpf_probe_read_kernel(&e->owner_pid, sizeof(e->owner_pid),
				      &owner_task->pid);
		bpf_probe_read_kernel_str(&e->owner_name, sizeof(e->owner_name),
					  owner_task->comm);
		bpf_probe_read_kernel(&e->owner_prio, sizeof(e->owner_prio),
				      &owner_task->prio);
	} else {
		e->owner_pid = 0;
		__builtin_memset(e->owner_name, 0, sizeof(e->owner_name));
	}

	/* 更新锁竞争统计 */
	struct mutex_info *info = bpf_map_lookup_elem(&kmutex_info_map, &lock_addr);
	if (info) {
		bpf_u64_t contention_start = ts;
		info->contended_total += (contention_start - info->acquire_time);
		info->count++;
	} else {
		struct mutex_info new_info;
		init_mutex_info(&new_info, lock_addr, ts, 0);
		new_info.count = 1;
		bpf_map_update_elem(&kmutex_info_map, &lock_addr, &new_info, BPF_ANY);
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * kprobe/mutex_unlock
 * 触发时机：内核线程释放锁
 * 作用：计算锁持有时间，更新统计信息
 */
SEC("kprobe/mutex_unlock")
int BPF_KPROBE(trace_mutex_unlock, struct mutex *lock)
{
	struct MutexLock_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	bpf_u64_t lock_addr = (bpf_u64_t)lock;
	bpf_u64_t ts = bpf_ktime_get_ns();
	bpf_s32_t pid = (bpf_s32_t)bpf_get_current_pid_tgid();

	struct mutex_info *info = bpf_map_lookup_elem(&kmutex_info_map, &lock_addr);
	if (info) {
		bpf_u64_t held_time = ts - info->acquire_time;
		info->locked_total += held_time;
		if (held_time > info->locked_max)
			info->locked_max = held_time;
		info->last_owner = pid;
		bpf_get_current_comm(&info->last_name, sizeof(info->last_name));
	}
	return 0;
}

// ========================== 挂载点：用户态互斥锁 ==========================

/*
 * 处理用户态互斥锁加锁
 * 统计锁竞争 & 更新锁信息
 */
static inline void handle_user_mutex_lock(void *__mutex, bpf_u64_t now, bpf_s32_t pid)
{
	bpf_u64_t m = (bpf_u64_t)__mutex;
	struct mutex_info *info = bpf_map_lookup_elem(&umutex_info_map, &m);

	if (info) {
		if (info->acquire_time > 0) {
			info->contended_total += (now - info->acquire_time);
			info->count++;
		}
		update_mutex_info(info, now, pid);
	} else {
		struct mutex_info new_info;
		init_mutex_info(&new_info, m, now, pid);
		bpf_map_update_elem(&umutex_info_map, &m, &new_info, BPF_ANY);
	}
}

/*
 * uprobe/libc:pthread_mutex_lock
 * 触发时机：用户态程序调用 pthread_mutex_lock()
 */
SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:pthread_mutex_lock")
int BPF_KPROBE(pthread_mutex_lock, void *__mutex)
{
	struct MutexLock_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	bpf_u64_t now = bpf_ktime_get_ns();
	bpf_s32_t pid = (bpf_s32_t)(bpf_get_current_pid_tgid() >> 32);
	handle_user_mutex_lock(__mutex, now, pid);
	return 0;
}

/*
 * uprobe/__pthread_mutex_trylock
 * 触发时机：用户态调用 pthread_mutex_trylock()
 * 作用：暂存锁地址+时间，等 uretprobe 判断成功/失败
 */
SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:__pthread_mutex_trylock")
int BPF_KPROBE(__pthread_mutex_trylock, void *__mutex)
{
	struct MutexLock_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	bpf_u64_t pid_tgid = bpf_get_current_pid_tgid();
	bpf_u64_t now = bpf_ktime_get_ns();

	struct trylock_info info = {
		.__mutex = (bpf_u64_t)__mutex,
		.start_time = now,
	};
	bpf_map_update_elem(&trylock_map, &pid_tgid, &info, BPF_ANY);
	return 0;
}

/*
 * uretprobe/__pthread_mutex_trylock
 * 触发时机：pthread_mutex_trylock() 返回时
 * 作用：判断是否加锁成功，成功则更新锁信息
 */
SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:__pthread_mutex_trylock")
int BPF_KRETPROBE(ret_pthread_mutex_trylock, int ret)
{
	struct MutexLock_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	bpf_u64_t pid_tgid = bpf_get_current_pid_tgid();

	struct trylock_info *try_info = bpf_map_lookup_elem(&trylock_map, &pid_tgid);
	if (!try_info)
		return 0;

	if (ret == 0) {
		handle_user_mutex_lock((void *)try_info->__mutex,
				       try_info->start_time,
				       (bpf_s32_t)(pid_tgid >> 32));
	}

	bpf_map_delete_elem(&trylock_map, &pid_tgid);
	return 0;
}

/*
 * uprobe/pthread_mutex_unlock
 * 触发时机：用户态程序释放锁
 * 作用：计算锁持有时间，更新统计信息
 */
SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:pthread_mutex_unlock")
int BPF_KPROBE(pthread_mutex_unlock, void *__mutex)
{
	struct MutexLock_Delay_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;

	bpf_u64_t now = bpf_ktime_get_ns();
	bpf_s32_t pid = (bpf_s32_t)(bpf_get_current_pid_tgid() >> 32);
	bpf_u64_t m = (bpf_u64_t)__mutex;

	struct mutex_info *info = bpf_map_lookup_elem(&umutex_info_map, &m);
	if (info) {
		bpf_u64_t held_time = now - info->acquire_time;
		info->locked_total += held_time;
		if (held_time > info->locked_max)
			info->locked_max = held_time;
		info->last_owner = pid;
		bpf_get_current_comm(&info->last_name, sizeof(info->last_name));
	}
	return 0;
}
