#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "mutexlock.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

/**
 * @struct mutex_info
 * 单把mutex锁的长期统计结构体，存储在kmutex_map哈希表
 * @field locked_total 该锁累计所有持有总时长(ns)
 * @field locked_max 该锁单次最大持有时长(ns)
 * @field contended_total 该锁发生竞争阻塞总次数
 * @field acquire_time mutex_lock入口记录的纳秒时间戳，解锁时计算持有耗时
 * @field ptr 当前mutex内核虚拟地址，唯一标识一把锁
 * @field count 上锁总次数（预留扩展）
 * @field last_owner 最后持有该锁的进程PID
 * @field last_name 最后持有锁的进程名
 */
/* 锁统计信息 */
struct mutex_info {
	bpf_u64_t locked_total, locked_max, contended_total, acquire_time, ptr;
	bpf_s32_t count, last_owner;
	bpf_s8_t  last_name[TASK_COMM_LEN];
};

/*
 * kmutex_map：每把mutex独立统计哈希MAP
 * 类型：BPF_MAP_TYPE_HASH，key为struct mutex*内核地址，每一把锁一条记录
 * max_entries=1024：限制监控最大并发不同mutex数量，防止内核内存溢出
 * value：mutex_info 持久保存单锁持有时长、竞争次数、最后持有者
 * 读写流程：mutex_lock写入acquire_time；mutex_unlock更新累计/最大持有时长；slowpath累加竞争计数
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH); 
	__uint(max_entries, 1024);
	__type(key, bpf_u64_t); 
	__type(value, struct mutex_info);
} kmutex_map SEC(".maps");

/* PERCPU 竞争等待暂存：kprobe/slowpath 写入，kretprobe 读取计算争用时延 */
struct contention_data {
	bpf_u64_t addr, enter_ts;
	bpf_s32_t owner_pid, contender_pid;
	bpf_s32_t owner_prio, contender_prio;
	bpf_s8_t  owner_name[TASK_COMM_LEN];
	bpf_s8_t  contender_name[TASK_COMM_LEN];
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
	__type(key, int); __type(value, struct contention_data);
} slowpath_map SEC(".maps");

/*
 * ctrl_map：全局监控控制参数数组MAP
 * 全局单条配置，存储Mutexlock_ctrl开关、过滤PID、阈值（min_delay_ns预留）
 * 用户态启动时写入，所有探针统一读取过滤规则
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY); 
	__uint(max_entries, 1);
	__type(key, int); 
	__type(value, struct Mutexlock_ctrl);
} ctrl_map SEC(".maps");

/*
 * stats_map：整机全局锁竞争汇总统计MAP
 * 存储全局竞争总次数、最长锁持有记录，程序退出用户态读取打印汇总报表
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY); 
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Mutexlock_stats);
} stats_map SEC(".maps");

/*
 * rb：RingBuf环形缓冲区，内核向用户态推送锁竞争事件通道
 * 容量256KB，仅锁发生阻塞进入slowpath时才下发Mutexlock_event事件
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
 * @brief 工具函数：获取全局监控配置
 * @return ctrl_map全局控制结构体指针
 */
static inline struct Mutexlock_ctrl *get_ctrl(void)
{ 
	return bpf_map_lookup_elem(&ctrl_map, &ctrl_key); 
}

/**
 * @brief 初始化新mutex锁的统计结构体
 * @param info 待初始化mutex_info指针
 * @param addr mutex内核虚拟地址
 * @param ts 本次上锁入口时间戳
 * @param pid 当前上锁进程PID
 */
static void init_mutex_info(struct mutex_info *info, bpf_u64_t addr, bpf_u64_t ts, bpf_s32_t pid)
{
	info->locked_total = 0; 
	info->locked_max = 0; 
	info->contended_total = 0;
	info->count = 0; 
	info->last_owner = pid; 
	info->acquire_time = ts; 
	info->ptr = addr;
	__builtin_memset(info->last_name, 0, sizeof(info->last_name));
	bpf_get_current_comm(&info->last_name, sizeof(info->last_name));
}

/*
 * kprobe/mutex_lock：互斥锁上锁入口探针
 * 作用：记录上锁起始时间戳到kmutex_map，新锁自动初始化统计条目
 * 仅监控开启时执行；不产生事件，仅做计时缓存
 */
 /**
 * @brief mutex_lock上锁入口，记录获取锁的起点时间
 * @param lock 当前操作的struct mutex内核指针
 * @return 0 BPF探针标准返回
 */
SEC("kprobe/mutex_lock")
int BPF_KPROBE(mutex_lock_trace, struct mutex *lock)
{
	struct Mutexlock_ctrl *c = get_ctrl();
	if (!c || !c->enable) return 0;

	bpf_u64_t addr = (bpf_u64_t)lock;
	bpf_u64_t ts = bpf_ktime_get_ns();
	// 根据锁地址查询单锁统计信息
	struct mutex_info *info = bpf_map_lookup_elem(&kmutex_map, &addr);
	if (info) {
		// 已有记录，更新本次上锁起始时间戳
		info->acquire_time = ts;
	} else {
		// 哈希表无此锁记录，初始化并插入新条目
		struct mutex_info ni;
		init_mutex_info(&ni, addr, ts, 0);
		bpf_map_update_elem(&kmutex_map, &addr, &ni, BPF_ANY);
	}
	return 0;
}

/*
 * kprobe/mutex_unlock：互斥锁释放探针
 * 作用：读取上锁缓存时间戳，计算本次锁持有时长，更新单锁累计/最大持有指标
 * 不推送事件，仅更新kmutex_map内单锁统计数据
 */
 /**
 * @brief mutex_unlock释放锁钩子，计算并更新锁持有耗时统计
 * @param lock 待释放的struct mutex内核指针
 * @return 0 BPF探针标准返回
 */
SEC("kprobe/mutex_unlock")
int BPF_KPROBE(mutex_unlock_trace, struct mutex *lock)
{
	struct Mutexlock_ctrl *c = get_ctrl();
	if (!c || !c->enable) return 0;

	bpf_u64_t addr = (bpf_u64_t)lock;
	bpf_u64_t ts = bpf_ktime_get_ns();
	bpf_s32_t pid = bpf_get_current_pid_tgid();
	struct mutex_info *info = bpf_map_lookup_elem(&kmutex_map, &addr);
	if (info) {
		// 计算本次锁持有总纳秒
		u64 held = ts - info->acquire_time;
		// 累加该锁全部持有总时长
		info->locked_total += held;
		// 刷新单次最大持有时长
		if (held > info->locked_max)
			info->locked_max = held;
		// 更新最后持有者PID与进程名
		info->last_owner = pid;
		bpf_get_current_comm(&info->last_name, sizeof(info->last_name));
	}
	return 0;
}

/*
 * kprobe/__mutex_lock_slowpath 锁慢路径探测钩子
 * 核心背景：
 * 内核mutex上锁分两条路径：
 * 1. fastpath：锁空闲，无竞争，直接获取，不会进入本函数；
 * 2. slowpath：锁已被其他线程持有，当前线程需要阻塞等待，发生锁竞争，才会执行 __mutex_lock_slowpath
 * 本探针专门捕获**锁竞争阻塞事件**，推送实时竞争详情给用户态，并累加全局竞争统计计数
 * 过滤规则：监控总开关关闭 / 指定target_pid且当前线程不匹配，则直接丢弃本次竞争事件
 */
/**
* @brief 捕获mutex锁发生竞争阻塞的慢路径，封装竞争事件下发ringbuf并更新全局竞争统计
* @param lock 发生竞争阻塞的内核 struct mutex 互斥锁对象指针
* @return 0 BPF探针固定返回值
*/
SEC("kprobe/__mutex_lock_slowpath")
int BPF_KPROBE(mutex_slowpath_entry, struct mutex *lock)
{
	struct Mutexlock_ctrl *c = get_ctrl();
	if (!c || !c->enable) return 0;
	bpf_s32_t pid = bpf_get_current_pid_tgid();
	if (c->target_pid != 0 && pid != c->target_pid) return 0;

	int key = 0;
	struct contention_data *d = bpf_map_lookup_elem(&slowpath_map, &key);
	if (!d) return 0;

	d->enter_ts = bpf_ktime_get_ns();
	d->addr = (bpf_u64_t)lock;
	d->contender_pid = pid;
	bpf_get_current_comm(&d->contender_name, sizeof(d->contender_name));

	long owner;
	bpf_probe_read_kernel(&owner, sizeof(owner), &lock->owner);
	struct task_struct *owner_task = (struct task_struct *)(owner & ~0x1L);
	struct task_struct *ctask = (struct task_struct *)bpf_get_current_task();
	bpf_probe_read_kernel(&d->contender_prio, sizeof(d->contender_prio), &ctask->prio);

	if (owner_task) {
		bpf_probe_read_kernel(&d->owner_pid, sizeof(d->owner_pid), &owner_task->pid);
		bpf_probe_read_kernel_str(&d->owner_name, sizeof(d->owner_name), owner_task->comm);
		bpf_probe_read_kernel(&d->owner_prio, sizeof(d->owner_prio), &owner_task->prio);
	} else {
		d->owner_pid = 0;
		__builtin_memset(d->owner_name, 0, sizeof(d->owner_name));
		d->owner_prio = 0;
	}
	return 0;
}

/* kretprobe: 计算出竞争等待总耗时，过滤、下发事件、更新统计 */
SEC("kretprobe/__mutex_lock_slowpath")
int BPF_KRETPROBE(mutex_slowpath_exit, int ret)
{
	struct Mutexlock_ctrl *c = get_ctrl();
	if (!c || !c->enable) return 0;

	int key = 0;
	struct contention_data *d = bpf_map_lookup_elem(&slowpath_map, &key);
	if (!d || d->enter_ts == 0) return 0;

	bpf_u64_t now = bpf_ktime_get_ns();
	bpf_u64_t contention_ns = now - d->enter_ts;
	d->enter_ts = 0;

	if (c->min_delay_ns && contention_ns < c->min_delay_ns) return 0;

	struct Mutexlock_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) return 0;

	e->ptr = d->addr;
	e->owner_pid = d->owner_pid;
	e->contender_pid = d->contender_pid;
	e->owner_prio = d->owner_prio;
	e->contender_prio = d->contender_prio;
	e->contention_ns = contention_ns;
	__builtin_memcpy(e->owner_name, d->owner_name, TASK_COMM_LEN);
	__builtin_memcpy(e->contender_name, d->contender_name, TASK_COMM_LEN);

	bpf_ringbuf_submit(e, 0);

	struct Mutexlock_stats *st = bpf_map_lookup_elem(&stats_map, &ctrl_key);
	if (!st) { struct Mutexlock_stats z = {}; bpf_map_update_elem(&stats_map, &ctrl_key, &z, BPF_ANY); st = bpf_map_lookup_elem(&stats_map, &ctrl_key); }
	if (st) st->contention_count++;
	return 0;
}

 
