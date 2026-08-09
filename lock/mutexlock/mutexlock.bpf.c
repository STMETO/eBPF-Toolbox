/*
流程：
	线程T尝试获取mutex锁，快速路径（__mutex_lock）抢锁失败；
	内核进入 __mutex_lock_slowpath 慢路径函数；
	kprobe/__mutex_lock_slowpath 探针触发；
		采集当前竞争线程信息、读取mutex瞬间的owner持锁task快照、记录进入慢路径时间enter_ts；
		以pid_tgid(线程唯一标识)为key，把全部快照存入contention_map(LRU_HASH)；
	线程T在slowpath内部做：自适应自旋、加入mutex等待队列、发生睡眠阻塞TASK_UNINTERRUPTIBLE；

	--- 此时线程T休眠，让出CPU；持锁线程继续运行 ---

	持锁线程执行mutex_unlock，唤醒等待队列上的线程T；
	线程T变为就绪态，进入runqueue调度队列排队，等待CPU调度；
	CPU调度器选中线程T，线程T恢复执行，再次争抢mutex；
	如果抢到锁，__mutex_lock_slowpath函数执行return返回；

	kretprobe/__mutex_lock_slowpath 探针触发；
		使用app_current_pid_tgid_ns拿到当前线程pid_tgid；
		通过pid_tgid从contention_map查找本次竞争保存的快照数据；
		wait_ns = 当前时刻 − enter_ts，算出整个慢路径耗时；
		判断是否大于min_delay_ns阈值，小于阈值直接丢弃事件；
		阈值达标：分配ringbuf事件，填充锁地址、竞争者、持锁者、耗时等字段；
		bpf_ringbuf_submit上报事件给用户态；
		bpf_map_delete_elem清理map中的线程上下文，避免内存泄露；

特殊边界说明：
1. kprobe入口抓取的owner只是【进入slowpath一瞬间快照】，等待过程锁可能发生handoff移交，owner会变化；上报的owner只是当时快照，不代表全程持有者。
2. LRU map淘汰、进程退出、探针乱序会产生lookup_miss统计，此时无法计算延时。
3. 这个延时 = 自旋重试时间 + 睡眠等待时间 + runqueue调度排队时间 + 醒来后再次抢锁的时间总和。
*/

/*
__mutex_lock()
    → fast path原子抢锁失败
    → __mutex_lock_slowpath()      ← kprobe入口
        → mutex_spin_on_owner()    // 自适应自旋
        → __mutex_lock_common()
            → add to wait_queue
            → schedule()          // 睡眠，让出CPU
        // 被unlock唤醒后回到这里
        → 再次尝试acquire锁
← kretprobe出口，函数返回，代表成功拿到锁
s
*/

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "mutexlock.h"
#include "common/pid_namespace.bpf.h"

/**
 * @brief BPF程序许可证声明
 * Dual BSD/GPL 允许内核kprobe追踪，非GPL协议无法挂载kprobe
 */
char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

/**
 * @brief Linux内核mutex owner字段掩码
 * struct mutex -> owner.counter 存储 task_struct* + 3个低位标志位
 * bit0: WAITERS, bit1: HANDOFF, bit2: PICKUP
 * 需要掩码清除低位标志才能拿到合法task_struct指针
 */
#define MUTEX_OWNER_FLAGS 0x7UL

/**
 * @brief 互斥锁竞争上下文数据
 * 保存线程进入mutex慢路径时的快照，kprobe入口存入，kretprobe取出计算等待耗时
 */
struct contention_data {
	bpf_u64_t addr;                 // mutex锁对象内核地址
	bpf_u64_t enter_ts;             // 进入__mutex_lock_slowpath时间戳(ns)
	bpf_s32_t owner_pid;            // 持锁者TID(当前pidns内)
	bpf_s32_t owner_tgid;           // 持锁者TGID(进程号，当前pidns内)
	bpf_s32_t contender_pid;        // 竞争线程TID(当前pidns内)
	bpf_s32_t contender_tgid;      // 竞争线程TGID(进程号，当前pidns内)
	bpf_s32_t owner_prio;           // 持锁进程调度优先级
	bpf_s32_t contender_prio;      // 竞争线程调度优先级
	bpf_s8_t owner_name[TASK_COMM_LEN];     // 持锁进程名称comm
	bpf_s8_t contender_name[TASK_COMM_LEN]; // 竞争线程进程名称comm
};

/**
 * @brief 线程竞争上下文哈希表
 * 类型：LRU_HASH，防止无限增长OOM
 * key: pid_tgid (低32位tid，高32位tgid，唯一标识一个线程)
 * value: contention_data 进入慢路径时快照
 * 设计说明：
 * __mutex_lock_slowpath 是睡眠慢路径，会发生CPU迁移，**不能使用PERCPU map**，
 * 必须以线程pid_tgid作为key关联入口与返回探针
 */
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

/**
 * @brief 统计信息Per-CPU数组Map
 * Per-CPU避免bpf内部原子竞争，用户态汇总各个cpu统计值
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Mutexlock_stats);
} stats_map SEC(".maps");

/**
 * @brief RingBuffer环形缓冲区
 * 用于向用户态高效推送锁竞争事件，相比perf buffer更加简单易用
 * 缓冲区大小：256KB
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
 * @brief 获取采集控制配置
 * @return Mutexlock_ctrl* 配置结构体指针，空表示未初始化
 */
static __always_inline struct Mutexlock_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
}

/**
 * @brief 获取per-cpu统计结构体
 * @return Mutexlock_stats* 当前CPU统计数据指针
 */
static __always_inline struct Mutexlock_stats *get_stats(void)
{
	return bpf_map_lookup_elem(&stats_map, &ctrl_key);
}

/**
 * @brief kprobe挂载点：__mutex_lock_slowpath 入口
 * 当mutex快速获取失败，进入慢路径（可能睡眠等待锁）时触发
 * @param lock 待获取的struct mutex对象指针
 */
SEC("kprobe/__mutex_lock_slowpath")
int BPF_KPROBE(mutex_slowpath_entry, struct mutex *lock)
{
	struct Mutexlock_ctrl *ctrl = get_ctrl();
	struct Mutexlock_stats *stats;
	struct contention_data data = {};
	struct task_struct *owner_task;
	bpf_u64_t pid_tgid;
	unsigned long owner;

	// 配置不存在 或者 采集开关关闭，直接退出
	if (!ctrl || !ctrl->enable)
		return 0;

	/*
	 * 获取当前线程在目标pid namespace下的pid_tgid
	 * 参数为目标pidns设备号与inode，实现容器内PID追踪
	 * 返回值格式：低32bit=TID，高32bit=TGID
	 * 返回0代表pidns不匹配，忽略本次事件
	 */
	pid_tgid = app_current_pid_tgid_ns(ctrl->pid_ns_dev, ctrl->pid_ns_ino);
	if (!pid_tgid)
		return 0;

	// 填充竞争者线程PID信息（当前正在尝试获取锁的线程）
	data.contender_pid = (bpf_s32_t)pid_tgid;
	data.contender_tgid = (bpf_s32_t)(pid_tgid >> 32);

	// 如果配置了目标进程过滤，且当前线程不属于目标进程，直接丢弃
	if (ctrl->target_pid && data.contender_tgid != ctrl->target_pid)
		return 0;

	// 统计：进入慢路径尝试次数+1
	stats = get_stats();
	if (stats)
		stats->attempted++;

	data.addr = (bpf_u64_t)lock;                // 记录mutex内核地址
	data.enter_ts = bpf_ktime_get_ns();         // 记录进入慢路径时刻
	// 获取当前线程调度优先级
	data.contender_prio = BPF_CORE_READ((struct task_struct *)bpf_get_current_task(), prio);
	// 获取竞争者进程名称 comm
	bpf_get_current_comm(data.contender_name, sizeof(data.contender_name));

	/*
	 * 读取mutex owner字段：lock->owner.counter
	 * 内核mutex设计：owner存储task_struct指针 + 3bit状态标志
	 * owner & ~MUTEX_OWNER_FLAGS 清除低位标志，得到持锁task_struct指针
	 * 注意：这只是【进入慢路径瞬间】的快照，等待过程中锁可能发生owner移交，
	 * 仅作为溯源线索，不能代表整个等待周期持续持有者
	 */
	owner = (unsigned long)BPF_CORE_READ(lock, owner.counter);
	owner_task = (struct task_struct *)(owner & ~MUTEX_OWNER_FLAGS);
	if (owner_task) {
		// 读取持锁者在目标pidns内的tid、tgid
		data.owner_pid = app_task_tid_ns(owner_task, ctrl->pid_ns_ino);
		data.owner_tgid = app_task_tgid_ns(owner_task, ctrl->pid_ns_ino);
		// 持锁任务调度优先级
		data.owner_prio = BPF_CORE_READ(owner_task, prio);
		// 读取持锁进程名称comm
		bpf_probe_read_kernel_str(data.owner_name, sizeof(data.owner_name), owner_task->comm);
	}

	// 将竞争上下文存入LRU Hash，key=线程pid_tgid，供kretprobe读取
	// BPF_ANY: 存在则覆盖，不存在新建
	if (bpf_map_update_elem(&contention_map, &pid_tgid, &data, BPF_ANY) && stats)
		stats->map_update_failed++;

	return 0;
}

/**
 * @brief kretprobe挂载点：__mutex_lock_slowpath 返回
 * 函数正常返回代表：竞争者成功获取mutex锁
 * 计算等待耗时，组装事件发送到ringbuf给到用户态
 */
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

	// 获取当前线程在目标pidns内pid_tgid，和入口探针key保持一致
	pid_tgid = app_current_pid_tgid_ns(ctrl->pid_ns_dev, ctrl->pid_ns_ino);
	if (!pid_tgid)
		return 0;

	// 根据线程pid_tgid查找入口保存的竞争快照
	data = bpf_map_lookup_elem(&contention_map, &pid_tgid);
	if (!data) {
		// 找不到上下文，统计miss（常见场景：探针乱序、进程提前退出、map被LRU淘汰）
		bpf_s32_t tgid = (bpf_s32_t)(pid_tgid >> 32);
		if (ctrl && ctrl->enable && stats &&
		    (!ctrl->target_pid || ctrl->target_pid == tgid))
			stats->lookup_missed++;
		return 0;
	}

	// 二次校验过滤条件：采集关闭 / 不匹配目标进程，清理map后退出
	if (!ctrl || !ctrl->enable ||
	    (ctrl->target_pid && data->contender_tgid != ctrl->target_pid)) {
		bpf_map_delete_elem(&contention_map, &pid_tgid);
		return 0;
	}

	// 计算等待时长：返回时刻 - 进入慢路径时刻
	wait_ns = bpf_ktime_get_ns() - data->enter_ts;

	// 最小延迟过滤：等待时间小于阈值，丢弃事件，不发送用户态
	if (ctrl->min_delay_ns && wait_ns < ctrl->min_delay_ns) {
		if (stats)
			stats->filtered_delay++;
		bpf_map_delete_elem(&contention_map, &pid_tgid);
		return 0;
	}

	// 从ringbuf预留一块内存存放事件，0=不使用特定flags
	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event) {
		// ringbuf缓冲区满，事件丢弃
		if (stats)
			stats->ringbuf_dropped++;
		bpf_map_delete_elem(&contention_map, &pid_tgid);
		return 0;
	}

	// 填充上报事件字段
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

	// 更新全局统计指标
	if (stats) {
		stats->contention_count++;
		stats->wait_total_ns += wait_ns;
		// 刷新最大等待耗时记录
		if (wait_ns > stats->wait_max_ns) {
			stats->wait_max_ns = wait_ns;
			stats->max_lock_addr = data->addr;
			stats->max_owner_pid = data->owner_pid;
			stats->max_contender_pid = data->contender_pid;
			__builtin_memcpy(stats->max_owner_name, data->owner_name, TASK_COMM_LEN);
			__builtin_memcpy(stats->max_contender_name, data->contender_name,
					 TASK_COMM_LEN);
		}
	}

	// 将事件提交到ringbuf，用户态可以读取
	bpf_ringbuf_submit(event, 0);
	// 清理hash表内线程上下文，避免map持续膨胀
	bpf_map_delete_elem(&contention_map, &pid_tgid);

	return 0;
}
