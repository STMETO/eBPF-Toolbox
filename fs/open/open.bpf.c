/*
 * fs/open — 监控进程 openat 系统调用
 *
 * 双挂载点设计：
 *   sys_enter_openat → 捕获 文件路径（ctx->args[1]）、PID
 *   sys_exit_openat  → 捕获 文件描述符（ctx->ret）、进程名（bpf_get_current_comm）
 *
 * 入口与出口数据通过 tid_map（key=tid，value=路径+PID）关联，
 * 出口时合并为完整事件一次性推送给用户态。
 */

/*
应用程序执行 openat()，触发陷入内核（syscall）
sys_enter_openat 触发 → 开始计时
内核开始整套打开文件逻辑：
    解析相对 / 绝对文件路径
    逐级查找目录项（dentry 查找）
    权限校验、inode 查找
    文件系统层操作（ext4/xfs/btrfs）
    如果需要，触发磁盘 IO 加载元数据（目录、inode）
    分配文件结构体、生成新 fd
所有逻辑跑完，准备切回用户态
sys_exit_openat 触发 → 停止计时
fd / 错误码返回给应用程序
*/ 

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "open.h"
#include "common/pid_namespace.bpf.h"

char LICENSE[] SEC("license") = "GPL";

const int ctrl_key = 0;

/* ========== MAP 定义 ========== */

/*
 * ctrl_map — 全局控制开关
 *   用户态写入 {enable: true/false}，控制采集启停
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Open_ctrl);
} ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Open_stats);
} stats_map SEC(".maps");


/**
* @struct entry_data
* tid_map哈希存储的临时上下文结构体，sys_enter_openat入口保存现场
* @field pid 发起openat调用的进程TGID
* @field path_name_ 用户态传入的待打开文件路径字符串
*/
struct entry_data {
	bpf_u64_t enter_ts;
	bpf_u64_t flags;
	bpf_s32_t pid;
	bpf_s32_t tid;
	bpf_s32_t dirfd;
	char path_name_[FS_OPEN_PATH_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);  /* 足够容纳并发 openat 的线程数 */
	__type(key, u32);            /* tid */
	__type(value, struct entry_data);
} tid_map SEC(".maps");

/*
 * rb — RingBuffer 事件输出
 *   出口阶段构造完整的 Open_event 后提交到此缓冲区，
 *   用户态 poll 读取
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* ========== 辅助函数 ========== */

static __always_inline struct Open_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
}

static __always_inline struct Open_stats *get_stats(void)
{
	return bpf_map_lookup_elem(&stats_map, (void *)&ctrl_key);
}

/*
 * ========== 挂载点 1：sys_enter_openat（入口） ==========
 *
 * 触发时机：进程刚进入 openat 系统调用，尚未分配 fd
 * 职责：捕获文件路径和 PID，暂存到 tid_map
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int openat_entry(struct trace_event_raw_sys_enter *ctx)
{
	struct Open_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	/* tid 作为 tid_map 的 key，入口/出口通过同一 tid 关联 */
	u64 pid_tgid = app_current_pid_tgid_ns(ctrl->pid_ns_dev, ctrl->pid_ns_ino);
	if (!pid_tgid)
		return 0;
	u32 tid = (u32)pid_tgid;        /* 低 32 位 = 线程 ID  */
	bpf_s32_t pid = (bpf_s32_t)(pid_tgid >> 32);  /* 高 32 位 = 进程 ID  */
	struct Open_stats *stats = get_stats();

	if (ctrl->target_pid != 0 && pid != ctrl->target_pid) {
		if (stats)
			stats->filtered_pid++;
		return 0;
	}
	if (stats)
		stats->attempted++;

	struct entry_data entry = {};
	entry.enter_ts = bpf_ktime_get_ns();
	entry.flags = ctx->args[2];
	entry.pid = pid;
	entry.tid = tid;
	entry.dirfd = (bpf_s32_t)ctx->args[0];

	/*
	 * openat 第二个参数是用户指针，必须用 user helper 有界读取。返回值包含
	 * 结尾 NUL；等于缓冲区大小说明可能被截断，负数说明指针读取失败。
	 */
	long path_len = bpf_probe_read_user_str(entry.path_name_, sizeof(entry.path_name_),
					(void *)ctx->args[1]);
	if (path_len < 0) {
		if (stats)
			stats->path_read_failed++;
		__builtin_memcpy(entry.path_name_, "<read-error>", sizeof("<read-error>"));
	} else if (path_len == sizeof(entry.path_name_)) {
		if (stats)
			stats->path_truncated++;
	}

	/*
	 * 用 namespace 可见 TID 而不是 TGID：同一进程的多个线程可以并发
	 * openat，TGID 会导致入口上下文互相覆盖。只有当前 namespace 可见的
	 * 任务才会走到这里，所以 TID 在该 Map 中唯一。
	 */
	if (bpf_map_update_elem(&tid_map, &tid, &entry, BPF_ANY) && stats)
		stats->map_update_failed++;

	return 0;
}

/*
 * ========== 挂载点 2：sys_exit_openat（出口） ==========
 *
 * 触发时机：openat 系统调用即将返回用户态，fd 已分配
 * 职责：获取 fd、进程名，组合入口数据发送完整事件
 */
SEC("tracepoint/syscalls/sys_exit_openat")
int openat_exit(struct trace_event_raw_sys_exit *ctx)
{
	struct Open_ctrl *ctrl = get_ctrl();
	if (!ctrl)
		return 0;
	u64 pid_tgid = app_current_pid_tgid_ns(ctrl->pid_ns_dev, ctrl->pid_ns_ino);
	if (!pid_tgid)
		return 0;
	u32 tid = (u32)pid_tgid;

	/* 从 tid_map 取出入口阶段暂存的路径、flags 和开始时间。 */
	struct entry_data *entry = bpf_map_lookup_elem(&tid_map, &tid);
	if (!entry) {
		struct Open_stats *stats = get_stats();
		bpf_s32_t pid = (bpf_s32_t)(pid_tgid >> 32);
		if (ctrl && ctrl->enable && stats &&
		    (ctrl->target_pid == 0 || ctrl->target_pid == pid))
			stats->lookup_missed++;
		return 0;  /* 没有对应入口记录（可能是开关中途开启），跳过 */
	}

	/* 开关可能在系统调用执行过程中被关闭，仍需清理入口状态。 */
	if (!ctrl || !ctrl->enable) {
		bpf_map_delete_elem(&tid_map, &tid);
		return 0;
	}

	struct Open_stats *stats = get_stats();
	bpf_u64_t now = bpf_ktime_get_ns();
	bpf_u64_t latency_ns = now - entry->enter_ts;
	s64 ret = ctx->ret;
	if (stats) {
		stats->completed++;
		if (ret < 0)
			stats->failed++;
		stats->total_ns += latency_ns;
		if (latency_ns > stats->max_ns) {
			stats->max_ns = latency_ns;
			stats->max_pid = entry->pid;
			bpf_get_current_comm(stats->max_comm, sizeof(stats->max_comm));
		}
	}

	/* PID 过滤 */
	if (ctrl->target_pid != 0 && entry->pid != ctrl->target_pid) {
		if (stats)
			stats->filtered_pid++;
		bpf_map_delete_elem(&tid_map, &tid);
		return 0;
	}
	/*
	 * 统计包含所有完成调用；阈值只控制明细是否进入 ringbuf。这样即使
	 * 用户只查看长尾事件，退出摘要仍能给出完整次数、失败率与平均耗时。
	 */
	if (ctrl->min_delay_ns && latency_ns < ctrl->min_delay_ns) {
		if (stats)
			stats->filtered_delay++;
		bpf_map_delete_elem(&tid_map, &tid);
		return 0;
	}


	/* 出口返回值：openat 成功返回 fd(≥0)，失败返回 -errno */
	bpf_s32_t fd = (ret >= 0) ? (bpf_s32_t)ret : (bpf_s32_t)-1;

	/* 预留 ringbuf 事件内存 */
	struct Open_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		if (stats)
			stats->ringbuf_dropped++;
		bpf_map_delete_elem(&tid_map, &tid);  /* 清理避免泄漏 */
		return 0;
	}

	/* ---- 组装完整事件 ---- */
	e->pid         = entry->pid;
	e->tid         = entry->tid;
	e->dirfd       = entry->dirfd;
	e->fd          = fd;
	e->ret         = ret;
	e->flags       = entry->flags;
	e->timestamp_ns = now;
	e->latency_ns  = latency_ns;
	__builtin_memcpy(e->path_name_, entry->path_name_, FS_OPEN_PATH_SIZE);

	/* 直接在这里获取进程名，不再绕 comm_cache / ctx 指针 */
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	if (stats)
		stats->submitted++;
	bpf_ringbuf_submit(e, 0);

	/* 清理 tid_map 中的临时记录，防止哈希表膨胀 */
	bpf_map_delete_elem(&tid_map, &tid);

	return 0;
}
