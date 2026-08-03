#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "read.h"
#include "common/pid_namespace.bpf.h"

/**
 * @brief BPF程序许可证
 * Dual BSD/GPL 许可，允许内核加载tracepoint类型BPF程序，避免许可证校验失败
 */
char LICENSE[] SEC("license") = "Dual BSD/GPL";

/**
 * @brief 全局常量key
 * 所有单元素MAP统一使用该key进行查找，避免循环分配栈变量
 */
static const int zero = 0;

/**
 * @struct read_entry_data
 * @brief sys_enter_read捕获后保存的调用上下文
 * 用于sys_enter_read与sys_exit_read配对，计算耗时、恢复调用参数
 */
struct read_entry_data {
	bpf_u64_t enter_ts;             // read系统调用进入时刻纳秒时间戳
	bpf_u64_t requested_count;      // read请求读取字节数（第二个参数count）
	bpf_s32_t pid;                  // 观测工具PID命名空间内可见TGID（进程ID）
	bpf_s32_t tid;                  // 观测工具PID命名空间内可见TID（线程ID）
	bpf_s32_t fd;                   // read操作目标文件描述符
	bpf_s8_t comm[TASK_COMM_LEN];   // 进程名称task_comm，最大16字节
	bpf_s8_t path_name_[FS_READ_PATH_SIZE]; // fd对应的文件dentry基础名称
};

/**
 * @brief ctrl_map：全局控制参数MAP
 * BPF_MAP_TYPE_ARRAY，仅单个元素；用户态下发Read_ctrl配置，动态控制采集行为
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Read_ctrl);
} ctrl_map SEC(".maps");

/**
 * @brief stats_map：每CPU独立统计MAP
 * PERCPU_ARRAY，每个CPU拥有独立统计结构体，消除高频路径原子锁竞争，提升性能
 * 用户态程序退出时，汇总所有CPU数据得到全局统计面板
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Read_stats);
} stats_map SEC(".maps");

/**
 * @brief inflight_reads：正在执行的read系统调用哈希表
 * key：宿主机初始PID命名空间全局TID（整机唯一，保障enter/exit可靠配对）
 * value：read_entry_data上下文信息
 * 注意：结构体内部pid/tid是转换后容器内可见ID，与key语义区分开
 * max_entries限制最大并发未完成read调用，防止哈希表无限膨胀
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, bpf_u32_t);
	__type(value, struct read_entry_data);
} inflight_reads SEC(".maps");

/**
 * @brief rb：环形缓冲区
 * BPF向用户态推送Read事件的通道，内核异步写入，libbpf ringbuffer轮询消费
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
 * @brief 获取全局控制配置
 * @return Read_ctrl指针，NULL代表查询失败
 */
static __always_inline struct Read_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, &zero);
}

/**
 * @brief 获取当前CPU独立统计结构体
 * @return Read_stats每CPU统计数据指针
 */
static __always_inline struct Read_stats *get_stats(void)
{
	return bpf_map_lookup_elem(&stats_map, &zero);
}

/**
 * @brief 根据fd反向解析对应文件dentry基础文件名
 * @param fd_num 文件描述符
 * @param out 输出字符串缓冲区
 * @param out_sz 缓冲区大小
 * @return 0成功；负数失败
 *
 * 读取链路：task_struct -> files_struct -> fdtable -> fd数组 -> struct file -> dentry -> d_name
 * 安全校验：提前校验fd不超过max_fds，防止非法fd造成内核地址越界读取
 * 限制：仅获取文件名最后一级，**不生成完整绝对路径**
 */
static __always_inline int fill_name_from_fd(bpf_s32_t fd_num,
					      bpf_s8_t *out, int out_sz)
{
	struct task_struct *task;
	struct files_struct *files;
	struct fdtable *fdt;
	struct file **fd_array;
	struct file *filp = NULL;
	struct dentry *dentry;
	struct qstr d_name;
	bpf_u32_t max_fds;

	if (out_sz <= 0)
		return -1;
	out[0] = '\0';
	if (fd_num < 0)
		return -1;

	task = (struct task_struct *)bpf_get_current_task();
	if (!task)
		return -1;
	files = BPF_CORE_READ(task, files);
	if (!files)
		return -1;
	fdt = BPF_CORE_READ(files, fdt);
	if (!fdt)
		return -1;
	max_fds = BPF_CORE_READ(fdt, max_fds);
	// 校验fd合法性，防止越界访问fd数组
	if ((bpf_u32_t)fd_num >= max_fds)
		return -1;
	fd_array = BPF_CORE_READ(fdt, fd);
	if (!fd_array)
		return -1;
	if (bpf_probe_read_kernel(&filp, sizeof(filp), &fd_array[fd_num]) || !filp)
		return -1;

	dentry = BPF_CORE_READ(filp, f_path.dentry);
	if (!dentry)
		return -1;
	d_name = BPF_CORE_READ(dentry, d_name);
	if (!d_name.name || !d_name.len)
		return -1;
	return bpf_probe_read_kernel_str(out, out_sz, d_name.name) > 0 ? 0 : -1;
}

/**
 * @brief tracepoint 系统调用进入read
 * 触发时机：进程发起read()，刚进入内核，尚未执行文件IO逻辑
 */
SEC("tracepoint/syscalls/sys_enter_read")
int read_entry(struct trace_event_raw_sys_enter *ctx)
{
	struct read_entry_data entry = {};
	struct Read_stats *stats;
	struct Read_ctrl *ctrl;
	bpf_u64_t global_pid_tgid;
	bpf_u64_t visible_pid_tgid;
	bpf_u32_t global_tid;

	ctrl = get_ctrl();
	// 采集总开关关闭，直接返回
	if (!ctrl || !ctrl->enable)
		return 0;

	/*
	 * 将内核全局pid/tid转换为目标PID命名空间内可见ID
	* 返回0代表当前线程不在目标pidns，直接丢弃，实现容器采集边界隔离
	* 即使target_pid=0，也只会捕获指定pidns内进程，不会全宿主机采集
	 */
	visible_pid_tgid = app_current_pid_tgid_ns(ctrl->pid_ns_dev,
						      ctrl->pid_ns_ino);
	if (!visible_pid_tgid)
		return 0;

	stats = get_stats();
	entry.pid = (bpf_s32_t)(visible_pid_tgid >> 32);
	entry.tid = (bpf_s32_t)visible_pid_tgid;

	// 自环防护：过滤观测工具自身进程，避免打印日志产生read无限递归捕获
	if (ctrl->self_pid && ctrl->self_pid == entry.pid) {
		if (stats)
			stats->filtered_self++;
		return 0;
	}
	// PID过滤：不匹配目标进程直接丢弃
	if (ctrl->target_pid && ctrl->target_pid != entry.pid) {
		if (stats)
			stats->filtered_pid++;
		return 0;
	}
	// 统计：成功通过前置过滤的read调用尝试次数
	if (stats)
		stats->attempted++;

	// 尽早记录时间戳，保证测量区间覆盖完整read系统调用生命周期
	entry.enter_ts = bpf_ktime_get_ns();
	entry.fd = (bpf_s32_t)ctx->args[0];
	entry.requested_count = (bpf_u64_t)ctx->args[2];
	bpf_get_current_comm(entry.comm, sizeof(entry.comm));

	// 反向解析fd对应的文件名，失败则统计路径查找失败指标
	if (fill_name_from_fd(entry.fd, entry.path_name_,
			      sizeof(entry.path_name_)) && stats)
		stats->path_lookup_failed++;

	// 获取宿主机全局唯一TID，作为inflight哈希表key
	global_pid_tgid = bpf_get_current_pid_tgid();
	global_tid = (bpf_u32_t)global_pid_tgid;
	// 存入上下文，供exit配对；插入失败代表哈希表已满，统计异常
	if (bpf_map_update_elem(&inflight_reads, &global_tid, &entry, BPF_ANY) &&
	    stats)
		stats->map_update_failed++;
	return 0;
}

/**
 * @brief tracepoint 系统调用退出read
 * 触发时机：read内核逻辑执行完毕，准备返回用户态
 * 核心：匹配enter上下文、计算耗时、执行过滤、组装事件下发用户态
 */
SEC("tracepoint/syscalls/sys_exit_read")
int read_exit(struct trace_event_raw_sys_exit *ctx)
{
	struct read_entry_data *entry;
	struct Read_event *event;
	struct Read_stats *stats;
	struct Read_ctrl *ctrl;
	bpf_u64_t visible_pid_tgid;
	bpf_u64_t now;
	bpf_u64_t latency_ns;
	bpf_u32_t global_tid;

	// 使用全局宿主机TID查找入口保存的上下文
	global_tid = (bpf_u32_t)bpf_get_current_pid_tgid();
	entry = bpf_map_lookup_elem(&inflight_reads, &global_tid);
	ctrl = get_ctrl();

	/*
	 * 场景：exit找不到对应的enter上下文（lookup miss）
	 * 成因：探针动态加载、入口map插入失败、调用过快enter未捕获
	 * 仅统计符合采集规则的进程，避免无效计数
	 */
	if (!entry) {
		if (ctrl && ctrl->enable) {
			visible_pid_tgid = app_current_pid_tgid_ns(ctrl->pid_ns_dev,
							      ctrl->pid_ns_ino);
			stats = get_stats();
			if (visible_pid_tgid && stats &&
			    (bpf_s32_t)(visible_pid_tgid >> 32) != ctrl->self_pid &&
			    (!ctrl->target_pid ||
			     ctrl->target_pid == (bpf_s32_t)(visible_pid_tgid >> 32)))
				stats->lookup_missed++;
		}
		return 0;
	}

	/*
	 * 安全兜底：read阻塞期间用户关闭采集开关
	 * 无论是否继续采集，必须清理inflight条目，防止哈希表内存泄漏
	 */
	if (!ctrl || !ctrl->enable) {
		bpf_map_delete_elem(&inflight_reads, &global_tid);
		return 0;
	}

	// 计算本次read系统调用耗时
	now = bpf_ktime_get_ns();
	latency_ns = now - entry->enter_ts;
	stats = get_stats();

	/*
	 * 全局汇总统计：不受延迟阈值影响
	 * 即使明细事件被过滤，completed、总耗时、失败计数依然正常统计
	 */
	if (stats) {
		stats->completed++;
		stats->total_ns += latency_ns;
		if (ctx->ret < 0)
			stats->failed++;
		// 更新观测周期内最大耗时记录
		if (latency_ns > stats->max_ns) {
			stats->max_ns = latency_ns;
			stats->max_pid = entry->pid;
			__builtin_memcpy(stats->max_comm, entry->comm, TASK_COMM_LEN);
		}
	}

	// 延迟阈值过滤：耗时低于阈值，不上报ringbuf明细，仅统计过滤数量
	if (ctrl->min_delay_ns && latency_ns < ctrl->min_delay_ns) {
		if (stats)
			stats->filtered_delay++;
		bpf_map_delete_elem(&inflight_reads, &global_tid);
		return 0;
	}

	// 从ringbuf分配事件内存，准备下发用户态
	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event) {
		// ringbuf缓冲区满，事件丢失，统计丢包指标
		if (stats)
			stats->ringbuf_dropped++;
		bpf_map_delete_elem(&inflight_reads, &global_tid);
		return 0;
	}

	// 填充事件结构体
	event->pid = entry->pid;
	event->tid = entry->tid;
	event->fd = entry->fd;
	event->requested_count = entry->requested_count;
	event->bytes_read = ctx->ret;          // read返回值：正数读取字节，负数=-errno
	event->timestamp_ns = now;
	event->latency_ns = latency_ns;
	__builtin_memcpy(event->comm, entry->comm, TASK_COMM_LEN);
	__builtin_memcpy(event->path_name_, entry->path_name_, FS_READ_PATH_SIZE);
	bpf_ringbuf_submit(event, 0);
	if (stats)
		stats->submitted++;

	// 配对完成，清理inflight哈希条目，防止表持续膨胀
	bpf_map_delete_elem(&inflight_reads, &global_tid);
	return 0;
}
