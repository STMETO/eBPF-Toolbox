#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "write.h"
#include "common/pid_namespace.bpf.h"

// BPF程序许可证，Dual BSD/GPL 允许内核加载tracepoint类型BPF程序
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 常量key，用于单元素MAP查询，避免栈上重复分配
static const int zero = 0;

/**
 * @brief write系统调用入口保存的上下文数据
 * 用于sys_enter_write保存现场，sys_exit_write取出配对计算耗时、组装事件
 */
struct write_entry_data {
	bpf_u64_t enter_ts;             // 系统调用进入时刻（纳秒时间戳）
	bpf_u64_t requested_count;      // 应用调用write请求写入的字节数（参数count）
	bpf_s32_t pid;                  // 目标PID（经过pid namespace转换后的容器内PID）
	bpf_s32_t tid;                  // 目标TID（经过pid namespace转换后的容器内线程ID）
	bpf_s32_t fd;                   // write操作的文件描述符fd
	bpf_s8_t comm[TASK_COMM_LEN];   // 进程名称（task comm，最多16字节）
	bpf_s8_t path_name_[FS_WRITE_PATH_SIZE]; // fd对应的文件名称
};

/**
 * ctrl_map：全局控制参数MAP
 * 类型：单元素Array，用户态程序写入控制配置下发给内核BPF
 * 包含开关、过滤PID、延迟阈值、PID命名空间参数、自身PID防自环
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Write_ctrl);
} ctrl_map SEC(".maps");

/**
 * stats_map：每CPU独立统计结构体
 * PERCPU_ARRAY：每个CPU拥有独立副本，BPF无需锁，避免多核竞争；
 * 用户态退出时汇总所有CPU计数，输出运行健康面板。
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Write_stats);
} stats_map SEC(".maps");

/**
 * inflight_writes：正在执行的write系统调用哈希表
 * key：全局内核TID（宿主机初始命名空间TID，唯一标识线程）
 * value：write_entry_data 上下文
 * 作用：实现sys_enter / sys_exit配对；系统调用结束必须删除key，防止内存泄漏
 * max_entries=10240：限制最大并发未完成write调用数量
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, bpf_u32_t);
	__type(value, struct write_entry_data);
} inflight_writes SEC(".maps");

/**
 * rb：环形缓冲区，BPF向用户态推送事件
 * 内核异步写入，用户态libbpf ring_buffer轮询消费
 * 大小256KB，事件过载时会触发ringbuf_dropped统计
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
 * @brief 获取全局控制配置
 * @return Write_ctrl指针，NULL代表未启用/查询失败
 */
static __always_inline struct Write_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, &zero);
}

/**
 * @brief 获取当前CPU独立统计结构体
 * @return Write_stats每CPU统计指针
 */
static __always_inline struct Write_stats *get_stats(void)
{
	return bpf_map_lookup_elem(&stats_map, &zero);
}

/**
 * @brief 从当前线程fd表，根据fd读取对应文件dentry名称
 * @param fd_num 文件描述符
 * @param out 输出缓冲区
 * @param out_sz 缓冲区大小
 * @return 0成功；负数失败（fd非法、内核对象读取失败、无文件名等）
 *
 * 读取链路：task_struct -> files_struct -> fdtable -> fd[] -> struct file -> dentry -> d_name
 * 注意：仅拿到最后一级文件名，不是完整绝对路径；且BPF_CORE_READ保证跨内核版本兼容（CO-RE）
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

	// 获取当前任务task_struct
	task = (struct task_struct *)bpf_get_current_task();
	if (!task)
		return -1;
	// 读取进程文件表
	files = BPF_CORE_READ(task, files);
	if (!files)
		return -1;
	// 读取fd表
	fdt = BPF_CORE_READ(files, fdt);
	if (!fdt)
		return -1;
	// 校验fd不超过最大文件描述符限制
	max_fds = BPF_CORE_READ(fdt, max_fds);
	if ((bpf_u32_t)fd_num >= max_fds)
		return -1;
	// 获取fd数组指针
	fd_array = BPF_CORE_READ(fdt, fd);
	if (!fd_array)
		return -1;
	// 取出fd对应的struct file*
	if (bpf_probe_read_kernel(&filp, sizeof(filp), &fd_array[fd_num]) || !filp)
		return -1;
	// 获取文件对应的dentry
	dentry = BPF_CORE_READ(filp, f_path.dentry);
	if (!dentry)
		return -1;
	// 获取dentry名称
	d_name = BPF_CORE_READ(dentry, d_name);
	if (!d_name.name || !d_name.len)
		return -1;
	// 拷贝文件名字符串到输出缓冲区
	return bpf_probe_read_kernel_str(out, out_sz, d_name.name) > 0 ? 0 : -1;
}

/**
 * @brief tracepoint 系统调用进入write
 * 触发时机：进程发起write()，刚进入内核，还未执行任何文件逻辑
 */
SEC("tracepoint/syscalls/sys_enter_write")
int write_entry(struct trace_event_raw_sys_enter *ctx)
{
	struct write_entry_data entry = {};
	struct Write_stats *stats;
	struct Write_ctrl *ctrl;
	bpf_u64_t visible_pid_tgid;
	bpf_u32_t global_tid;

	// 读取全局开关，未启用直接退出
	ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	// 转换PID/TID到目标pid namespace（容器内可见进程号，和open模块统一口径）
	visible_pid_tgid = app_current_pid_tgid_ns(ctrl->pid_ns_dev,
						      ctrl->pid_ns_ino);
	if (!visible_pid_tgid)
		return 0;

	stats = get_stats();
	// 过滤采集程序自身：避免用户态打印LOG产生write，无限递归捕获自身日志IO
	entry.pid = (bpf_s32_t)(visible_pid_tgid >> 32);
	entry.tid = (bpf_s32_t)visible_pid_tgid;
	if (ctrl->self_pid && ctrl->self_pid == entry.pid) {
		if (stats)
			stats->filtered_self++;
		return 0;
	}

	// 根据target_pid过滤非目标进程
	if (ctrl->target_pid && ctrl->target_pid != entry.pid) {
		if (stats)
			stats->filtered_pid++;
		return 0;
	}

	// 统计：成功通过前置过滤的write调用尝试次数
	if (stats)
		stats->attempted++;

	// 填充上下文信息
	entry.enter_ts = bpf_ktime_get_ns();                  // 记录进入时间戳
	entry.fd = (bpf_s32_t)ctx->args[0];                   // write第一个参数fd
	entry.requested_count = (bpf_u64_t)ctx->args[2];      // write第三个参数count（请求写入字节）
	bpf_get_current_comm(entry.comm, sizeof(entry.comm)); // 获取进程名

	// 读取fd对应的文件名；失败则统计路径查找失败
	if (fill_name_from_fd(entry.fd, entry.path_name_,
			      sizeof(entry.path_name_)) && stats)
		stats->path_lookup_failed++;

	// 使用宿主机全局TID作为key存入inflight哈希表，用于exit配对
	global_tid = (bpf_u32_t)bpf_get_current_pid_tgid();
	if (bpf_map_update_elem(&inflight_writes, &global_tid, &entry, BPF_ANY) &&
	    stats)
		stats->map_update_failed++;

	return 0;
}

/**
 * @brief tracepoint 系统调用退出write
 * 触发时机：write内核逻辑执行完毕，准备返回用户态
 * 核心：根据全局TID匹配入口保存的上下文，计算耗时、组装事件、各类过滤
 */
SEC("tracepoint/syscalls/sys_exit_write")
int write_exit(struct trace_event_raw_sys_exit *ctx)
{
	struct write_entry_data *entry;
	struct Write_event *event;
	struct Write_stats *stats;
	struct Write_ctrl *ctrl;
	bpf_u64_t visible_pid_tgid;
	bpf_u64_t now;
	bpf_u64_t latency_ns;
	bpf_u32_t global_tid;

	// 使用全局宿主机TID查找入口保存的上下文
	global_tid = (bpf_u32_t)bpf_get_current_pid_tgid();
	entry = bpf_map_lookup_elem(&inflight_writes, &global_tid);
	ctrl = get_ctrl();

	// 场景：只捕获exit、没有捕获enter（探针中途加载、入口map写入失败）
	if (!entry) {
		if (ctrl && ctrl->enable) {
			visible_pid_tgid = app_current_pid_tgid_ns(ctrl->pid_ns_dev,
							      ctrl->pid_ns_ino);
			stats = get_stats();
			// 排除自身进程、匹配目标PID才统计lookup_miss
			if (visible_pid_tgid && stats &&
			    (bpf_s32_t)(visible_pid_tgid >> 32) != ctrl->self_pid &&
			    (!ctrl->target_pid ||
			     ctrl->target_pid == (bpf_s32_t)(visible_pid_tgid >> 32)))
				stats->lookup_missed++;
		}
		return 0;
	}

	// 安全兜底：BPF运行时关闭采集，**必须清理inflight哈希表**，防止条目永久残留泄漏
	if (!ctrl || !ctrl->enable) {
		bpf_map_delete_elem(&inflight_writes, &global_tid);
		return 0;
	}

	// 计算本次write系统调用耗时（墙钟时间）
	now = bpf_ktime_get_ns();
	latency_ns = now - entry->enter_ts;
	stats = get_stats();

	// 基础汇总统计（无论后续是否推送明细，都计入全局统计）
	if (stats) {
		stats->completed++;                  // 成功配对enter+exit的调用总数
		stats->total_ns += latency_ns;       // 累计总耗时
		if (ctx->ret < 0)                    // 返回值负数 = write调用出错
			stats->failed++;
		// 更新最大耗时记录，附带进程信息
		if (latency_ns > stats->max_ns) {
			stats->max_ns = latency_ns;
			stats->max_pid = entry->pid;
			__builtin_memcpy(stats->max_comm, entry->comm, TASK_COMM_LEN);
		}
	}

	// ========== 延迟阈值过滤逻辑 min_delay_ns 生效点 ==========
	// 耗时低于阈值：不推送明细事件，仅统计过滤计数，直接清理map条目返回
	if (ctrl->min_delay_ns && latency_ns < ctrl->min_delay_ns) {
		if (stats)
			stats->filtered_delay++;
		bpf_map_delete_elem(&inflight_writes, &global_tid);
		return 0;
	}

	// 尝试从ringbuf分配事件内存
	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event) {
		// ringbuf缓冲区满，事件丢弃，统计丢包
		if (stats)
			stats->ringbuf_dropped++;
		bpf_map_delete_elem(&inflight_writes, &global_tid);
		return 0;
	}

	// 填充输出事件结构体，下发到用户态
	event->pid = entry->pid;
	event->tid = entry->tid;
	event->fd = entry->fd;
	event->requested_count = entry->requested_count;
	event->bytes_written = ctx->ret;          // 实际写入字节（负数代表错误）
	event->timestamp_ns = now;
	event->latency_ns = latency_ns;
	__builtin_memcpy(event->comm, entry->comm, TASK_COMM_LEN);
	__builtin_memcpy(event->path_name_, entry->path_name_, FS_WRITE_PATH_SIZE);

	// 提交事件给用户态消费
	bpf_ringbuf_submit(event, 0);
	if (stats)
		stats->submitted++;

	// 关键：配对完成，删除inflight条目，防止哈希表持续膨胀
	bpf_map_delete_elem(&inflight_writes, &global_tid);
	return 0;
}
