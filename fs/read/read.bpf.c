/*
 * fs/read — 监控进程 read 系统调用
 *
 * 双挂载点设计（与 open 模块同模式）：
 *   sys_enter_read → 捕获 fd、PID、进程名、文件路径（内核 fd 表反查）
 *   sys_exit_read  → 捕获实际读取字节数（ctx->ret）
 *
 * 入口与出口数据通过 tid_map（key=tid）关联，出口后立即 delete 清理。
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "read.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

/* ========== MAP 定义 ========== */

/*
 * ctrl_map — 全局采集开关
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Read_ctrl);
} ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Read_stats);
} stats_map SEC(".maps");

/*
 * tid_map — 入口→出口临时存储（key=tid，出口即删）
 *   入口暂存：pid + fd + comm + path
 *   出口取出组装完整事件，然后 delete
 */
struct entry_data {
	bpf_s32_t pid;
	bpf_s32_t fd;
	char comm[TASK_COMM_LEN];
	char path_name_[FS_READ_PATH_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);              /* tid */
	__type(value, struct entry_data);
} tid_map SEC(".maps");

/*
 * rb — RingBuffer 事件输出
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* ========== 辅助函数 ========== */

static __always_inline struct Read_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
}

/*
 * 从 task_struct 的 fd 表反查文件路径
 *
 * 路径: task -> files -> fdt -> fd[fd_num] -> f_path.dentry -> d_name
 *
 * 注意：此操作依赖内核结构体布局，BPF_CORE_READ 在 CO-RE 下自动适配偏移，
 *       但在极端旧内核（<4.14）上可能因字段缺失而失败，此时 path 字段为空串。
 */
static void fill_path_from_fd(bpf_s32_t fd_num, char *out, int out_sz)
{
	/* 初始化输出为空串 */
	if (out_sz > 0)
		out[0] = '\0';

	if (fd_num < 0)
		return;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (!task)
		return;

	/* 读取 fd 数组指针：fdt->fd 是 struct file ** 类型 */
	struct file **fd_array = BPF_CORE_READ(task, files, fdt, fd);
	if (!fd_array)
		return;

	/* 安全读取 fd_array[fd_num] 指向的 struct file * 指针 */
	struct file *filp;
	bpf_probe_read_kernel(&filp, sizeof(filp), &fd_array[fd_num]);
	if (!filp)
		return;

	/* 逐级读取 file → dentry → d_name */
	struct dentry *dentry = BPF_CORE_READ(filp, f_path.dentry);
	if (!dentry)
		return;

	struct qstr d_name = BPF_CORE_READ(dentry, d_name);
	if (!d_name.name || d_name.len == 0)
		return;

	/* 安全拷贝文件名到输出缓冲区 */
	bpf_probe_read_kernel_str(out, out_sz, d_name.name);
}

/* ========== 挂载点 1：sys_enter_read（入口） ========== */
SEC("tracepoint/syscalls/sys_enter_read")
int read_entry(struct trace_event_raw_sys_enter *ctx)
{
	struct Read_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tid = (u32)pid_tgid;

	struct entry_data entry = {};

	/* 基本信息：直接从 tracepoint / BPF helper 获取 */
	entry.pid = (bpf_s32_t)(pid_tgid >> 32);
	entry.fd  = (bpf_s32_t)ctx->args[0];          /* read 的第一个参数 = fd */
	bpf_get_current_comm(entry.comm, sizeof(entry.comm));

	/* 文件路径：从内核 fd 表反查（best-effort，失败则为空串） */
	fill_path_from_fd(entry.fd, entry.path_name_, FS_READ_PATH_SIZE);

	/* 暂存到 tid_map，出口取出 */
	bpf_map_update_elem(&tid_map, &tid, &entry, BPF_ANY);

	return 0;
}

/* ========== 挂载点 2：sys_exit_read（出口） ========== */
SEC("tracepoint/syscalls/sys_exit_read")
int read_exit(struct trace_event_raw_sys_exit *ctx)
{
	struct Read_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tid = (u32)pid_tgid;

	/* 取出入口阶段暂存的数据 */
	struct entry_data *entry = bpf_map_lookup_elem(&tid_map, &tid);
	if (!entry)

		/* PID 过滤 */
		if (ctrl->target_pid != 0 && entry->pid != ctrl->target_pid) {
			bpf_map_delete_elem(&tid_map, &tid);
			return 0;
		}
		return 0;


	struct Read_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		/* ringbuf 满也先清理 tid_map，防止哈希表膨胀 */
		bpf_map_delete_elem(&tid_map, &tid);
		return 0;
	}

	/* ---- 组装完整事件 ---- */
	e->pid          = entry->pid;
	e->fd           = entry->fd;
	e->bytes_read   = ctx->ret;  /* read 返回值 = 实际读取字节数（或 -errno） */
	e->timestamp_ns = bpf_ktime_get_ns();
	__builtin_memcpy(e->comm, entry->comm, TASK_COMM_LEN);
	__builtin_memcpy(e->path_name_, entry->path_name_, FS_READ_PATH_SIZE);

	bpf_ringbuf_submit(e, 0);

	/* tid_map 记录已完成使命，删除释放空间 */
	bpf_map_delete_elem(&tid_map, &tid);

	return 0;
}
