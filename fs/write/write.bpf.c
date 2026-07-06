/*
 * fs/write — 监控进程 write 系统调用
 *
 * 双挂载点设计（与 open/read 同模式）：
 *   sys_enter_write → 捕获 fd（ctx->args[0]）、count（ctx->args[2]）、PID、进程名、文件路径
 *   sys_exit_write  → 捕获实际写入字节数（ctx->ret）
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "write.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

/* ========== MAP 定义 ========== */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Write_ctrl);
} ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct WWrite_stats);
} stats_map SEC(".maps");

/*
 * tid_map — 入口→出口临时存储（key=tid，出口即删）
 */
struct entry_data {
	bpf_s32_t pid;
	bpf_s32_t fd;
	bpf_s64_t count;
	char comm[TASK_COMM_LEN];
	char path_name_[FS_WRITE_PATH_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct entry_data);
} tid_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* ========== 辅助函数 ========== */

static __always_inline struct Write_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
}

/*
 * 从 task_struct 的 fd 表反查文件路径
 *
 * 路径: task -> files -> fdt -> fd[fd_num] -> f_path.dentry -> d_name
 */
static void fill_path_from_fd(bpf_s32_t fd_num, char *out, int out_sz)
{
	if (out_sz > 0)
		out[0] = '\0';

	if (fd_num < 0)
		return;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (!task)
		return;

	struct file **fd_array = BPF_CORE_READ(task, files, fdt, fd);
	if (!fd_array)
		return;

	struct file *filp;
	bpf_probe_read_kernel(&filp, sizeof(filp), &fd_array[fd_num]);
	if (!filp)
		return;

	struct dentry *dentry = BPF_CORE_READ(filp, f_path.dentry);
	if (!dentry)
		return;

	struct qstr d_name = BPF_CORE_READ(dentry, d_name);
	if (!d_name.name || d_name.len == 0)
		return;

	bpf_probe_read_kernel_str(out, out_sz, d_name.name);
}

/* ========== 挂载点 1：sys_enter_write（入口） ========== */
SEC("tracepoint/syscalls/sys_enter_write")
int write_entry(struct trace_event_raw_sys_enter *ctx)
{
	struct Write_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tid = (u32)pid_tgid;

	struct entry_data entry = {};

	/*
	 * write(fd, buf, count) 的三个参数：
	 *   args[0] = fd       文件描述符
	 *   args[1] = buf      用户态缓冲区地址（本模块不读取内容）
	 *   args[2] = count    请求写入的字节数
	 */
	entry.pid   = (bpf_s32_t)(pid_tgid >> 32);
	entry.fd    = (bpf_s32_t)ctx->args[0];     
	entry.count = (bpf_s64_t)ctx->args[2];     
	bpf_get_current_comm(entry.comm, sizeof(entry.comm));
	fill_path_from_fd(entry.fd, entry.path_name_, FS_WRITE_PATH_SIZE);

	bpf_map_update_elem(&tid_map, &tid, &entry, BPF_ANY);

	return 0;
}

/* ========== 挂载点 2：sys_exit_write（出口） ========== */
SEC("tracepoint/syscalls/sys_exit_write")
int write_exit(struct trace_event_raw_sys_exit *ctx)
{
	struct Write_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tid = (u32)pid_tgid;

	struct entry_data *entry = bpf_map_lookup_elem(&tid_map, &tid);
	if (!entry)

		/* PID 过滤 */
		if (ctrl->target_pid != 0 && entry->pid != ctrl->target_pid) {
			bpf_map_delete_elem(&tid_map, &tid);
			return 0;
		}
		return 0;


	struct Write_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		bpf_map_delete_elem(&tid_map, &tid);   /* 失败也清理 */
		return 0;
	}

	/* ---- 组装完整事件 ---- */
	e->pid          = entry->pid;
	e->fd           = entry->fd;
	e->count        = entry->count;              /* 请求写入字节数 */
	e->real_count   = ctx->ret;                  /* 实际写入字节数（出口返回值） */
	e->timestamp_ns = bpf_ktime_get_ns();
	__builtin_memcpy(e->comm, entry->comm, TASK_COMM_LEN);
	__builtin_memcpy(e->path_name_, entry->path_name_, FS_WRITE_PATH_SIZE);

	bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&tid_map, &tid);

	return 0;
}
