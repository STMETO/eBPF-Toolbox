#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "write.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Write_ctrl);
} ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, int);
} data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline struct Write_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
}

/* 在 do_sys_openat2 返回时记录 fd，用于后续 vfs_write 关联 */
SEC("kretprobe/do_sys_openat2")
int BPF_KRETPROBE(do_sys_openat2_ret)
{
	struct Write_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	int fd = (int)PT_REGS_RC(ctx);
	if (fd >= 0)
		bpf_map_update_elem(&data, &pid, &fd, BPF_ANY);
	return 0;
}

/* 在 vfs_write 入口处捕获写操作信息 */
SEC("kprobe/vfs_write")
int kprobe_vfs_write(struct pt_regs *ctx)
{
	struct Write_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	struct file *filp = (struct file *)PT_REGS_PARM1(ctx);
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	size_t count = (size_t)PT_REGS_PARM3(ctx);
	struct Write_event *e;
	int *fd_ptr;

	fd_ptr = bpf_map_lookup_elem(&data, &pid);

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	if (fd_ptr) {
		e->fd = *fd_ptr;
		e->count = count;
		e->pid = pid;
		e->real_count = 0; /* real_count 需要在 kretprobe 中获取 */
	} else {
		e->fd = -1;
		e->count = count;
		e->pid = pid;
		e->real_count = 0;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}
