#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "Read.h"

#define MAX_FILENAME_LEN 256

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 手动定义文件类型宏
#define S_IFMT  0170000
#define S_IFREG 0100000
#define S_IFCHR 0020000
#define S_IFDIR 0040000
#define S_IFLNK 0120000
#define S_IFBLK 0060000
#define S_IFIFO 0010000
#define S_IFSOCK 0140000

const int ctrl_key = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Read_ctrl);
} ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, MAX_FILENAME_LEN);
} data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline struct Read_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
}

SEC("kprobe/vfs_read")
int kprobe_enter_read(struct pt_regs *ctx)
{
	struct Read_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	struct file *filp = (struct file *)PT_REGS_PARM1(ctx);
	pid_t pid;
	struct Read_event *e;
	u64 ts;
	char buf[256];

	pid = bpf_get_current_pid_tgid() >> 32;
	ts = bpf_ktime_get_ns() / 1000;

	// 获取文件路径结构体
	struct dentry *dentry = BPF_CORE_READ(filp, f_path.dentry);
	if (!dentry) {
		bpf_printk("Failed to read dentry\n");
		return 0;
	}
	struct qstr d_name = BPF_CORE_READ(dentry, d_name);

	// 读文件名称到缓冲区
	int ret = bpf_probe_read_kernel(buf, sizeof(buf), d_name.name);
	if (ret != 0) {
		bpf_printk("failed to read file name\n");
	}

	// 判断文件类型，并过滤掉设备文件
	unsigned short file_type = BPF_CORE_READ(dentry, d_inode, i_mode) & S_IFMT;
	bpf_map_update_elem(&data, &pid, &buf, BPF_ANY);

	switch (file_type) {
	case S_IFREG:
		bpf_printk("Regular file name: %s", buf);
		break;
	case S_IFCHR:
		bpf_printk("Char device: %s", buf);
		break;
	case S_IFDIR:
		bpf_printk("Directory: %s", buf);
		break;
	case S_IFLNK:
		bpf_printk("Symlink: %s", buf);
		break;
	case S_IFBLK:
		bpf_printk("Block device: %s", buf);
		break;
	case S_IFIFO:
		bpf_printk("FIFO: %s", buf);
		break;
	case S_IFSOCK:
		bpf_printk("Socket: %s", buf);
		break;
	default:
		bpf_printk("other!!!");
		break;
	}

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;
	e->pid = pid;
	e->duration_ns = ts;
	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}
