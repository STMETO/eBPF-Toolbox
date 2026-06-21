#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "open.h"

char LICENSE[] SEC("license") = "GPL";

const int ctrl_key = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Open_ctrl);
} ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, char[TASK_COMM_LEN]);
} comm_cache SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline struct Open_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int do_syscall_trace(struct trace_event_raw_sys_enter *ctx)
{
	struct Open_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	struct Open_event *e;
	char comm[TASK_COMM_LEN];

	bpf_get_current_comm(&comm, sizeof(comm));

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (task == NULL) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	int pid = bpf_get_current_pid_tgid() >> 32;

	bpf_map_update_elem(&comm_cache, &pid, &comm, BPF_ANY);

	bpf_probe_read_str(e->path_name_, sizeof(e->path_name_),
			   (void *)(ctx->args[1]));

	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
	if (fdt == NULL) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	e->n_ = BPF_CORE_READ(fdt, max_fds);
	e->pid_ = pid;

	bpf_ringbuf_submit(e, 0);
	return 0;
}
