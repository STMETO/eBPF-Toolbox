#include <vmlinux.h>
#include <bpf/bpf_helpers.h>		
#include <bpf/bpf_tracing.h>

#include "syscall.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 512);
    __type(key, u64);
    __type(value, u64);
} SyscallEnterTime SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10);
    __type(key, u64);
    __type(value, u64);
} Events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct SystemCall_Delay_ctrl);
} ctrl_map SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static inline struct SystemCall_Delay_ctrl *get_ctrl(void) {
    struct SystemCall_Delay_ctrl *sc_ctrl;
    sc_ctrl = bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
    if (!sc_ctrl || !sc_ctrl->enable) {
        return NULL;
    }
    return sc_ctrl;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__syscalls__sys_enter(struct trace_event_raw_sys_enter *args){
	struct SystemCall_Delay_ctrl *sc_ctrl = get_ctrl();
	if (!sc_ctrl) return 0;

	u64 start_time = bpf_ktime_get_ns() / 1000;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 syscall_id = (u64)args->id;

	bpf_map_update_elem(&Events, &pid_tgid, &syscall_id, BPF_ANY);
	bpf_map_update_elem(&SyscallEnterTime, &pid_tgid, &start_time, BPF_ANY);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int tracepoint__syscalls__sys_exit(struct trace_event_raw_sys_exit *args){
	struct SystemCall_Delay_ctrl *sc_ctrl = get_ctrl();
	if (!sc_ctrl) return 0;

	u64 exit_time = bpf_ktime_get_ns() / 1000;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 syscall_id;
	u64 start_time, delay;

	u64 *val = bpf_map_lookup_elem(&SyscallEnterTime, &pid_tgid);
	if (!val) return 0;

	start_time = *val;
	delay = exit_time - start_time;
	bpf_map_delete_elem(&SyscallEnterTime, &pid_tgid);

	u64 *val2 = bpf_map_lookup_elem(&Events, &pid_tgid);
	if (!val2) return 0;

	syscall_id = *val2;
	bpf_map_delete_elem(&Events, &pid_tgid);

	struct SystemCall_Delay_event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)	return 0;

	e->pid = pid_tgid;      // 传递 64 位 ID 到用户态
	e->delay = delay;
	e->syscall_id = syscall_id;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
