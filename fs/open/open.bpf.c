// 禁用 eBPF 全局数据段，所有常量/全局变量会放到 map 中，适配内核限制、避免全局只读数据报错
#define BPF_NO_GLOBAL_DATA

// 内核导出的 vmlinux 头，包含所有内核结构体定义：task_struct、fdtable、files_struct 等
#include <vmlinux.h>
// eBPF 基础工具函数：ringbuf、map 操作、bpf_get_current_xxx 等
#include <bpf/bpf_helpers.h>
// 追踪相关宏：SEC、BPF_KPROBE、BPF_TRACEPOINT 等段定义
#include <bpf/bpf_tracing.h>
// CO-RE（Compile Once – Run Everywhere）核心读取宏，适配不同内核版本结构体偏移
#include <bpf/bpf_core_read.h>
// 自定义头文件，存放 Open_ctrl、Open_event 两个结构体定义
#include "open.h"

// eBPF 程序必须声明 GPL 协议，否则无法加载部分内核追踪、BPF_CORE_READ 功能
char LICENSE[] SEC("license") = "GPL";

// 全局常量：ctrl_map 的唯一 key，数组 map 只有一个下标 0
const int ctrl_key = 0;

/**
 * ctrl_map：控制参数数组Map
 * 类型：数组 MAP（BPF_MAP_TYPE_ARRAY），固定长度1，仅存全局开关/配置
 * key：int 固定0，value：自定义结构体 Open_ctrl（包含 enable 开关等控制字段）
 * 用途：用户态程序下发采集开关、过滤规则、阈值配置到内核态 eBPF 程序
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);    // map 类型：数组
	__uint(max_entries, 1);              // 仅1个元素
	__type(key, int);                    // key 类型 int
	__type(value, struct Open_ctrl);     // 值为控制结构体
} ctrl_map SEC(".maps");

/**
 * comm_cache：进程名缓存哈希Map
 * 类型：哈希表，最多1024条记录
 * key：pid_t 进程PID
 * value：char[TASK_COMM_LEN] 进程名称（程序名，最多16字节内核定义）
 * 用途：缓存每个PID对应的进程名，用户态读取事件时无需重复获取comm，减少开销
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, char[TASK_COMM_LEN]);
} comm_cache SEC(".maps");

/**
 * rb：环形缓冲区 RingBuffer
 * 类型：BPF_MAP_TYPE_RINGBUF，现代高性能事件输出载体，替代老旧 perf buffer
 * 大小：256KB 缓冲区，内核态预分配事件内存，批量提交给用户态
 * 优点：无锁、低延迟，适合高频系统调用采集
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
 * @brief 内联函数，读取全局控制配置
 * @return 指向 ctrl_map 中唯一 Open_ctrl 配置的指针，为空代表未初始化
 * __always_inline：强制内联，消除函数调用栈开销，eBPF 推荐写法
 */
static __always_inline struct Open_ctrl *get_ctrl(void)
{
	// 根据固定 key=0 查询数组 map，返回内核态指针
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
}

/**
 * tracepoint/syscalls/sys_enter_openat 挂载点
 * tracepoint：内核静态埋点，稳定性高于kprobe，不会因内核函数重命名失效
 * 触发时机：进程进入 openat 系统调用瞬间
 * ctx：tracepoint 上下文，存放系统调用参数 args[0]~args[5]
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int do_syscall_trace(struct trace_event_raw_sys_enter *ctx)
{
	// 1. 获取用户态下发的采集控制开关
	struct Open_ctrl *ctrl = get_ctrl();
	// 开关未开启，直接退出，不采集事件
	if (!ctrl || !ctrl->enable)
		return 0;

	struct Open_event *e;  // 待发送到ringbuf的事件结构体
	char comm[TASK_COMM_LEN]; // 临时存储当前进程名

	// 获取当前任务的进程名（comm，如 bash、cat、nginx），拷贝到临时数组
	bpf_get_current_comm(&comm, sizeof(comm));

	// 从环形缓冲区预留一块内存存放事件，大小等于Open_event
	// 第三个参数flags=0：普通预留，无特殊标记
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	// ringbuf缓冲区满/分配失败，直接退出，丢弃本次事件
	if (!e)
		return 0;

	// 获取当前进程 task_struct 内核对象指针（内核描述进程的核心结构体）
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (task == NULL) {
		// task 指针非法，释放刚才预留的ringbuf内存，丢弃事件
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	// 提取PID：bpf_get_current_pid_tgid 返回64位值，高32位PID，低32位TID
	int pid = bpf_get_current_pid_tgid() >> 32;

	// 更新进程名缓存map：key=pid，值=进程名，BPF_ANY存在则覆盖，不存在则新增
	bpf_map_update_elem(&comm_cache, &pid, &comm, BPF_ANY);

	// 读取 sys_enter_openat 第二个参数 args[1]：文件路径字符串指针
	// bpf_probe_read_str：安全读取用户态字符串，自动截断、补'\0'
	bpf_probe_read_str(e->path_name_, sizeof(e->path_name_),
			   (void *)(ctx->args[1]));

	// CO-RE 安全读取 task->files->fdt：进程打开文件表 fdtable
	// BPF_CORE_READ 自动适配不同内核结构体偏移，避免硬编码偏移导致加载失败
	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
	if (fdt == NULL) {
		// 文件表为空，丢弃事件释放ringbuf内存
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	// 读取 fdtable 中 max_fds：当前进程支持的最大文件描述符数量，存入事件
	e->n_ = BPF_CORE_READ(fdt, max_fds);
	// 写入当前进程PID到事件
	e->pid_ = pid;

	// 提交ringbuf事件，数据正式推送给用户态程序消费
	bpf_ringbuf_submit(e, 0);
	return 0;
}
