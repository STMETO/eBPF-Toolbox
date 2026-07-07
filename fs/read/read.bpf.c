/*
 * fs/read — 监控进程 read 系统调用
 *
 * 双挂载点设计（与 open 模块同架构）：
 *   sys_enter_read → 捕获 fd、PID、进程名，通过内核task文件描述符表反查文件路径，存入临时哈希tid_map
 *   sys_exit_read  → 捕获read系统调用返回值（实际读取字节数/错误码），取出入口缓存数据组装完整事件推送用户态
 *
 * 入口与出口数据通过 tid_map（key=线程TID）关联，事件处理完成后立即delete清理哈希条目，避免内核哈希内存持续膨胀。
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "read.h"

 // BPF追踪程序许可证，tracepoint类必须GPL双协议才可正常加载内核
char LICENSE[] SEC("license") = "Dual BSD/GPL";
 
 // ctrl_map、stats_map全局数组统一固定key值
const int ctrl_key = 0;
 
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Read_ctrl);
} ctrl_map SEC(".maps");
 
 /**
  * stats_map — 整机read系统调用全局统计MAP
  * 持久累加所有过滤通过的read调用指标，程序退出用户态读取打印汇总报表
  */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Read_stats);
} stats_map SEC(".maps");
 
 /**
  * @struct entry_data
  * tid_map哈希临时存储结构体，sys_enter_read入口缓存read调用现场信息
  * @field pid 发起read操作的进程TGID
  * @field fd read操作文件描述符
  * @field comm 发起read的进程名称
  * @field path_name_ 通过fd反查得到的文件全路径，失败为空字符串
  */
 /*
  * tid_map — 入口→出口临时存储HASH MAP
  * key: 线程TID（bpf_get_current_pid_tgid低32位），唯一区分并发read调用线程
  * value: entry_data 存储入口捕获的fd、pid、进程名、文件路径
  * max_entries=10240：支持最多10240条并发未完成read调用，限制哈希内存上限
  * 流程：sys_enter写入现场 → sys_exit读取处理后delete释放条目，防止哈希溢出
  */
struct entry_data {
	bpf_s32_t pid;
	bpf_s32_t fd;
	bpf_s8_t  comm[TASK_COMM_LEN];
	bpf_s8_t  path_name_[FS_READ_PATH_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);            /* tid 线程ID作为哈希键 */
	__type(value, struct entry_data);
} tid_map SEC(".maps");
 
 /*
  * rb — RingBuffer环形缓冲区
  * 内核sys_exit_read组装完整Read_event事件后提交，用户态libbpf阻塞poll实时读取打印IO事件
  * 总容量256KB，缓冲区满时分配内存失败直接丢弃当前事件
  */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");
 
 /* ========== 辅助工具函数 ========== */
/**
* @brief 内联工具函数：获取全局监控控制配置指针
* @return ctrl_map存储的Read_ctrl结构体指针
*/
static __always_inline struct Read_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
}
 
 /*
  * fill_path_from_fd — 工具函数：通过文件描述符fd反向解析对应文件路径
  * 内核结构体逐级读取链路：task_struct -> files_struct -> fd数组 -> struct file -> dentry -> d_name文件名
  * 采用BPF_CORE_READ CO-RE偏移自适应，兼容多内核版本无需重编译
  * @param fd_num 待解析的文件描述符
  * @param out 输出缓冲区，存放文件路径字符串
  * @param out_sz 输出缓冲区最大长度
  * 特性：解析失败缓冲区置空串；旧内核字段缺失会返回空路径，不中断整个监控逻辑
  */
static void fill_path_from_fd(bpf_s32_t fd_num, char *out, int out_sz)
{
	// 初始化输出缓冲区为空字符串，解析失败时保持空
	if (out_sz > 0)
		out[0] = '\0';

	// 无效fd直接返回，无需解析
	if (fd_num < 0)
		return;

	// 获取当前线程task_struct
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (!task)
		return;

	// CO-RE安全读取task->files->fdt->fd 文件描述符数组指针
	struct file **fd_array = BPF_CORE_READ(task, files, fdt, fd);
	if (!fd_array)
		return;

	// 读取fd数组对应下标fd_num的struct file指针
	struct file *filp;
	bpf_probe_read_kernel(&filp, sizeof(filp), &fd_array[fd_num]);
	if (!filp)
		return;

	// 读取file结构体关联的dentry目录项
	struct dentry *dentry = BPF_CORE_READ(filp, f_path.dentry);
	if (!dentry)
		return;

	// 读取dentry内文件名称qstr结构体
	struct qstr d_name = BPF_CORE_READ(dentry, d_name);
	if (!d_name.name || d_name.len == 0)
		return;

	// 安全拷贝内核文件名字符串到输出缓冲区
	bpf_probe_read_kernel_str(out, out_sz, d_name.name);
}
 
 /* ========== 挂载点1：tracepoint/syscalls/sys_enter_read read入口钩子 ========== */
 /*
  * 触发时机：进程刚进入read系统调用，尚未执行IO读取操作
  * 功能：拆分pid/tid、获取fd，调用fill_path_from_fd通过fd反查文件路径，把整套调用现场存入tid_map哈希
  * 前置过滤：监控开关关闭直接跳过，不执行解析与哈希写入操作
  */
/**
* @brief read系统调用入口追踪点，缓存线程TID对应的fd、PID、进程名、文件路径
* @param ctx tracepoint原生syscall入参结构体，args[0]为read传入的fd
* @return 0 BPF tracepoint固定返回值
*/
SEC("tracepoint/syscalls/sys_enter_read")
int read_entry(struct trace_event_raw_sys_enter *ctx)
{
	struct Read_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tid = (u32)pid_tgid;                // 低32位 = 线程TID，哈希key
	bpf_s32_t pid = (bpf_s32_t)(pid_tgid >> 32);  // 高32位 = 进程TGID(PID)

	struct entry_data entry = {};
	entry.pid = pid;
	// read第一个系统调用参数为文件fd
	entry.fd  = (bpf_s32_t)ctx->args[0];
	// 读取当前进程名称
	bpf_get_current_comm(entry.comm, sizeof(entry.comm));
	// 调用工具函数，通过fd反向解析文件路径
	fill_path_from_fd(entry.fd, entry.path_name_, FS_READ_PATH_SIZE);

	// 将本条read调用上下文存入tid_map哈希，等待出口追踪点匹配读取
	bpf_map_update_elem(&tid_map, &tid, &entry, BPF_ANY);

	return 0;
}
 
 /* ========== 挂载点2：tracepoint/syscalls/sys_exit_read read返回钩子 ========== */
 /*
  * 触发时机：read系统调用执行完毕，即将返回用户态，可拿到read返回值（读取字节数/错误码）
  * 完整流程：
  * 1. 根据当前线程TID查询tid_map，取出入口缓存的fd、进程、文件路径
  * 2. PID过滤：目标监控PID不匹配则删除哈希条目丢弃事件
  * 3. 分配ringbuf事件，填充fd、PID、进程名、文件路径、实际读取字节数、时间戳
  * 4. 推送事件到环形缓冲区，更新全局read统计
  * 5. delete tid_map本条key，清除哈希脏数据防止并发read数据错乱
  */
/**
* @brief read系统调用返回追踪点，组装完整read IO事件下发用户态并更新全局统计
* @param ctx tracepoint原生返回参数，ret字段存放read返回值（读取字节/负错误码）
* @return 0 BPF tracepoint固定返回值
*/
SEC("tracepoint/syscalls/sys_exit_read")
int read_exit(struct trace_event_raw_sys_exit *ctx)
{
	struct Read_ctrl *ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tid = (u32)pid_tgid;

	// 通过当前线程TID匹配入口存入的read现场
	struct entry_data *entry = bpf_map_lookup_elem(&tid_map, &tid);
	if (!entry)
		return 0;

	/* PID过滤逻辑：配置目标监控PID，当前线程不匹配，清理哈希条目丢弃事件 */
	if (ctrl->target_pid != 0 && entry->pid != ctrl->target_pid) {
		bpf_map_delete_elem(&tid_map, &tid);
		return 0;
	}

	// 从ringbuf预分配内存封装read实时IO事件
	struct Read_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		// ringbuf缓冲区满，分配失败，清理哈希脏数据丢弃事件
		bpf_map_delete_elem(&tid_map, &tid);
		return 0;
	}

	// 填充read事件所有字段
	e->pid         = entry->pid;
	e->fd          = entry->fd;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->bytes_read  = ctx->ret;  // read返回值：正数读取字节，负数为错误码
	__builtin_memcpy(e->comm, entry->comm, sizeof(e->comm));
	__builtin_memcpy(e->path_name_, entry->path_name_, sizeof(e->path_name_));

	// 将完整read IO事件提交ringbuf，用户态libbpf阻塞读取打印
	bpf_ringbuf_submit(e, 0);

	/* 更新整机read系统调用全局统计指标 */
	struct Read_stats *st = bpf_map_lookup_elem(&stats_map, &ctrl_key);
	// 首次运行stats_map无初始化数据，创建全零统计结构体写入map
	if (!st) {
		struct Read_stats z = {};
		bpf_map_update_elem(&stats_map, &ctrl_key, &z, BPF_ANY);
		st = bpf_map_lookup_elem(&stats_map, &ctrl_key);
	}
	if (st) {
		st->count++;        // read调用总次数+1
		// 此处可扩展累加总耗时、最大耗时（当前结构体预留）
	}

	// 本条read调用处理完毕，删除tid_map哈希条目释放内核内存，防止哈希表膨胀溢出
	bpf_map_delete_elem(&tid_map, &tid);

	return 0;
}
 