#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "syscall.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int ctrl_key = 0;

/**
 * @struct start_val
 * PERCPU临时缓存结构体，配合sys_enter + sys_exit成对tracepoint使用
 * sys_enter入口记录系统调用起点时间、系统调用号；sys_exit读取计算完整调用耗时
 * @field start_ts sys_enter触发时内核时间戳，单位微秒(ns/1000)，用于计算调用延迟
 * @field syscall_id 当前执行的系统调用编号（open/read/write/mq_timedsend等内核标准syscall号）
 */
struct start_val {
	bpf_u64_t start_ts;
	bpf_s32_t syscall_id;
};

/*
 * enter_map：每CPU独立临时缓存MAP
 * 类型：BPF_MAP_TYPE_PERCPU_ARRAY，每个CPU拥有独立数据副本，天然无多核并发竞争、无需锁
 * max_entries=1：单CPU同一时刻只会执行一条系统调用，仅需一条缓存条目
 * key：固定int 0
 * value：start_val 存储本次syscall入口现场信息
 * 流程：sys_enter写入缓存记录起点 → sys_exit读取使用后置零start_ts标记已消费
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct start_val);
} enter_map SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Syscall_ctrl);
} ctrl_map SEC(".maps");

/*
 * stats_map：全局系统调用汇总统计MAP
 * 持久累加所有符合过滤条件的syscall指标：总次数、总耗时、单次最大耗时及对应进程/系统调用号
 * 程序退出时用户态读取此map，打印整机系统调用汇总报表
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct Syscall_stats);
} stats_map SEC(".maps");

/*
 * rb：RingBuf环形缓冲区，内核向用户态推送Syscall_event事件通道
 * 总容量256KB，内核过滤完成后分配事件结构体写入rb，用户态libbpf阻塞poll读取打印
 * 缓冲区满时内存分配失败，直接丢弃当前系统调用事件
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
 * @brief 工具内联函数：获取全局监控控制配置指针
 * @return ctrl_map存储的Syscall_ctrl结构体指针
 */
static inline struct Syscall_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
}

/*
 * tracepoint/raw_syscalls/sys_enter：系统调用入口追踪点
 * 内核任何进程进入任意系统调用都会触发本钩子
 * 功能：读取syscall编号、记录进入时刻时间戳存入当前CPU专属临时缓存enter_map
 * 过滤逻辑：监控开关关闭直接跳过，不写入缓存
 */
/**
* @brief 系统调用入口钩子，记录调用起点上下文存入PERCPU缓存
* @param args tracepoint原生参数结构体，存放当前syscall编号等信息
* @return 0 BPF tracepoint固定返回值
*/
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_enter(struct trace_event_raw_sys_enter *args)
{
	struct Syscall_ctrl *c = get_ctrl();
	if (!c || !c->enable)
		return 0;

	int key = 0;
	// 获取当前CPU独有的临时缓存
	struct start_val *v = bpf_map_lookup_elem(&enter_map, &key);
	if (!v)
		return 0;

	// 获取当前内核纳秒时间戳，除以1000转为微秒存储，减少后续大数运算开销
	v->start_ts = bpf_ktime_get_ns() / 1000;
	// 保存本次执行的系统调用编号
	v->syscall_id = (bpf_s32_t)args->id;

	return 0;
}

/*
 * tracepoint/raw_syscalls/sys_exit：系统调用返回追踪点
 * 与sys_enter成对使用：读取同CPU缓存，计算整套syscall调用耗时
 * 多层过滤：PID匹配、最小延迟阈值过滤；符合条件则封装事件推送ringbuf，更新全局统计
 * 处理完成后置零start_ts，清除缓存脏数据，防止CPU连续syscall上下文错乱
 */
/**
* @brief 系统调用返回钩子，计算调用耗时、过滤、推送实时事件并更新全局统计
* @param args tracepoint原生返回参数结构体（本程序未读取返回值）
* @return 0 BPF tracepoint固定返回值
*/
SEC("kretprobe/udp_sendmsg")
SEC("tracepoint/raw_syscalls/sys_exit")
int trace_exit(struct trace_event_raw_sys_exit *args)
{
	struct Syscall_ctrl *c = get_ctrl();
	if (!c || !c->enable)
		return 0;

	int key = 0;
	// 读取当前CPU缓存的syscall入口现场
	struct start_val *v = bpf_map_lookup_elem(&enter_map, &ctrl_key);
	// 缓存不存在 或 缓存标记已消费(start_ts=0)，无有效syscall记录直接返回
	if (!v || v->start_ts == 0)
		return 0;

	// 获取系统调用返回时刻时间戳，单位微秒
	u64 now = bpf_ktime_get_ns() / 1000;
	// 计算整套系统调用完整耗时（入口时间 → 返回时间，单位微秒）
	u64 delay = now - v->start_ts;
	// 清空缓存时间戳，标记本条syscall记录已处理，避免脏数据干扰下一次CPU系统调用
	v->start_ts = 0;

	// 拆分当前线程pid_tgid：高32位TGID(进程PID)，低32位TID(线程ID)
	u64 pt = bpf_get_current_pid_tgid();
	bpf_s32_t pid = (bpf_s32_t)(pt >> 32);
	bpf_s32_t tid = (bpf_s32_t)(pt & 0xFFFFFFFF);

	// 过滤规则1：配置目标监控PID，当前进程不匹配，丢弃事件不上报
	if (c->target_pid != 0 && pid != c->target_pid)
		return 0;
	// 过滤规则2：配置最小延迟阈值，将微秒delay*1000还原为纳秒对比，耗时不足则丢弃
	if (c->min_latency_ns && delay * 1000 < c->min_latency_ns)
		return 0;

	// 从ringbuf预分配内存用于封装实时系统调用事件
	struct Syscall_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	// 填充事件基础信息
	e->ts_ns      = now;                 // 事件时间戳：syscall返回时刻(微秒)
	e->delay_ns   = delay;               // 整套syscall调用耗时(微秒)
	e->pid        = pid;                 // 进程TGID
	e->tid        = tid;                 // 线程LWP ID
	e->syscall_id = v->syscall_id;       // 本次执行的系统调用编号
	// 读取进程名称存入事件
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* 更新全局系统调用统计指标，持久化到stats_map数组map */
	struct Syscall_stats *st = bpf_map_lookup_elem(&stats_map, &ctrl_key);
	// 程序首次运行时stats_map无数据，初始化全零统计结构体写入map
	struct Syscall_stats z = {};
	if (!st) {
		bpf_map_update_elem(&stats_map, &ctrl_key, &z, BPF_ANY);
		st = bpf_map_lookup_elem(&stats_map, &ctrl_key);
	}
	// 统计指针有效，累加全局指标
	if (st) {
		st->count++;                    // 捕获syscall总次数+1
		st->total_ns += delay;          // 累加所有syscall总耗时(微秒)
		// 判断是否刷新单次最大耗时记录
		if (delay > st->max_ns) {
			st->max_ns = delay;
			st->max_pid = pid;
			st->max_syscall_id = v->syscall_id;
			__builtin_memcpy(st->max_comm, e->comm, TASK_COMM_LEN);
		}
	}

	// 将完整系统调用事件提交ringbuf，用户态libbpf阻塞读取解析打印
	bpf_ringbuf_submit(e, 0);

	return 0;
}
