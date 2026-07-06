// eBPF程序必须包含的内核类型定义
#include <vmlinux.h>

// eBPF核心帮助函数库
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// 包含我们自己定义的共用结构体
#include "context_switch.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ========================== 全局常量定义 ==========================
// 控制map的key值，固定为0（因为我们只需要一个全局控制块）
const int ctrl_key = 0;

// ========================== eBPF MAP 定义 ==========================

/*
 * 1. 时间戳存储 map
 * 作用：在 kprobe 记录切换开始时间，kretprobe 取出计算延迟
 * key：固定 0
 * value：时间戳 u64
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, u64);
} start_time_map SEC(".maps");

/*
 * 2. 全局控制 map
 * 作用：用户态设置 enable=true/false，控制 eBPF 是否采集数据
 * key：固定 0
 * value：struct ContextSwitch_Delay_ctrl
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct ContextSwitch_Delay_ctrl);
} ctrl_map SEC(".maps");

/*
 * 3. 环形缓冲区（ringbuf）
 * 作用：eBPF -> 用户态 传递采集到的事件数据
 * 高性能、无锁、官方推荐
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB 缓冲区大小
} rb SEC(".maps");

// ========================== 工具函数 ==========================
/*
 * 获取监控开关状态
 * 返回值：
 *   NULL = 未初始化 或 监控关闭
 *   非NULL = 可以开始采集数据
 */
static inline struct ContextSwitch_Delay_ctrl *get_switch_ctrl(void)
{
    // 从map中查找控制结构体
    struct ContextSwitch_Delay_ctrl *ctrl = bpf_map_lookup_elem(&ctrl_map, &ctrl_key);

    // 双重判断：
    // 1. map是否存在数据
    // 2. 开关是否为true
    if (!ctrl || !ctrl->enable)
        return NULL;

    return ctrl;
}

// ========================== 挂载点：进程切换开始 ==========================

/*
 * kprobe/schedule
 * 触发时机：当系统准备进行进程切换时
 * 作用：记录开始时间戳
 */
SEC("kprobe/schedule")
int BPF_KPROBE(schedule)
{
    // 先判断开关是否开启
    struct ContextSwitch_Delay_ctrl *ctrl = get_switch_ctrl();
    if (!ctrl)
        return 0;

    // 获取当前时间（纳秒），并转成微秒
    u64 start_time = bpf_ktime_get_ns() / 1000;
    int key = 0;

    // 将开始时间存入map
    bpf_map_update_elem(&start_time_map, &key, &start_time, BPF_ANY);

    return 0;
}

// ========================== 挂载点：进程切换结束 ==========================

/*
 * kretprobe/schedule
 * 触发时机：进程切换完成，函数返回时
 * 作用：计算延迟，并把数据发送到用户态
 */
SEC("kretprobe/schedule")
int BPF_KRETPROBE(schedule_exit)
{
    // 判断开关
    struct ContextSwitch_Delay_ctrl *ctrl = get_switch_ctrl();
    if (!ctrl)
        return 0;

    // 获取结束时间
    u64 end_time = bpf_ktime_get_ns() / 1000;

    // 从map中取出开始时间
    int key = 0;
    u64 *start_ptr = bpf_map_lookup_elem(&start_time_map, &key);
    if (!start_ptr)
        return 0;

    // 计算延迟
    u64 delay = end_time - *start_ptr;

    // 用完删除map，避免脏数据
    bpf_map_delete_elem(&start_time_map, &key);

    // ===================== 发送事件到用户态 =====================
    // 申请ringbuf空间
    struct ContextSwitch_Delay_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    // 填充数据
    e->start_time = *start_ptr;
    e->end_time   = end_time;
    e->delay      = delay;

    // 提交给用户态
    bpf_ringbuf_submit(e, 0);

    return 0;
}
