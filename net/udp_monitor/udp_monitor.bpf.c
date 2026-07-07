#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "udp_monitor.h"

// BPF 程序许可证，必须声明 Dual BSD/GPL 才能使用 kprobe 等内核探针
char LICENSE[] SEC("license") = "Dual BSD/GPL";
// map 固定key常量，全局仅使用下标0存取数组map
const int ck = 0;

/**
 * @brief kprobe(udp_sendmsg) 阶段临时缓存结构
 * 每条UDP发送调用进入函数时保存上下文，退出kretprobe时读取计算延迟并上报
 */
struct udp_start {
    bpf_u64_t start_ts;      // udp_sendmsg 函数进入时间戳(ns)
    bpf_u64_t len;           // 本次发送UDP报文数据长度
    bpf_u32_t tgid;          // 线程组ID(进程PID)
    bpf_s32_t pid;           // 线程PID
    bpf_u16_t sport;         // 源端口（本机端口）
    bpf_u16_t dport;         // 目的端口
    bpf_u32_t saddr_v4;      // IPv4源地址（大端）
    bpf_u32_t daddr_v4;      // IPv4目的地址（大端）
    int af;                  // 地址族 AF_INET / AF_INET6
    bpf_s8_t  comm[TASK_COMM_LEN]; // 进程名(16字节)
    bpf_u8_t  saddr_v6[16];  // IPv6源地址16字节数组
    bpf_u8_t  daddr_v6[16];  // IPv6目的地址16字节数组
};

// ========== BPF MAP 定义区域 ==========
/**
 * start_map：每CPU数组，缓存udp_sendmsg入参上下文
 * 类型：PERCPU_ARRAY 避免多CPU并发覆盖脏数据，最大条目1，仅使用key=0
 * value：udp_start 临时缓存结构体
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct udp_start);
} start_map SEC(".maps");

/**
 * ctrl_map：全局控制开关配置map
 * 用户态下发过滤规则、总开关、最小延迟过滤阈值
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct UdpMonitor_ctrl);
} ctrl_map SEC(".maps");

/**
 * stats_map：全局UDP收发统计数据map
 * 累计发包数、总延迟、总字节、最大延迟记录等指标
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct UdpMonitor_stats);
} stats_map SEC(".maps");

/**
 * rb：环形缓冲区，内核向用户态推送UDP事件数据
 * 256KB 环形缓冲，低延迟批量上报事件
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
 * @brief 快捷获取全局控制配置指针
 * @return struct UdpMonitor_ctrl* 控制结构体指针，空表示未初始化
 */
static inline struct UdpMonitor_ctrl *get_ctrl(void)
{
    return bpf_map_lookup_elem(&ctrl_map, &ck);
}

/**
 * kprobe 钩子：udp_sendmsg 函数入口
 * 捕获UDP发送请求入参，填充临时缓存start_map，保存全部五元组、进程、时间信息
 * 参数：sk 套接字结构体; msg 用户层消息头; len 发送数据长度
 */
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    // 获取用户态下发的控制配置
    struct UdpMonitor_ctrl *c = get_ctrl();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    // 未开启监控 或 配置不存在，直接退出
    if (!c || !c->enable)
        return 0;
    // 配置指定了目标PID且当前进程不匹配，过滤丢弃
    if (c->target_pid != 0 && (u32)c->target_pid != tgid)
        return 0;

    int key = 0;
    // 获取当前CPU专属的临时缓存
    struct udp_start *v = bpf_map_lookup_elem(&start_map, &key);
    if (!v)
        return 0;

    // 记录进入udp_sendmsg的时间戳、报文长度、进程线程ID
    v->start_ts = bpf_ktime_get_ns();
    v->len      = len;
    v->pid      = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    v->tgid     = tgid;
    // CO-RE安全读取套接字地址族、本机源端口
    v->af       = BPF_CORE_READ(sk, __sk_common.skc_family);
    v->sport    = BPF_CORE_READ(sk, __sk_common.skc_num);
    // 读取当前进程名称
    bpf_get_current_comm(&v->comm, sizeof(v->comm));

    // 读取套接字绑定的源IP（本机地址）
    if (v->af == AF_INET) {
        // IPv4 源地址
        v->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    } else {
        // IPv6 源地址，批量读取16字节地址数组
        BPF_CORE_READ_INTO(&v->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    }

    // 目的地址：一次性读完整 sockaddr_in，回退到 sk
    struct sockaddr *dst = BPF_CORE_READ(msg, msg_name);
    int got_dst = 0;
    if (dst) {
        struct sockaddr_in sin;
        if (bpf_probe_read_user(&sin, sizeof(sin), dst) == 0 &&
            sin.sin_family == AF_INET) {
            v->dport    = sin.sin_port;
            v->daddr_v4 = sin.sin_addr.s_addr;
            got_dst = 1;
        }
    }
    if (!got_dst) {
        v->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
        if (v->af == AF_INET)
            v->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        else
            BPF_CORE_READ_INTO(&v->daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    return 0;
}

/**
 * kretprobe 钩子：udp_sendmsg 函数返回时触发
 * 读取入口缓存的上下文，计算函数调用延迟，过滤低延迟事件
 * 封装事件推入ringbuf给用户态，同时更新全局统计指标
 * 参数：retval udp_sendmsg系统调用返回值（发送成功字节/错误码，本代码未使用）
 */
SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(ret_udp_sendmsg, int retval)
{
    // 读取全局控制配置
    struct UdpMonitor_ctrl *c = get_ctrl();
    if (!c || !c->enable)
        return 0;

    int key = 0;
    struct udp_start *v = bpf_map_lookup_elem(&start_map, &key);
    // 缓存无有效数据（入口未触发），直接返回
    if (!v || v->start_ts == 0)
        return 0;

    // 计算本次udp_sendmsg调用耗时
    u64 now = bpf_ktime_get_ns();
    u64 lat = now - v->start_ts;
    // 清空本次缓存标记，防止下一轮复用脏数据
    v->start_ts = 0;

    // 配置最小延迟过滤，低于阈值丢弃事件
    if (c->min_latency_ns && lat < c->min_latency_ns)
        return 0;

    // 从ringbuf预分配事件内存
    struct UdpMonitor_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    // 填充上报事件全部字段
    e->ts_ns       = now;
    e->latency_ns  = lat;
    e->len         = v->len;
    e->pid         = v->pid;
    e->tgid        = v->tgid;
    e->af          = v->af;
    e->sport       = v->sport;
    e->dport       = v->dport;
    e->saddr_v4    = v->saddr_v4;
    e->daddr_v4    = v->daddr_v4;
    __builtin_memcpy(e->comm, v->comm, TASK_COMM_LEN);
    __builtin_memcpy(e->saddr_v6, v->saddr_v6, 16);
    __builtin_memcpy(e->daddr_v6, v->daddr_v6, 16);
    // 提交事件到环形缓冲区，用户态可读取
    bpf_ringbuf_submit(e, 0);

    // ========= 更新全局统计指标 =========
    struct UdpMonitor_stats *st = bpf_map_lookup_elem(&stats_map, &ck);
    struct UdpMonitor_stats zero_stats = {};
    // 统计map未初始化则填充全零初始值
    if (!st) {
        bpf_map_update_elem(&stats_map, &ck, &zero_stats, BPF_ANY);
        st = bpf_map_lookup_elem(&stats_map, &ck);
    }

    if (st) {
        st->count++;                // 总发包次数+1
        st->total_ns += lat;        // 累计总延迟
        st->total_bytes += v->len;  // 累计发送字节数

        // 更新最大延迟记录
        if (lat > st->max_ns) {
            st->max_ns = lat;
            st->max_pid = v->pid;
            __builtin_memcpy(st->max_comm, v->comm, TASK_COMM_LEN);
        }
    }

    return 0;
}
