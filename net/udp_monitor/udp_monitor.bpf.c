/**
* @file udp_monitor.bpf.c
* @brief eBPF UDP发送监控探针，基于kprobe/kretprobe 跟踪udp_sendmsg / udpv6_sendmsg内核函数
*
* 功能说明：
* 1、捕获应用调用udp_sendmsg / udpv6_sendmsg内核函数执行耗时；统计报文实际发送长度、五元组、进程线程信息；
* 2、支持全局总开关、PID‑Namespace感知的PID过滤、最小延迟阈值过滤，过滤不需要上报的明细事件；
* 3、明细事件通过RINGBUF环形缓冲区低延迟推送给用户态程序；ringbuf满时丢弃事件，不阻塞内核发送路径；
* 4、维护per‑cpu全局累计统计：发包调用总次数、总字节、总延迟、最大延迟以及对应进程线程信息，同时记录各类过滤、丢包、map更新失败统计；
*
* 实现原理：
* 1、kprobe(udp_sendmsg / udpv6_sendmsg)：函数入口钩子；采集socket、msghdr、进程线程、时间戳，以bpf_get_current_pid_tgid()为key存入LRU_HASH类型start_map；
* 2、depth_map嵌套深度hash：解决IPv4‑mapped‑IPv6场景，udpv6_sendmsg内部递归调用udp_sendmsg造成重复采集，只对最外层调用做完整事件生命周期；内层仅增减嵌套深度，不新建上下文；
* 3、kprobe(udp_send_skb / udp_v6_send_skb)：报文真正构造skb阶段，此时路由已经完成，flowi4/flowi6以及skb网络头中保存最终生效五元组，覆盖入口阶段获取的不完整五元组（例如未bind sendto源IP为0.0.0.0场景）；
* 4、kretprobe(udp_sendmsg / udpv6_sendmsg)：函数返回钩子；通过pid_tgid key读取start_map上下文快照，计算内核函数耗时；依据retval区分发送成功/失败；按延迟阈值过滤；组装ringbuf事件上报；更新per‑cpu统计；清理start_map与depth_map上下文；
*
* 关键设计点：
* 1、放弃早期PERCPU_ARRAY上下文缓存方案：线程在udp_sendmsg执行过程中可被抢占、发生CPU迁移，per‑cpu槽会发生上下文错乱；改用LRU_HASH，key = bpf_get_current_pid_tgid()（高32位tgid进程，低32位pid线程），线程迁移CPU不影响key匹配；LRU自动淘汰老旧条目，防止内存泄露；
* 2、五元组三级采集策略：
*    ①入口msghdr.msg_name(sendto)；
*    ②connect UDP回退读取sock内部缓存对端地址；
*    ③udp_send_skb/udp_v6_send_skb阶段flowi4/flowi6 + skb网络头，获取路由决议之后真正生效的五元组，优先级最高；tuple_source标记五元组来源，用户态可以观测采集降级情况；
* 3、kretprobe无法获取原函数入参，全部现场信息必须在kprobe入口存入map，返回阶段读取快照；读取完成立刻删除map条目，避免脏条目残留；
* 4、retval真实语义：不用入参len，使用内核返回值retval作为实际发送字节；retval<0代表系统调用发送失败，只计入失败统计，不上报明细事件；
* 5、ringbuf采用bpf_ringbuf_reserve预分配内存再submit；缓冲区满reserve返回NULL直接丢弃明细，但是per‑cpu统计指标仍然更新，保证汇总统计不受ringbuf丢事件影响；
* 6、stats_map使用BPF_MAP_TYPE_PERCPU_ARRAY，每个CPU独立一套统计结构体，规避多CPU并发写的数据竞争；用户态读取全部CPU副本，做聚合求和得到全局统计；
* 7、PID‑Namespace兼容：内核bpf_get_current_pid_tgid拿到的是初始命名空间PID；通过pid_ns_dev/ino转换得到目标PID namespace内可见PID，过滤与上报展示使用namespace内PID，适配容器场景；
*
* 局限：
* 1、仅监控UDP发送路径 udp_sendmsg / udpv6_sendmsg；不监控接收路径 udp_recvmsg；
* 2、当前基于kprobe/kretprobe，强依赖内核kallsyms符号；内核符号剥离、kprobe关闭环境无法加载；生产环境优先替换为tracepoint；
* 3、LRU_HASH max_entries存在上限，极端高并发短生命周期线程，LRU淘汰会丢失部分事件；可根据业务调大max_entries；
* 4、IPv4‑mapped‑IPv6递归路径依靠depth_map做嵌套防护，如果入口kprobe丢失，depth_map条目残留会造成该线程后续UDP事件全部识别为嵌套调用，事件丢失；
* 5、ringbuf丢弃的仅仅是明细事件，聚合统计仍然保留；但明细丢失无法还原单包完整链路；
*
*/

/*
udp_monitor.bpf.c 整体执行流程
├──【用户态】写入 ctrl_map(enable/target_pid/min_latency_ns/pid_ns)
│
├── 触发路径A：kprobe/udp_sendmsg       ──┐
├── 触发路径B：kprobe/udpv6_sendmsg     ──┼──> record_udp_send(sk,msg,len) 【入口公共逻辑】
│                                         │
│                                         ├─ 读取 ctrl_map
│                                         │   ├─ enable=0 / ctrl不存在 → return 0 (直接退出)
│                                         │   └─ enable=1 继续
│                                         │
│                                         ├─ app_current_pid_tgid_ns() 做PID‑Namespace转换
│                                         │   ├─ visible_pid_tgid=0 → stats.filtered_pid++ return 0
│                                         │   └─ 拿到ns内tgid/tid继续
│                                         │
│                                         ├─ target_pid过滤(非0时)
│                                         │   ├─ 不匹配 → stats.filtered_pid++ return 0
│                                         │   └─ 匹配继续
│                                         │
│                                         ├─ 查询 depth_map[key=pid_tgid]
│                                         │   ├─ depth已存在(嵌套调用，IPv4‑mapped‑IPv6内层)
│                                         │   │    ├─ *depth +=1
│                                         │   │    ├─ stats.nested_calls++
│                                         │   │    └─ return 0；不创建start_map
│                                         │   │
│                                         │   └─ depth不存在【最外层UDP调用】
│                                         │        ├─ bpf_map_update_elem depth_map BPF_NOEXIST
│                                         │        │    ├─ 更新失败 → stats.map_update_failed++ return 0
│                                         │        │    └─ depth=1写入成功继续
│                                         │        │
│                                         │        ├─ 填充栈 struct udp_start entry
│                                         │        │   ├─ start_ts(bpf_ktime_get_ns)、len、pid/tgid、comm
│                                         │        │   ├─ BPF_CORE_READ sk获取 af、sport、saddr_v4/saddr_v6
│                                         │        │   ├─ 读取 msg->msg_name(sendto目的地址)
│                                         │        │   │    ├─ 读取成功 → tuple_source=UDP_TUPLE_MSG
│                                         │        │   │    └─ 读取失败(msg_name=null/connect udp)
│                                         │        │   │         └─ 回退读sock内部对端地址 tuple_source=UDP_TUPLE_SOCKET
│                                         │        │   │
│                                         │        └─ bpf_map_update_elem start_map(key=pid_tgid, &entry, BPF_ANY)
│                                         │               ├─ 更新失败 → 删除depth_map，stats.map_update_failed++ return0
│                                         │               └─ 更新成功 → stats.attempted++ return0；等待后续探针
│
│
├── 触发路径C：kprobe/udp_send_skb      ──┐
│  (udp_sendmsg内部构造skb，路由完成)     │
│                                        ├─ key = bpf_get_current_pid_tgid()
│                                        ├─ 查 start_map[key]
│                                        │    ├─ 找不到上下文 → return 0
│                                        │    └─ 找到上下文
│                                        │         ├─ 读取flowi4
│                                        │         ├─ 读取skb network_header → iphdr
│                                        │         ├─ 用skb真实IPv4头覆盖五元组
│                                        │         └─ tuple_source = UDP_TUPLE_FLOW (最高优先级)
│
├── 触发路径D：kprobe/udp_v6_send_skb   ──┐
│  (udpv6_sendmsg内部构造skb，路由完成)   │
│                                        ├─ key = bpf_get_current_pid_tgid()
│                                        ├─ 查 start_map[key]
│                                        │    ├─ 找不到上下文 → return0
│                                        │    └─ 找到上下文
│                                        │         ├─ 读取flowi6
│                                        │         ├─ 读取skb network_header → ipv6hdr
│                                        │         ├─ 用skb真实IPv6头覆盖五元组
│                                        │         └─ tuple_source = UDP_TUPLE_FLOW
│
│
├── 触发路径E：kretprobe/udp_sendmsg    ──┐
├── 触发路径F：kretprobe/udpv6_sendmsg  ──┼──> finish_udp_send(retval)【返回结算公共逻辑】
                                          │
                                          ├─ key = bpf_get_current_pid_tgid()
                                          ├─ 查询 depth_map[key]
                                          │    ├─ depth不存在 → stats.lookup_missed++ return0 (入口kprobe丢事件)
                                          │    └─ depth存在
                                          │         ├─ *depth >1 【内层嵌套调用返回】
                                          │         │    ├─ *depth -=1
                                          │         │    └─ return0；不做事件结算
                                          │         │
                                          │         └─ *depth ==1【最外层调用返回】
                                          │              ├─ bpf_map_delete_elem depth_map[key]
                                          │              ├─ 查询 start_map[key]
                                          │              │    ├─ 找不到 / start_ts=0 → stats.lookup_missed++ return0
                                          │              │    └─ 找到上下文
                                          │              │         ├─ __builtin_memcpy拷贝到栈 snapshot !!!关键
                                          │              │         ├─ bpf_map_delete_elem start_map[key] 立刻清理map
                                          │              │         │
                                          │              │         ├─ ctrl.enable==0 → return0，仅清理map不统计不上报
                                          │              │         │
                                          │              │         ├─ now = bpf_ktime_get_ns()
                                          │              │         ├─ lat = now - snapshot.start_ts
                                          │              │         │
                                          │              │         ├─ retval < 0 (发送失败)
                                          │              │         │    ├─ stats.failed++
                                          │              │         │    └─ return0，不输出ringbuf明细
                                          │              │         │
                                          │              │         ├─ retval >=0 发送成功
                                          │              │         │    ├─ 更新per‑cpu stats_map: count、total_ns、total_bytes
                                          │              │         │    ├─ 根据tuple_source统计 flow_tuple / fallback_tuple
                                          │              │         │    └─ 比较lat更新max_ns/max_pid/max_tid/max_comm
                                          │              │         │
                                          │              │         ├─ min_latency_ns阈值过滤
                                          │              │         │    ├─ lat < min_latency_ns → stats.filtered_latency++ return0
                                          │              │         │    └─ 满足延迟阈值继续，准备上报明细
                                          │              │         │
                                          │              │         ├─ bpf_ringbuf_reserve(&rb, sizeof(event),0)
                                          │              │         │    ├─ reserve返回NULL ringbuf满
                                          │              │         │    │    ├─ stats.ringbuf_dropped++
                                          │              │         │    │    └─ return0；汇总统计已经更新，丢弃明细
                                          │              │         │    │
                                          │              │         │    └─ 分配event内存成功
                                          │              │         │         ├─ 填充UdpMonitor_event全部字段
                                          │              │         │         ├─ memcpy comm、saddr_v6、daddr_v6数组
                                          │              │         │         └─ bpf_ringbuf_submit(e,0) → 用户态收到UDP发送事件
                                          │
└──【用户态】
    ├─ 循环读取 ringbuf rb 回调消费 UdpMonitor_event 明细事件
    └─ 轮询读取 stats_map 全部per‑cpu副本，聚合求和得到全局统计指标

*/

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "udp_monitor.h"
#include "common/pid_namespace.bpf.h"

/**
* @brief BPF程序许可证声明
* kprobe/kretprobe探针必须声明 Dual BSD/GPL许可证；内核模块校验不通过会直接拒绝eBPF程序加载
*/
char LICENSE[] SEC("license") = "Dual BSD/GPL";

/**
* @brief map固定key常量
* ctrl_map、stats_map为max_entries=1的ARRAY / PERCPU_ARRAY，固定使用key=0访问唯一的配置/统计实例
*/
const int ck = 0;

/**
* @struct udp_start
* @brief kprobe入口阶段临时缓存结构体，保存udp_sendmsg调用现场，给kretprobe返回阶段、flowi探针使用
*
* 说明：
* kretprobe钩子函数不能拿到原udp_sendmsg函数入参sk、msg、len；flowi探针也需要线程关联上下文；
* 入口kprobe钩子采集全部需要的上下文存入start_map(LRU_HASH)；
* key：bpf_get_current_pid_tgid()，高32位tgid(进程组ID/PID)，低32位pid(线程ID/TID)
*/
struct udp_start {
    bpf_u64_t start_ts;      ///< udp_sendmsg / udpv6_sendmsg 内核函数进入时刻时间戳，单位ns，来源bpf_ktime_get_ns
    bpf_u64_t len;           ///< 用户调用传入的待发送报文长度（系统调用入参len，注意不等于实际发送字节，实际以retval为准）
    bpf_u32_t tgid;          ///< PID‑Namespace转换后线程组ID，用户态可见进程PID
    bpf_s32_t pid;           ///< PID‑Namespace转换后线程ID(TID)，同一进程多线程TID不同
    bpf_u16_t sport;         ///< UDP源端口，主机字节序
    bpf_u16_t dport;         ///< UDP目的端口，主机字节序
    bpf_u32_t saddr_v4;      ///< IPv4源地址，网络字节序；af != AF_INET时此字段无业务含义
    bpf_u32_t daddr_v4;      ///< IPv4目的地址，网络字节序；af != AF_INET时此字段无业务含义
    int af;                  ///< socket地址族：AF_INET(2) IPv4；AF_INET6(10) IPv6
    bpf_s8_t  comm[TASK_COMM_LEN]; ///< 进程名称，TASK_COMM_LEN固定16字节，包含字符串结束'\0'
    bpf_u8_t  saddr_v6[16];  ///< IPv6源地址，16字节原始网络序数组；af != AF_INET6无意义
    bpf_u8_t  daddr_v6[16];  ///< IPv6目的地址，16字节原始网络序数组；af != AF_INET6无意义
    bpf_u8_t  tuple_source;   ///< enum UdpTupleSource五元组采集来源：MSG/ SOCKET / FLOW；标记五元组来自msg_name、sock缓存、flowi+skb路由后真实报文
};

// ===================== BPF MAP定义区域 =====================

/**
* @map start_map
* @brief LRU_HASH，保存线程的udp_sendmsg调用上下文 udp_start
* type: BPF_MAP_TYPE_LRU_HASH LRU哈希，超出max_entries自动淘汰最久未使用条目，避免内存泄漏
* max_entries:16384，最大同时缓存16384个线程的UDP发送上下文；业务高并发场景可以调大
* key: bpf_u64_t，bpf_get_current_pid_tgid()，线程唯一标识
* value: struct udp_start，线程调用现场快照
*
* 设计说明：
* 废弃早期PERCPU_ARRAY方案：函数执行中线程可抢占、CPU迁移，per‑cpu单槽位会上下文错乱；
* 使用pid_tgid作为key，线程CPU迁移不影响key匹配；kprobe入口update_elem写入；kretprobe结算完成delete_elem删除；
* 生命周期：kprobe入口填充字段写入map；kretprobe读取快照，立刻删除map条目，避免脏数据残留；
* udp_send_skb / udp_v6_send_skb探针根据同一个pid_tgid key查找，覆写五元组为路由后真实值。
*/
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, bpf_u64_t);
    __type(value, struct udp_start);
} start_map SEC(".maps");

/**
* @map depth_map
* @brief HASH map，记录每个线程UDP发送函数嵌套调用深度，解决IPv4‑mapped‑IPv6递归调用问题
*
* 场景说明：
* IPv6 socket发送IPv4映射地址时，udpv6_sendmsg内部会递归调用udp_sendmsg；
* 如果不记录嵌套深度，内层udp_sendmsg kprobe会新建start_map条目，同一个用户请求产生两次事件上报；
* 规则：
* 1、线程第一次进入（depth不存在），depth=1，新建start_map上下文，作为最外层调用；
* 2、再次进入该线程已经存在depth，depth++，内层调用，不新建start_map；
* 3、kretprobe返回时depth>1则depth‑‑；depth==1代表最外层返回，执行完整事件结算、删除depth与start_map；
*
* key：bpf_u64_t pid_tgid线程标识；value：bpf_u32_t嵌套调用深度；
* max_entries与start_map对齐16384；
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, bpf_u64_t);
    __type(value, bpf_u32_t);
} depth_map SEC(".maps");

/**
* @map ctrl_map
* @brief ARRAY map，用户态下发监控控制参数
* max_entries=1，key=0唯一实例；
* 用户态libbpf写入UdpMonitor_ctrl配置结构体；
* 字段包括enable总开关、target_pid过滤PID、min_latency_ns最小上报延迟阈值、pid_ns_dev/ino目标PID命名空间；
* BPF侧只读读取配置，不修改；
*/
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct UdpMonitor_ctrl);
} ctrl_map SEC(".maps");

/**
* @map stats_map
* @brief PERCPU_ARRAY map，UDP发送统计指标，每个CPU独立一份统计结构体
* type BPF_MAP_TYPE_PERCPU_ARRAY，max_entries=1 key=0；
* 每个CPU写自己的统计副本，完全规避多CPU并发写race condition；
* 用户态读取全部CPU副本，遍历累加得到全局统计结果；
* 统计包含成功调用计数、总字节、总延迟、最大延迟记录，以及各类过滤、失败、map错误、ringbuf丢包计数；
*/
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct UdpMonitor_stats);
} stats_map SEC(".maps");

/**
* @map rb
* @brief RINGBUF环形缓冲区，内核向用户态输出UDP明细事件UdpMonitor_event
* max_entries=256*1024 缓冲区大小256KB；
* 使用bpf_ringbuf_reserve预分配内存，分配成功填充结构体，bpf_ringbuf_submit提交；
* 缓冲区满，reserve返回NULL，直接丢弃明细事件，**不会阻塞内核UDP发送路径**；
* 注意：ringbuf丢弃明细事件时，stats_map per‑cpu统计仍然更新，汇总统计不会丢失；
* 对比perf buffer：ringbuf支持预分配，减少数据拷贝，性能更优。
*/
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
* @brief get_ctrl() 内联快捷函数，获取用户态下发的监控控制配置
* @return struct UdpMonitor_ctrl* 成功返回map value指针；NULL代表map没有配置，探针直接不工作
*/
static inline struct UdpMonitor_ctrl *get_ctrl(void)
{
    return bpf_map_lookup_elem(&ctrl_map, &ck);
}

/**
* @brief get_stats() 获取当前CPU专属的统计结构体副本，PERCPU_ARRAY key=0
* @return struct UdpMonitor_stats*，per‑cpu array固定可以查到，不会返回NULL
*/
static __always_inline struct UdpMonitor_stats *get_stats(void)
{
    return bpf_map_lookup_elem(&stats_map, &ck);
}

/**
* @brief record_udp_send kprobe入口公共逻辑，udp_sendmsg / udpv6_sendmsg探针共用
*
* 内核原型：int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
* 内核原型：int udpv6_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
*
* 触发时机：刚进入udp_sendmsg / udpv6_sendmsg内核函数，发送逻辑尚未执行；
* 功能：做开关过滤、PID‑namespace转换、PID过滤；处理嵌套深度depth_map；采集进程、socket、msghdr五元组；
* 组装struct udp_start，写入start_map LRU_HASH供flow探针、kretprobe返回探针使用；
*
* @param sk 内核struct sock socket对象指针
* @param msg struct msghdr消息头内核指针，保存msg_name目的地址、iovec等信息
* @param len size_t 用户传入待发送报文长度（系统调用入参）
* @return int BPF探针返回值，0，kprobe返回值无内核语义，仅做探针内部逻辑返回
*/
static __always_inline int record_udp_send(struct sock *sk, struct msghdr *msg,
                                           size_t len)
{
    // 获取用户态下发的控制配置
    struct UdpMonitor_ctrl *c = get_ctrl();
    // 获取当前CPU独立统计副本
    struct UdpMonitor_stats *stats = get_stats();
    // 获取内核全局pid_tgid，作为start_map/depth_map的key；高32位tgid，低32位tid
    bpf_u64_t key = bpf_get_current_pid_tgid();
    // 保存转换到目标PID namespace内可见pid_tgid，用于过滤和上报
    bpf_u64_t visible_pid_tgid;
    // depth_map value指针，嵌套深度
    bpf_u32_t *depth;
    // depth初始值，第一次进入线程depth设置为1
    bpf_u32_t one = 1;
    // 栈上临时udp_start，采集完成后拷贝写入map
    struct udp_start entry = {};
    struct udp_start *v = &entry;
    u32 tgid;

    // 配置不存在，或者总开关enable关闭，直接返回，探针不处理本次调用
    if (!c || !c->enable)
        return 0;

    /*
     * key使用内核全局pid_tgid，保证kprobe入口、udp_send_skb flow探针、kretprobe返回探针三方key完全一致；
     * 过滤条件、上报展示使用目标PID‑Namespace里面可见PID，适配容器；
     * app_current_pid_tgid_ns 根据传入的pid_ns_dev/ino做命名空间转换；返回0代表不在目标命名空间；
     */
    visible_pid_tgid = app_current_pid_tgid_ns(c->pid_ns_dev, c->pid_ns_ino);
    if (!visible_pid_tgid) {
        // 当前线程不在目标PID namespace，计入过滤计数，直接返回
        if (stats)
            stats->filtered_pid++;
        return 0;
    }
    // 提取namespace内的tgid(进程PID，高32位)
    tgid = visible_pid_tgid >> 32;

    /*
     * 用户态配置target_pid!=0开启单PID过滤；
     * 当前进程namespace内PID不等于target_pid，直接过滤本次调用；
     */
    if (c->target_pid != 0 && (u32)c->target_pid != tgid) {
        if (stats)
            stats->filtered_pid++;
        return 0;
    }

    // 查询depth_map，判断当前线程UDP调用嵌套深度
    depth = bpf_map_lookup_elem(&depth_map, &key);
    if (depth) {
        /*
         * depth条目存在，说明线程处于UDP发送嵌套调用（IPv4‑mapped‑IPv6场景内层调用）；
         * 嵌套深度+1，统计嵌套调用计数；不新建start_map上下文；直接返回；
         * 内层调用仍然会触发udp_send_skb flow探针，但是找不到start_map key，不会覆写五元组，无副作用；
         */
        (*depth)++;
        if (stats)
            stats->nested_calls++;
        return 0;
    }

    /*
     * depth_map不存在，代表最外层UDP发送调用；
     * BPF_NOEXIST：只有key不存在的时候才写入；防止并发race重复插入；
     * update失败代表map满，无法建立嵌套标记，统计map_update_failed，直接返回，放弃本次事件采集；
     */
    if (bpf_map_update_elem(&depth_map, &key, &one, BPF_NOEXIST)) {
        if (stats)
            stats->map_update_failed++;
        return 0;
    }

    // ==========填充基础时间戳、进程线程信息==========
    v->start_ts = bpf_ktime_get_ns();  // 记录内核函数进入时刻时间戳，kretprobe用它计算函数耗时
    v->len      = len;                 // 用户传入待发送长度，入参保存，不等于实际发送字节，实际以retval为准
    v->pid      = visible_pid_tgid & 0xFFFFFFFF; // namespace可见线程TID，取低32位
    v->tgid     = tgid;                // namespace可见进程PID

    // BPF_CORE_READ CO‑RE安全读取sk结构体成员，跨不同内核版本兼容BTF
    v->af       = BPF_CORE_READ(sk, __sk_common.skc_family);  // socket地址族 AF_INET / AF_INET6
    v->sport    = BPF_CORE_READ(sk, __sk_common.skc_num);     // 本机UDP源端口，主机字节序

    // 获取当前task comm进程名称，拷贝到结构体comm字段，TASK_COMM_LEN=16
    bpf_get_current_comm(&v->comm, sizeof(v->comm));

    // ==========读取本机源IP地址==========
    if (v->af == AF_INET) {
        /*
         * IPv4：读取inet_sock->inet_saddr，本机绑定源IP，网络字节序；
         * 未bind的sendto场景，此处可能为0.0.0.0；后续udp_send_skb flow探针会用flowi4/skb头覆盖为路由后真实源IP；
         * skc_rcv_saddr是接收地址，发送场景优先inet_saddr；
         */
        v->saddr_v4 = BPF_CORE_READ((struct inet_sock *)sk, inet_saddr);
    } else {
        /*
         * IPv6场景；BPF_CORE_READ_INTO专门用于读取数组类型内核成员；
         * 将sk的skc_v6_rcv_saddr拷贝到v->saddr_v6[16字节]数组；网络字节序；
         */
        BPF_CORE_READ_INTO(&v->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    }

    // ==========读取目的地址，优先msghdr.msg_name(sendto)，失败回退sock内部缓存(connect UDP)==========
    // msg->msg_name：sendto传入的用户态目的地址指针；已经被内核拷贝至内核内存，使用bpf_probe_read_kernel读取
    struct sockaddr *dst = BPF_CORE_READ(msg, msg_name);
    // msg_namelen msg_name结构体有效字节长度，做安全校验，防止越界读取
    int dst_len = BPF_CORE_READ(msg, msg_namelen);
    // got_dst标记：是否成功从msg_name拿到目的地址
    int got_dst = 0;

    if (dst) {
        bpf_u16_t family = 0;
        /*
         * 安全校验：dst_len大于最小sockaddr头部大小；
         * bpf_probe_read_kernel读取内核内存的sockaddr sa_family地址族；
         */
        if (dst_len >= (int)sizeof(struct sockaddr) &&
            bpf_probe_read_kernel(&family, sizeof(family), dst) == 0) {
            // 分支1：IPv4 sockaddr_in
            if (family == AF_INET && dst_len >= (int)sizeof(struct sockaddr_in)) {
                struct sockaddr_in sin = {};
                // 将内核内存中sockaddr_in完整拷贝到栈局部变量sin
                if (bpf_probe_read_kernel(&sin, sizeof(sin), dst) == 0) {
                    v->af       = AF_INET;
                    v->dport    = bpf_ntohs(sin.sin_port);        // 网络序端口转主机序存入
                    v->daddr_v4 = sin.sin_addr.s_addr;            // IPv4目的地址，网络字节序
                    v->tuple_source = UDP_TUPLE_MSG;              // 五元组来源标记：来自msghdr msg_name
                    got_dst = 1;
                }
            }
            // 分支2：IPv6 sockaddr_in6
            else if (family == AF_INET6 &&
                       dst_len >= (int)sizeof(struct sockaddr_in6)) {
                struct sockaddr_in6 sin6 = {};
                // 拷贝内核sockaddr_in6到栈局部变量
                if (bpf_probe_read_kernel(&sin6, sizeof(sin6), dst) == 0) {
                    v->af = AF_INET6;
                    v->dport = bpf_ntohs(sin6.sin6_port);
                    // 拷贝16字节IPv6目的地址数组
                    __builtin_memcpy(v->daddr_v6,
                                     sin6.sin6_addr.in6_u.u6_addr8, 16);
                    v->tuple_source = UDP_TUPLE_MSG;
                    got_dst = 1;
                }
            }
        }
    }

    /*
     * got_dst等于0两种情况：
     * 1、msg_name == NULL，对应connect后的UDP socket；
     * 2、读取msg_name内存失败；
     * 回退读取sock结构体内部缓存的对端地址；tuple_source标记UDP_TUPLE_SOCKET；
     */
    if (!got_dst) {
        // skc_dport是网络字节序端口，转为主机字节序保存
        v->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        v->tuple_source = UDP_TUPLE_SOCKET;
        if (v->af == AF_INET) {
            v->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        } else {
            // IPv6回退读取sk内部缓存对端IPv6地址
            BPF_CORE_READ_INTO(&v->daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
        }
    }

    /*
     * 将栈上组装好的udp_start entry写入start_map LRU_HASH；key=pid_tgid；BPF_ANY允许覆盖旧key；
     * 如果map更新失败(LRU map满)，必须同步删除depth_map条目；
     * 否则depth_map残留条目，该线程后续全部UDP调用都被识别为嵌套调用，事件永久丢失；
     */
    if (bpf_map_update_elem(&start_map, &key, v, BPF_ANY)) {
        bpf_map_delete_elem(&depth_map, &key);
        if (stats)
            stats->map_update_failed++;
        return 0;
    }
    // 统计：成功建立上下文的调用尝试计数
    if (stats)
        stats->attempted++;

    return 0;
}

/**
* @brief kprobe钩子：udp_sendmsg IPv4 UDP发送入口
* SEC("kprobe/udp_sendmsg")挂载内核函数udp_sendmsg；
* BPF_KPROBE宏：自动解析内核函数入参sk,msg,len；
* 直接调用公共入口函数record_udp_send完成采集；
*/
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    return record_udp_send(sk, msg, len);
}

/**
* @brief kprobe钩子：udpv6_sendmsg IPv6 UDP发送入口
* 原实现缺失该探针，导致IPv6 UDP发送事件完全漏报；
* BPF_KPROBE自动解析入参sk,msg,len；复用record_udp_send公共采集逻辑；
*/
SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(trace_udpv6_sendmsg, struct sock *sk, struct msghdr *msg,
               size_t len)
{
    return record_udp_send(sk, msg, len);
}

/**
* @brief kprobe钩子 udp_send_skb：IPv4 UDP真正构造skb报文的函数；路由已经执行完毕
*
* 内核原型：int udp_send_skb(struct sk_buff *skb, struct flowi4 *fl4, struct inet_cork *cork);
*
* 问题背景：udp_sendmsg入口阶段，未bind的sendto场景源IP可能是0.0.0.0；
* 直到udp_send_skb路由完成，flowi4、skb的IPv4头部里面保存真正生效五元组；
* 探针读取flowi4，同时读取skb网络层IP头，优先skb头的值，覆盖start_map中旧五元组；
* 使用bpf_get_current_pid_tgid()作为key查找start_map，覆写五元组字段，tuple_source标记UDP_TUPLE_FLOW；
*
* @param skb 待发送skb数据包缓冲区
* @param fl4 flowi4路由结构体，保存路由解析后的源目的IP、端口
* @param cork inet_cork cork缓存结构，本探针未使用，void强消除编译警告
* @return int 探针返回0
*/
SEC("kprobe/udp_send_skb")
int BPF_KPROBE(trace_udp_send_skb, struct sk_buff *skb, struct flowi4 *fl4,
               struct inet_cork *cork)
{
    // 获取当前线程pid_tgid key，与入口kprobe保持一致
    bpf_u64_t key = bpf_get_current_pid_tgid();
    // 根据key查询线程上下文快照；kprobe丢失、嵌套内层调用会返回NULL直接返回
    struct udp_start *v = bpf_map_lookup_elem(&start_map, &key);
    struct iphdr iph = {};
    unsigned char *head;
    bpf_u16_t network_header;

    // 消除cork参数未使用编译告警
    (void)cork;
    // 上下文不存在或者flowi4为NULL直接返回，不做处理
    if (!v || !fl4)
        return 0;

    // 更新地址族标记IPv4
    v->af = AF_INET;

    // 首先读取flowi4路由结构体中的源IP、目的IP
    v->saddr_v4 = BPF_CORE_READ(fl4, saddr);
    v->daddr_v4 = BPF_CORE_READ(fl4, daddr);

    // 获取skb head缓冲区指针，network_header是ip头相对于skb->head偏移量
    head = BPF_CORE_READ(skb, head);
    network_header = BPF_CORE_READ(skb, network_header);

    /*
     * 优先读取skb真实IPv4头部，防止隧道路径、特殊路由flowi4还保留通配0地址；
     * head + network_header得到iphdr内存地址；bpf_probe_read_kernel拷贝iphdr；校验iph.version==4确认IPv4头；
     * 如果读取成功，使用skb报文头IP覆盖flowi4的值，这是最终真正发出报文的五元组；
     */
    if (head &&
        bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header) == 0 &&
        iph.version == 4) {
        v->saddr_v4 = iph.saddr;
        v->daddr_v4 = iph.daddr;
    }

    // flowi4 uli.ports保存源端口目的端口，网络序转主机序存入上下文
    v->sport = bpf_ntohs(BPF_CORE_READ(fl4, uli.ports.sport));
    v->dport = bpf_ntohs(BPF_CORE_READ(fl4, uli.ports.dport));
    // 标记五元组来源：路由flow+skb报文头，优先级最高
    v->tuple_source = UDP_TUPLE_FLOW;
    return 0;
}

/**
* @brief kprobe钩子 udp_v6_send_skb：IPv6 UDP真正构造skb报文函数；路由已经完成
*
* 内核原型 int udp_v6_send_skb(struct sk_buff *skb, struct flowi6 *fl6, struct inet_cork *cork);
*
* 逻辑同IPv4版本；flowi6可能saddr为::，未bind场景；
* skb此时已经填充IPv6报文头，优先从skb网络头读取真实源、目的IPv6地址；
* 更新start_map上下文五元组，tuple_source标记UDP_TUPLE_FLOW；
*
* @param skb 待发送skb缓冲区
* @param fl6 flowi6路由结构体
* @param cork inet_cork，本探针不使用
* @return int 返回0
*/
SEC("kprobe/udp_v6_send_skb")
int BPF_KPROBE(trace_udp_v6_send_skb, struct sk_buff *skb, struct flowi6 *fl6,
               struct inet_cork *cork)
{
    bpf_u64_t key = bpf_get_current_pid_tgid();
    struct udp_start *v = bpf_map_lookup_elem(&start_map, &key);
    struct ipv6hdr ip6h = {};
    unsigned char *head;
    bpf_u16_t network_header;

    (void)cork;
    if (!v || !fl6)
        return 0;

    // 设置地址族IPv6
    v->af = AF_INET6;
    // 先读取flowi6里面的saddr daddr，网络字节序拷贝到上下文数组
    BPF_CORE_READ_INTO(v->saddr_v6, fl6, saddr.in6_u.u6_addr32);
    BPF_CORE_READ_INTO(v->daddr_v6, fl6, daddr.in6_u.u6_addr32);

    /*
     * IPv6未bind场景flowi6.saddr可能为::；skb已经构造完成IPv6报文头；
     * 读取skb head + network_header偏移得到ipv6hdr，拷贝真实报文源目的IPv6地址，覆盖flowi6；
     */
    head = BPF_CORE_READ(skb, head);
    network_header = BPF_CORE_READ(skb, network_header);
    if (head &&
        bpf_probe_read_kernel(&ip6h, sizeof(ip6h), head + network_header) == 0 &&
        ip6h.version == 6) {
        __builtin_memcpy(v->saddr_v6, ip6h.saddr.in6_u.u6_addr8, 16);
        __builtin_memcpy(v->daddr_v6, ip6h.daddr.in6_u.u6_addr8, 16);
    }

    // flowi6 uli.ports端口网络序转主机序保存
    v->sport = bpf_ntohs(BPF_CORE_READ(fl6, uli.ports.sport));
    v->dport = bpf_ntohs(BPF_CORE_READ(fl6, uli.ports.dport));
    v->tuple_source = UDP_TUPLE_FLOW;
    return 0;
}

/**
* @brief finish_udp_send kretprobe返回探针公共结算逻辑；udp_sendmsg / udpv6_sendmsg kretprobe共用
*
* 触发时机：udp_sendmsg / udpv6_sendmsg内核函数执行完毕，函数即将返回；
* @param retval int，内核udp_sendmsg返回值；>0代表成功发送字节数；<0负错误码代表发送失败；
*
* 工作流程：
* 1、查询depth_map嵌套深度；内层调用depth‑‑直接返回；只有depth==1最外层调用才执行完整事件结算；
* 2、拿到start_map上下文，__builtin_memcpy复制完整快照；立刻删除map条目，避免verifier不允许删除后访问map value；
* 3、retval<0发送失败，只统计失败计数，不上报ringbuf明细；
* 4、retval>=0发送成功：计算内核函数执行latency_ns；更新per‑cpu全部统计指标；统计先执行，ringbuf满丢明细也不影响汇总统计；
* 5、判断min_latency_ns阈值，小于阈值过滤明细事件；
* 6、bpf_ringbuf_reserve预分配ringbuf事件内存；分配失败统计ringbuf_dropped，直接返回；
* 7、填充UdpMonitor_event事件全部字段；数组字段使用memcpy拷贝；bpf_ringbuf_submit提交事件给用户态；
*
* 注意：即使全局开关c->enable关闭，也必须执行map清理逻辑，防止start_map、depth_map残留脏条目；
*/
static __always_inline int finish_udp_send(int retval)
{
    struct UdpMonitor_ctrl *c = get_ctrl();
    struct UdpMonitor_stats *st = get_stats();
    bpf_u64_t key = bpf_get_current_pid_tgid();
    // 栈快照：必须在map删除之前把value完整拷贝到栈内存；BPF verifier禁止bpf_map_delete_elem之后访问map返回的指针
    struct udp_start snapshot = {};
    struct udp_start *v;
    bpf_u32_t *depth;

    /*
     * 第一步处理depth_map嵌套深度；
     * 即使总开关关闭，也要清理map条目，防止脏条目永久驻留map；
     * depth条目找不到：说明入口kprobe丢失，统计lookup_missed计数；直接返回；
     */
    depth = bpf_map_lookup_elem(&depth_map, &key);
    if (!depth) {
        if (c && c->enable && st)
            st->lookup_missed++;
        return 0;
    }

    // depth大于1，代表是内层嵌套调用，深度减一，直接返回，不做事件上报；最外层才往下执行
    if (*depth > 1) {
        (*depth)--;
        return 0;
    }

    // depth等于1：最外层调用；删除depth_map条目；后续处理start_map
    bpf_map_delete_elem(&depth_map, &key);

    // 根据pid_tgid key读取UDP发送上下文start_map
    v = bpf_map_lookup_elem(&start_map, &key);
    // kprobe丢失，上下文不存在，统计lookup_missed，直接返回
    if (!v || v->start_ts == 0) {
        if (c && c->enable && st)
            st->lookup_missed++;
        return 0;
    }

    /*
     * 关键：把map value完整拷贝到栈上snapshot；
     * 之后马上bpf_map_delete_elem删除map条目；
     * BPF verifier不允许delete之后继续引用map value指针；
     */
    __builtin_memcpy(&snapshot, v, sizeof(snapshot));
    bpf_map_delete_elem(&start_map, &key);

    // 如果总开关已经关闭，上下文清理完成，直接返回，不再统计、不上报事件
    if (!c || !c->enable)
        return 0;

    // 获取当前内核时间戳，计算udp_sendmsg内核函数执行耗时（内核态执行时间，ns）
    u64 now = bpf_ktime_get_ns();
    u64 lat = now - snapshot.start_ts;

    /*
     * retval <0：系统调用发送失败（如EAGAIN、ENOBUFS等）；
     * 只统计失败计数，不生成ringbuf明细事件；不统计字节、延迟汇总；
     */
    if (retval < 0) {
        if (st)
            st->failed++;
        return 0;
    }

    /*
     * =========更新per‑cpu统计，这一步必须放在ringbuf分配之前=========
     * 即使ringbuf缓冲区满丢弃明细，汇总统计仍然完整；
     * total_bytes使用retval实际发送字节，而不是用户入参len；
     * tuple_source区分五元组来源统计flow_tuple / fallback_tuple；
     * 更新最大延迟max_ns，同时记录发生最大延迟的pid、tid、comm进程名；
     */
    if (st) {
        st->count++;                                  // UDP成功调用总次数+1
        st->total_ns += lat;                          // 累加总内核耗时ns
        st->total_bytes += (bpf_u64_t)retval;        // 累加实际成功发送字节

        if (snapshot.tuple_source == UDP_TUPLE_FLOW)
            st->flow_tuple++;
        else
            st->fallback_tuple++;

        // 判断是否刷新全局最大延迟记录；保存延迟、pid、tid、进程名字符串
        if (lat > st->max_ns) {
            st->max_ns = lat;
            st->max_pid = snapshot.tgid;
            st->max_tid = snapshot.pid;
            __builtin_memcpy(st->max_comm, snapshot.comm, TASK_COMM_LEN);
        }
    }

    /*
     * 用户配置min_latency_ns>0开启延迟过滤；
     * 本次调用latency小于阈值，不上报明细事件；计入filtered_latency统计；直接返回；
     * 汇总统计已经完成，只是丢弃单包明细；
     */
    if (c->min_latency_ns && lat < c->min_latency_ns) {
        if (st)
            st->filtered_latency++;
        return 0;
    }

    /*
     * ringbuf预分配事件内存；sizeof(*e)事件结构体大小；flags=0；
     * 返回NULL代表ringbuf缓冲区已满；明细事件丢弃；统计ringbuf_dropped；
     */
    struct UdpMonitor_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        if (st)
            st->ringbuf_dropped++;
        return 0;
    }

    // =========填充ringbuf上报事件结构体所有字段=========
    e->ts_ns       = now;                     ///< 事件时间戳：udp_sendmsg返回时刻ns
    e->latency_ns  = lat;                     ///< udp_sendmsg内核函数耗时ns
    e->len         = (bpf_u64_t)retval;       ///< 实际发送成功字节数，来自内核retval
    e->pid         = snapshot.pid;            ///< 线程TID（目标PID namespace）
    e->tgid        = snapshot.tgid;           ///< 进程PID（目标PID namespace）
    e->result      = retval;                  ///< 系统调用返回值（正数成功）
    e->af          = snapshot.af;            ///< 地址族 AF_INET / AF_INET6
    e->sport       = snapshot.sport;          ///< 源端口，主机字节序
    e->dport       = snapshot.dport;          ///< 目的端口，主机字节序
    e->saddr_v4    = snapshot.saddr_v4;       ///< IPv4源地址网络序
    e->daddr_v4    = snapshot.daddr_v4;       ///< IPv4目的地址网络序
    e->tuple_source = snapshot.tuple_source;   ///< 五元组采集来源标记
    __builtin_memset(e->padding, 0, sizeof(e->padding)); ///< padding填充0，消除未初始化内存，安全校验

    /*
     * BPF不允许直接赋值数组类型成员；必须使用__builtin_memcpy拷贝comm、ipv6数组；
     */
    __builtin_memcpy(e->comm, snapshot.comm, TASK_COMM_LEN);
    __builtin_memcpy(e->saddr_v6, snapshot.saddr_v6, 16);
    __builtin_memcpy(e->daddr_v6, snapshot.daddr_v6, 16);

    /*
     * bpf_ringbuf_submit提交预分配事件；flags=0，不拷贝内存，直接把预分配内存交给ringbuf；
     * 用户态libbpf ringbuf回调函数读取该事件；
     */
    bpf_ringbuf_submit(e, 0);

    return 0;
}

/**
* @brief kretprobe钩子：udp_sendmsg IPv4发送返回探针
* SEC("kretprobe/udp_sendmsg")；BPF_KRETPROBE自动解析retval返回值；
* 调用公共结算函数finish_udp_send，传入retval；
*/
SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(ret_udp_sendmsg, int retval)
{
    return finish_udp_send(retval);
}

/**
* @brief kretprobe钩子：udpv6_sendmsg IPv6发送返回探针
* 原实现缺失，IPv6发送没有返回结算逻辑，完全不产生事件；
* BPF_KRETPROBE自动解析retval，复用finish_udp_send公共结算逻辑；
*/
SEC("kretprobe/udpv6_sendmsg")
int BPF_KRETPROBE(ret_udpv6_sendmsg, int retval)
{
    return finish_udp_send(retval);
}
