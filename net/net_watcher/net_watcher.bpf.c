#include <vmlinux.h>                // 内核完整结构体定义(sk_buff/sock/tcphdr等)
#include "proto/common.bpf.h"       // 通用工具、全局map、全局开关(protocol_count/udp_info/dns_info)
#include "proto/netfilter.bpf.h"    // netfilter打点存储逻辑 store_nf_time
#include "proto/icmp.bpf.h"         // ICMP报文采集逻辑
#include "proto/tcp.bpf.h"          // TCP全链路采集(__tcp_xxx系列函数)
#include "proto/packet.bpf.h"       // 通用数据包解析、五元组、协议统计sum_protocol
#include "proto/udp.bpf.h"          // UDP/DNS采集
#include "proto/mysql.bpf.h"        // MySQL uprobe处理
#include "proto/redis.bpf.h"        // Redis uprobe处理
#include "proto/drop.bpf.h"         // tracepoint kfree_skb丢包采集


// 服务端被动建立TCP连接：kretprobe 捕获 inet_csk_accept 返回值（新建连接sock）
/**
 * @name inet_csk_accept_exit
 * @brief kretprobe 钩子：内核函数 inet_csk_accept 执行完成后触发
 * @param sk 内核函数返回值，为新建立TCP连接对应的 struct sock*（newsk）
 * @return 返回值透传给BPF内核，无业务含义
 * 场景：服务端调用 accept() 拿到新客户端连接时触发
 * 作用：提取新建连接五元组、端口、sock标识，存入全局map做流量关联
 */
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_exit, struct sock *sk) {
    // 调用tcp层处理函数，完成新建连接信息采集
    return __inet_csk_accept(sk);
}

// ====================== IPv4 客户端主动连接 ======================
// kprobe：进入 tcp_v4_connect 函数时触发（发起连接瞬间）
/**
 * @name tcp_v4_connect
 * @brief kprobe 钩子：客户端发起IPv4 TCP连接，刚进入tcp_v4_connect内核函数
 * @param sk 当前客户端套接字对应的 struct sock*
 * 场景：用户态调用 connect(fd, ipv4地址)，内核进入TCP连接初始化流程
 * 作用：记录连接发起时间、源端口、目标IPv4地址，预存连接上下文
 */
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, const struct sock *sk) {
    return __tcp_v4_connect(sk);
}

// kretprobe：tcp_v4_connect 执行完毕，拿到连接返回结果（成功/失败）
/**
 * @name tcp_v4_connect_exit
 * @brief kretprobe 钩子：IPv4 connect 内核函数执行结束
 * @param ret 内核函数返回值：0=连接初始化成功；负数=连接失败（超时/拒绝/路由不可达等错误码）
 * 作用：上报连接耗时、连接失败错误码，失败则直接清理临时缓存
 */
SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_exit, int ret) {
    return __tcp_v4_connect_exit(ret);
}

// ====================== IPv6 客户端主动连接 ======================
// kprobe：进入 tcp_v6_connect，发起IPv6 TCP连接
/**
 * @name tcp_v6_connect
 * @brief kprobe 钩子：客户端发起IPv6 TCP连接，进入tcp_v6_connect内核函数
 * @param sk 当前客户端套接字 struct sock*
 * 作用：同ipv4 connect入口，提取源端口、目标IPv6地址，记录发起时间戳
 */
SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, const struct sock *sk) {
    return __tcp_v6_connect(sk);
}

// kretprobe：tcp_v6_connect 执行完成，获取连接结果
/**
 * @name tcp_v6_connect_exit
 * @brief kretprobe 钩子：IPv6 connect 流程结束
 * @param ret 返回码：0成功，负值为连接失败错误码
 * 作用：上报IPv6连接耗时、失败原因，维护连接上下文map
 */
SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(tcp_v6_connect_exit, int ret) {
    return __tcp_v6_connect_exit(ret);
}

// ===================== TCP连接状态变更 & 关闭清理 =====================
// erase CLOSED TCP connection：监控TCP状态切换，连接关闭时清理缓存
/**
 * @name tcp_set_state
 * @brief kprobe 钩子：内核修改TCP套接字状态时统一触发
 * @param sk 待修改状态的TCP套接字 struct sock*
 * @param state 新的TCP状态枚举（TCP_ESTABLISHED / TCP_FIN_WAIT / TCP_CLOSED 等）
 * 核心逻辑（在__tcp_set_state中）：
 * 1. 捕获状态切换事件，记录状态流转时序
 * 2. 当 state == TCP_CLOSED 时，删除全局map中该sock对应的五元组、时延缓存、重传统计等数据
 * 3. 防止map内存持续泄漏
 */
SEC("kprobe/tcp_set_state")
int BPF_KPROBE(tcp_set_state, struct sock *sk, int state) {
    return __tcp_set_state(sk, state);
}

/*!
in_ipv4:    // IPv4 TCP 报文内核收包完整路径（网卡→L2→IP→TCP→用户态）
    kprobe/eth_type_trans        // L2层：以太网报文刚进入内核，解析以太网头、区分IP协议
    kprobe/ip_rcv_core.isra.0    // L3 IPv4层：IPv4报文开始处理（注释带.isra.0 说明该函数常被编译器内联，符号带后缀）
    kprobe/tcp_v4_rcv            // L4 TCP层：TCPv4报文进入TCP协议栈处理入口
    kprobe/tcp_v4_do_rcv         // TCP层：skb和对应sock套接字绑定，能拿到完整连接五元组
    kprobe/skb_copy_datagram_iter// 用户态拷贝：内核把skb数据拷贝到应用程序缓冲区（recv/read系统调用底层）


in_ipv6:    //  IPv6 TCP 收包路径，逻辑和 v4 完全对称
    kprobe/eth_type_trans        // 共用L2入口，IPv4/IPv6共用这个打点
    kprobe/ip6_rcv_core.isra.0   // L3 IPv6报文处理入口，同样存在内联符号后缀风险
    kprobe/tcp_v6_rcv            // IPv6 TCP报文入口
    kprobe/tcp_v6_do_rcv         // 绑定ipv6连接对应的sock
    kprobe/skb_copy_datagram_iter// 共用用户态拷贝打点


out_ipv4:   // IPv4 TCP 发包路径（用户态→TCP→IPv4→网卡队列→硬件发送）
    kprobe/tcp_sendmsg           // L4 TCP层起点：应用调用send/write，数据进入TCP协议栈
    kprobe/ip_queue_xmit         // L3 IPv4层：TCP报文封装IPv4头部，送入IP发送逻辑
    kprobe/dev_queue_xmit        // 网卡软队列：报文交给设备发送队列排队
    kprobe/dev_hard_start_xmit   // L2硬件发送：报文下推给网卡驱动，准备发往物理链路


out_ipv6:   // IPv6 TCP 发包路径，仅 IP 层函数不同
    kprobe/tcp_sendmsg           // IPv4/IPv6 TCP发送共用同一入口
    kprobe/inet6_csk_xmit        // L3 IPv6专属发送函数，替代v4的ip_queue_xmit
    kprobe/dev_queue_xmit        // 共用网卡队列打点
    kprobe/dev_hard_start_xmit   // 共用硬件发送打点


*/

/*************** receive path *************************/

// 【L2 以太网层入口】IPv4/IPv6收包共用钩子：网卡报文刚进入内核协议栈
/** in ipv4 && ipv6 */ 
/**
 * @brief 内核函数 eth_type_trans 进入时触发
 * @param skb 当前收到的以太网数据包缓冲区
 * 核心能力：
 * 1. 解析以太网头，区分报文是IPv4/IPv6/ARP等上层协议
 * 2. 全局开关 protocol_count 控制协议流量统计：
 *    - protocol_count=true：执行 sum_protocol(skb, false)，false代表「收包」，统计各协议入站流量字节数、包量
 *    - protocol_count=false：只执行基础报文打点逻辑 __eth_type_trans(skb)
 * 时序位置：整条收包链路第一个埋点，记录报文进入内核的初始时间戳
 */
SEC("kprobe/eth_type_trans")
int BPF_KPROBE(eth_type_trans, struct sk_buff *skb) {
    if (protocol_count) {
        return sum_protocol(skb, false); // false = receive 入站流量统计
    } else {
        return __eth_type_trans(skb);
    }
}

// 【L3 IPv4 层处理入口】仅IPv4报文会走到该函数
/** in only ipv4 */ 
/**
 * @brief ip_rcv_core 是IPv4报文正式进入IP层处理的起点
 * @param skb IPv4数据包缓冲区
 * 作用：记录报文进入IPv4层的时间戳，存入skb临时上下文，用于后续计算L2→L3处理耗时
 */
SEC("kprobe/ip_rcv_core")
int BPF_KPROBE(ip_rcv_core, struct sk_buff *skb) { 
    return __ip_rcv_core(skb); 
}

// 【L3 IPv6 层处理入口】仅IPv6报文会走到该函数
/** in only ipv6 */
/**
 * @brief ip6_rcv_core 是IPv6报文正式进入IP层处理的起点
 * @param skb IPv6数据包缓冲区
 * 作用：与ip_rcv_core对称，记录IPv6报文进入IP层时间戳
 */
SEC("kprobe/ip6_rcv_core")
int BPF_KPROBE(ip6_rcv_core, struct sk_buff *skb) {
    return __ip6_rcv_core(skb);
}

// 【L4 TCPv4 接收入口】只有IPv4+TCP报文进入此函数
/**in only ipv4 */       
/**
 * @brief TCPv4报文剥离IP头后，进入TCP协议栈处理的第一个函数
 * @param skb 携带完整TCP头的IPv4报文
 * 作用：记录报文抵达TCP层时间戳，解析TCP基础头（源端口、目的端口、标志位SYN/ACK/FIN/RST等）
 */
SEC("kprobe/tcp_v4_rcv") 
int BPF_KPROBE(tcp_v4_rcv, struct sk_buff *skb) { 
    return __tcp_v4_rcv(skb); 
}

// 【L4 TCPv6 接收入口】只有IPv6+TCP报文进入此函数
/** in only ipv6 */
/**
 * @brief TCPv6报文剥离IPv6头后，进入TCP协议栈处理的第一个函数
 * @param skb 携带完整TCP头的IPv6报文
 * 作用：与tcp_v4_rcv对称，解析IPv6 TCP五元组、记录TCP层起始时间戳
 */
SEC("kprobe/tcp_v6_rcv") 
int BPF_KPROBE(tcp_v6_rcv, struct sk_buff *skb) { 
    return __tcp_v6_rcv(skb); 
}

// 【TCP层绑定socket钩子 v4】skb与对应TCP套接字关联，拿到完整连接信息
/**
 * @brief IPv4 TCP报文匹配到对应socket后触发
 * @param sk 当前TCP连接对应的套接字对象 struct sock
 * @param skb 当前待处理TCP报文缓冲区
 * 关键价值：
 * 前面探针只有skb，无法关联进程/连接全量信息；此处同时拿到sk+skb，
 * 可以提取完整五元组、进程PID、连接状态、RTT等连接维度指标，存入全局BPF Map做链路关联
 */
SEC("kprobe/tcp_v4_do_rcv")
int BPF_KPROBE(tcp_v4_do_rcv, struct sock *sk, struct sk_buff *skb) {
    return __tcp_v4_do_rcv(sk, skb);
}

// 【TCP层绑定socket钩子 v6】逻辑与v4完全对称 
/**
 * @brief IPv6 TCP报文匹配到对应socket后触发
 * @param sk IPv6 TCP连接套接字
 * @param skb 当前TCP报文
 * 作用：提取IPv6连接完整上下文，建立skb与socket的映射关系
 */
SEC("kprobe/tcp_v6_do_rcv")
int BPF_KPROBE(tcp_v6_do_rcv, struct sock *sk, struct sk_buff *skb) {
    return __tcp_v6_do_rcv(sk, skb);
}

// 【内核→用户态数据拷贝埋点】IPv4/IPv6 TCP共用，recv/read系统调用底层
/** in ipv4 && ipv6 */
/**
 * @brief 内核将skb中的TCP载荷拷贝到用户进程缓冲区时触发
 * @param skb 待拷贝的数据包
 * 业务意义：
 * 前面所有埋点都是内核协议栈内部处理耗时；本埋点代表「应用真正读到数据」的时刻，
 * 可计算指标：TCP层处理完成到用户读取的延迟（应用层等待时延）
 */
SEC("kprobe/skb_copy_datagram_iter") 
int BPF_KPROBE(skb_copy_datagram_iter, struct sk_buff *skb) {
    return __skb_copy_datagram_iter(skb);
}

// ===================== 收包异常错误捕获探针 =====================
// receive error packet
/* TCP invalid seq error 非法TCP序列号错误 */ 
/**
 * @brief 内核校验TCP报文序列号不合法时进入该函数
 * @param sk 当前TCP连接socket
 * @param skb 序列号异常的报文
 * 逻辑：在 __tcp_validate_incoming 中提取五元组、错误类型、报文偏移，
 * 将异常事件推送至RingBuffer，用于监控乱序、伪造报文、攻击流量
 */
SEC("kprobe/tcp_validate_incoming")
int BPF_KPROBE(tcp_validate_incoming, struct sock *sk, struct sk_buff *skb) {
    return __tcp_validate_incoming(sk, skb);
}

/* TCP invalid checksum error TCP校验和错误 */
/**
 * @brief kretprobe：报文校验和校验函数执行完成后触发，通过返回值判断是否校验失败
 * @param ret 函数返回值：ret != 0 代表TCP/IP校验和错误，报文会被内核丢弃
 * 逻辑：skb_checksum_complete(ret) 判断返回码，校验失败则上报校验和异常事件
 */
SEC("kretprobe/__skb_checksum_complete")
int BPF_KRETPROBE(__skb_checksum_complete_exit, int ret) {
    return skb_checksum_complete(ret);
}


/**** send path ****/
 /**
  * @brief 应用层发送数据入口，v4/v6 TCP发包共用钩子
  * @param sk 当前发送数据的TCP套接字 struct sock*
  * @param msg 用户态传入的发送缓冲区、地址、控制信息结构体
  * @param size 本次要发送的数据长度
  * 触发时机：用户调用 send / write / sendmsg 系统调用，内核进入TCP发送逻辑
  * 作用：
  * 1. 记录发包整条链路的**起始时间戳**；
  * 2. 提取连接五元组、进程PID、本次发送数据长度；
  * 3. 将上下文存入BPF map，供后续IP/链路层探针匹配同一条skb计算分层时延。
  */
SEC("kprobe/tcp_sendmsg")
 int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
     return __tcp_sendmsg(sk, msg, size);
 }
 
 /*!
    * \brief: 获取数据包进入IP层时刻的时间戳
    * tips:   此时ip数据段还没有数据，不能用 get_pkt_tuple(&pkt_tuple, ip, tcp)获取ip段的数据
    *         out only ipv4
  * @brief IPv4专属IP层发送钩子，TCP报文准备封装IPv4头、下发IP协议栈
  * @param sk 发包对应的TCP套接字
  * @param skb 待发送数据包缓冲区
  * 关键提示：此时skb还未填充完整IP头部，无法直接解析IP五元组，只能依靠前面tcp_sendmsg存入map的连接上下文做关联
  * 作用：记录报文进入IPv4层的时间戳，用于计算「TCP层处理耗时」（ip层时间 - tcp_sendmsg时间）
  */
SEC("kprobe/ip_queue_xmit")
 int BPF_KPROBE(ip_queue_xmit, struct sock *sk, struct sk_buff *skb) {
     return __ip_queue_xmit(sk, skb);
 };
 
 /*!
 * \brief: 获取数据包进入IP层时刻的时间戳
 * tips:   此时ip数据段还没有数据，不能用 get_pkt_tuple(&pkt_tuple, ip, tcp)获取ip段的数据
 *         out only ipv6
 */
 /**
  * @brief IPv6专属IP层发送钩子，和ip_queue_xmit完全对称
  * @param sk IPv6 TCP套接字
  * @param skb 待发送报文
  * 限制：同样未填充完整IPv6头部，不能直接解析IP头信息，依赖上层TCP上下文匹配
  * 作用：记录报文进入IPv6层时间戳，区分v4/v6发包分层时延
  */
SEC("kprobe/inet6_csk_xmit")
 int BPF_KPROBE(inet6_csk_xmit, struct sock *sk, struct sk_buff *skb) {
     return __inet6_csk_xmit(sk, skb);
 };
 
 /*!
 * \brief: 获取数据包进入数据链路层时刻的时间戳
     out ipv4 && ipv6
 */
 /**
  * @brief IP处理完成，报文送入网卡发送软队列（L2链路层起点），v4/v6共用
  * @param skb 完整封装IP+TCP+以太网头的待发送报文
  * 作用：记录报文进入网卡队列的时间戳，用于计算「IP层处理耗时」「网卡队列排队延迟」
  */
  SEC("kprobe/__dev_queue_xmit")
 int BPF_KPROBE(__dev_queue_xmit, struct sk_buff *skb) {
     return dev_queue_xmit(skb);
 };
 
 /*!
 * \brief: 获取数据包发送时刻的时间戳
     out ipv4 && ipv6
 */
 /**
  * @brief 报文离开内核软队列，下发网卡硬件驱动准备物理发送，整条发包链路最后一个埋点
  * @param skb 即将交给硬件发送的完整报文
  * 分支逻辑由全局开关 protocol_count 控制：
  * 1. protocol_count = true：执行sum_protocol(skb, true)，true代表「发送方向」，统计出站各协议包量、字节总量；
  * 2. protocol_count = false：仅执行基础打点逻辑 __dev_hard_start_xmit(skb)。
  * 作用：记录报文硬件下发时间戳，可算出网卡排队耗时（硬件下发时间 - 入队列时间），同时做全量协议流量统计。
  */
 SEC("kprobe/dev_hard_start_xmit")
 int BPF_KPROBE(dev_hard_start_xmit, struct sk_buff *skb) {
     if (protocol_count) {
         return sum_protocol(skb, true); // true = send 出站流量统计
     } else {
         return __dev_hard_start_xmit(skb);
     }
 };
 

// retrans 模块：TCP重传/拥塞状态监控探针
/* 在进入快速恢复阶段时，不管是基于Reno或者SACK的快速恢复，
 * 还是RACK触发的快速恢复，都将使用函数tcp_enter_recovery进入
 * TCP_CA_Recovery拥塞阶段。
 */
 /**
  * @brief kprobe钩子：内核进入TCP快速恢复拥塞状态时触发
  * @param sk 发生拥塞恢复的TCP连接套接字struct sock*
  * 触发场景：
  * 收到3个重复ACK、RACK检测到报文丢失，内核判定出现局部丢包，进入快速恢复流程
  * 拥塞状态标记：TCP_CA_Recovery
  * 业务作用：
  * 1. 采集该连接五元组、进入恢复状态的时间戳；
  * 2. 上报「快速恢复」事件，代表轻微丢包，触发局部重传，无需等待重传定时器超时；
  * 3. 统计连接恢复次数，衡量链路轻微抖动、偶发丢包指标。
  */
SEC("kprobe/tcp_enter_recovery")
int BPF_KPROBE(tcp_enter_recovery, struct sock *sk) {
    return __tcp_enter_recovery(sk);
}
 
/* Enter Loss state. If we detect SACK reneging, forget all SACK information
* and reset tags completely, otherwise preserve SACKs. If receiver
* dropped its ofo queue, we will know this due to reneging detection.
* 在报文的重传定时器到期时，在tcp_retransmit_timer函数中，进入TCP_CA_Loss拥塞状态。
*/

/**
* @brief kprobe钩子：TCP进入完全丢失Loss拥塞状态时触发
* @param sk 进入Loss状态的TCP套接字
* 触发场景：
* 重传定时器超时仍未收到ACK，内核判定报文彻底丢失，进入Loss阶段；
* 也会在SACK失信、接收方丢弃乱序队列时触发。
* 拥塞状态标记：TCP_CA_Loss
* 业务作用：
* 1. 上报严重丢包事件，代表链路故障、网络拥堵、断流等严重问题；
* 2. Loss下拥塞窗口会大幅收缩，触发全量报文重传，时延陡增；
* 3. 统计Loss事件次数，作为核心网络故障告警指标。
*/
SEC("kprobe/tcp_enter_loss")
int BPF_KPROBE(tcp_enter_loss, struct sock *sk) { 
    return __tcp_enter_loss(sk); 
}
 
///////////////////////
/* udp 模块探针：监控UDP收包、入队、发包、IP层发送流程，区分通用UDP与DNS流量采集 */
/**
 * @brief UDP报文接收入口钩子，内核收到UDP报文时触发
 * @param skb 接收的UDP数据包缓冲区
 * 分支逻辑由全局开关控制，按需采集避免性能损耗：
 * 1. udp_info = true：采集通用UDP流量，调用__udp_rcv解析UDP头、五元组、载荷长度
 * 2. dns_info = true：识别DNS报文，调用__dns_rcv解析域名、查询类型、应答结果
 * 3. 两个开关都关闭：直接return 0，不做任何采集逻辑
 */
 SEC("kprobe/udp_rcv")
 int BPF_KPROBE(udp_rcv, struct sk_buff *skb) {
     if (udp_info)
         return __udp_rcv(skb);
     else if (dns_info)
         return __dns_rcv(skb);
     else
         return 0;
 }
 
 /**
  * @brief UDP报文送入socket接收队列时触发
  * @param sk UDP套接字对象，可获取连接/进程信息
  * @param skb 待入队UDP报文
  * 场景：内核处理完UDP报文，准备交付给用户进程前入接收队列
  * 作用：记录UDP报文从内核处理完成到用户可读的时延，关联skb与socket上下文
  */
 SEC("kprobe/__udp_enqueue_schedule_skb")
 int BPF_KPROBE(__udp_enqueue_schedule_skb, struct sock *sk, struct sk_buff *skb) {
     return udp_enqueue_schedule_skb(sk, skb);
 }
 
 /**
  * @brief UDP报文发送核心钩子，应用发送UDP数据进入内核UDP层
  * @param skb 待发送UDP数据包
  * 开关分支与udp_rcv对称：
  * udp_info开启：采集普通UDP出站流量；
  * dns_info开启：采集DNS请求/应答发送报文；
  * 开关关闭则跳过采集。
  */
 SEC("kprobe/udp_send_skb")
 int BPF_KPROBE(udp_send_skb, struct sk_buff *skb) {
     if (udp_info)
         return __udp_send_skb(skb);
     else if (dns_info)
         return __dns_send(skb);
     else
         return 0;
 }
 
 /**
  * @brief UDP报文下发IPv4层发送时打点
  * @param net 网络命名空间指针
  * @param skb 封装完成UDP头、待下发IP层的报文
  * 作用：记录UDP报文进入IP协议栈的时间戳，用于计算UDP层到IP层的处理耗时
  */
 SEC("kprobe/ip_send_skb")
 int BPF_KPROBE(ip_send_skb, struct net *net, struct sk_buff *skb) {
     return __ip_send_skb(skb);
 }
 

// netfilter 防火墙链路打点探针，采集报文经过iptables各钩子的分层时延
/**
* @brief ip_rcv：IPv4报文IP层入口，执行 NF_INET_PRE_ROUTING(PREROUTING) 钩子前触发
* @param skb 接收报文缓冲区
* @param dev 收包网卡设备
* @param pt 数据包类型结构体
* @param orig_dev 原始接收设备
* 枚举标记 e_ip_rcv 对应 PRE_ROUTING 阶段
* 作用：记录报文刚进入IP层、即将执行预路由防火墙规则的时间戳
*/
SEC("kprobe/ip_rcv")
int BPF_KPROBE(ip_rcv, struct sk_buff *skb, struct net_device *dev,
            struct packet_type *pt, struct net_device *orig_dev) {
    return store_nf_time(skb, e_ip_rcv);
}
 
/**
* @brief ip_local_deliver：路由判定报文发给本机，即将执行 NF_INET_LOCAL_IN(INPUT) 钩子
* @param skb 本机接收报文
* 枚举 e_ip_local_deliver 对应 INPUT 链阶段
* 作用：记录进入本机入站防火墙规则前的时间戳，可算出PREROUTING到INPUT之间路由耗时
*/
SEC("kprobe/ip_local_deliver")
int BPF_KPROBE(ip_local_deliver, struct sk_buff *skb) {
    return store_nf_time(skb, e_ip_local_deliver);
}

/**
* @brief ip_local_deliver_finish：INPUT防火墙规则执行完成，准备上送传输层(TCP/UDP)
* @param net 网络命名空间
* @param sk 对应本机socket（报文最终交付的套接字）
* @param skb 报文缓冲区
* 枚举 e_ip_local_deliver_finish：INPUT链处理结束节点
* 作用：标记防火墙INPUT规则处理完成，计算INPUT链纯规则耗时
*/
SEC("kprobe/ip_local_deliver_finish")
int BPF_KPROBE(ip_local_deliver_finish, struct net *net, struct sock *sk,
            struct sk_buff *skb) {
    return store_nf_time(skb, e_ip_local_deliver_finish);
}
 
/**
* @brief ip_local_out：本地应用发送报文，刚进入IP层，执行 NF_INET_LOCAL_OUT(OUTPUT) 出站钩子
* @param net 网络命名空间
* @param sk 发送端socket
* @param skb 待发送报文
* 枚举 e_ip_local_out 对应 OUTPUT 链起点
* 作用：记录本地发包即将执行OUTPUT防火墙规则的起始时间
*/
SEC("kprobe/ip_local_out")
int BPF_KPROBE(ip_local_out, struct net *net, struct sock *sk,
            struct sk_buff *skb) {
    return store_nf_time(skb, e_ip_local_out);
}
 
/**
* @brief ip_output：OUTPUT规则执行完毕，路由完成，准备执行 NF_INET_POST_ROUTING 钩子
* @param net 网络命名空间
* @param sk 发送套接字
* @param skb 待发送报文
* 枚举 e_ip_output：POSTROUTING链起点
* 作用：区分OUTPUT规则耗时与POSTROUTING(SNAT/MASQUERADE)处理耗时
*/
SEC("kprobe/ip_output")
int BPF_KPROBE(ip_output, struct net *net, struct sock *sk,
            struct sk_buff *skb) {
    return store_nf_time(skb, e_ip_output);
}
 
/**
* @brief __ip_finish_output：POSTROUTING防火墙规则执行完成，报文下发链路层
* @param net 网络命名空间
* @param sk 发送套接字
* @param skb 待发送完整报文
* 枚举 e_ip_finish_output：POSTROUTING链结束节点
* 作用：计算POSTROUTING NAT/过滤规则总耗时
*/
SEC("kprobe/__ip_finish_output")
int BPF_KPROBE(__ip_finish_output, struct net *net, struct sock *sk,
            struct sk_buff *skb) {
    return store_nf_time(skb, e_ip_finish_output);
}
 
/**
* @brief ip_forward：路由判定报文需要跨网卡转发，执行 NF_INET_FORWARD 转发钩子
* @param skb 转发报文缓冲区
* 枚举 e_ip_forward 对应 FORWARD 转发链
* 作用：采集跨主机转发报文经过FORWARD防火墙规则的时延，用于网关/路由器观测
*/
SEC("kprobe/ip_forward")
int BPF_KPROBE(ip_forward, struct sk_buff *skb) {
    return store_nf_time(skb, e_ip_forward);
}
 

// drop 丢包捕获 + ICMP报文全生命周期监控探针
/**
* @brief tracepoint静态探针：skb被内核释放时触发，统一捕获所有报文丢弃事件
* @param ctx tracepoint原生上下文结构体，内置skb指针、丢包原因枚举、协议等信息
* 优势：tracepoint相比kprobe稳定，内核ABI不会随意变动；所有skb销毁都会走到该点
* 业务逻辑下沉 __tp_kfree：
* 1. 判断skb是正常读完释放还是内核各层主动丢弃；
* 2. 提取五元组、网卡、丢弃栈/丢弃原因；
* 3. 将丢包事件推送至RingBuffer，做丢包统计、告警
*/
SEC("tp/skb/kfree_skb")
int tp_kfree(struct trace_event_raw_kfree_skb *ctx) { 
    return __tp_kfree(ctx); 
}
 
/**
* @brief kprobe：内核收到ICMP报文进入icmp_rcv处理函数
* @param skb ICMP数据包缓冲区
* 场景：ping响应、端口不可达、超时、路由不可达等各类ICMP差错/通知报文入站
* 作用：记录ICMP报文进入ICMP协议栈的时间戳，采集ICMP类型、代码、五元组
*/
SEC("kprobe/icmp_rcv")
int BPF_KPROBE(icmp_rcv, struct sk_buff *skb) { 
    return __icmp_time(skb); 
}
 
/**
* @brief kprobe：ICMP报文校验解析完成，准备送入对应socket接收队列
* @param sk 匹配到的目标套接字
* @param skb 当前ICMP报文
* 作用：标记ICMP报文内核处理完毕、即将暴露给用户进程的时间点，计算ICMP内核处理总耗时
*/
SEC("kprobe/__sock_queue_rcv_skb")
int BPF_KPROBE(__sock_queue_rcv_skb, struct sock *sk, struct sk_buff *skb) {
    return __rcvend_icmp_time(skb);
}
 
/**
* @brief kprobe：内核主动构造ICMP应答报文（例如ping回复、ICMP差错返回）
* @param icmp_param ICMP报文构造参数结构体（类型、代码、载荷信息）
* @param skb 新生成的ICMP回复报文缓冲区
* 场景：本机ping别人、本机回送端口不可达/TTL超时等差错包
* 作用：记录ICMP应答报文生成时间，监控ICMP出站流量与差错报文输出频率
*/
SEC("kprobe/icmp_reply")
int BPF_KPROBE(icmp_reply, struct icmp_bxm *icmp_param, struct sk_buff *skb) {
    return __reply_icmp_time(skb);
}
 

// mysql 模块：用户态探针采集MySQL SQL执行耗时、SQL语句、执行结果
/**
* 符号说明：_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command 是C++函数demangle前的mangled符号
* demangle后原型：void dispatch_command(THD*, COM_DATA*, enum_server_command)
* 该函数是MySQL服务端处理每条客户端SQL命令的统一入口
*/

/**
* @brief uprobe 用户态探针：进入MySQL dispatch_command函数，SQL执行开始
* @ctx uprobe内置上下文，可读取用户态函数入参、寄存器、栈内存
* 作用：
* 1. 捕获SQL执行起始时间戳；
* 2. 从THD、COM_DATA参数中解析SQL语句、操作类型(SELECT/INSERT/UPDATE等)、库名；
* 3. 保存本次查询上下文到BPF map，等待uretprobe读取结束耗时；
*/
SEC("uprobe/_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command")
int BPF_KPROBE(query__start) { 
    return __handle_mysql_start(ctx); 
}
 
/**
* @brief uretprobe 用户态返回探针：dispatch_command执行完毕，SQL执行结束
* @ctx uretprobe上下文，可获取函数返回值、执行耗时
* 作用：
* 1. 读取当前时间戳，计算SQL总执行耗时(结束时间 - uprobe记录的起始时间)；
* 2. 读取函数返回状态，判断SQL执行成功/失败；
* 3. 从map取出之前缓存的SQL、库名、线程ID、客户端IP端口；
* 4. 组装完整SQL慢查询事件，推送至RingBuffer上报用户态采集程序；
* 5. 清理本次查询临时缓存，释放map空间；
*/
SEC("uretprobe/_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command")
int BPF_KPROBE(query__end) { 
    return __handle_mysql_end(ctx); 
}
 

// Redis 用户态探针：采集 Redis 命令执行耗时、读写 Key、返回 Value 观测
/**
* @brief uprobe：进入 Redis 核心命令处理函数 processCommand
* ctx：uprobe 内置上下文，可读取函数入参、栈、寄存器数据
* 作用：
* 1. 记录 Redis 单条命令执行起始时间戳；
* 2. 解析当前执行的命令名（GET/SET/HGETALL 等）、客户端连接信息；
* 3. 将当前线程TID、命令上下文存入BPF Map，等待uretprobe匹配收尾计算耗时；
*/
SEC("uprobe/processCommand")
int BPF_KPROBE(redis_processCommand) { 
    return __handle_redis_start(ctx); 
}

/**
* @brief uretprobe：Redis 命令执行完成退出钩子，挂载在 call 函数返回点
* 作用：
* 1. 获取当前时间，减去 processCommand 保存的起始时间，算出单条Redis命令总耗时；
* 2. 读取命令执行返回状态，区分成功/失败；
* 3. 从Map取出缓存的命令信息，组装Redis命令耗时事件推送RingBuffer；
* 4. 清理当前线程临时缓存，释放BPF Map内存；
*/
SEC("uretprobe/call")
int BPF_KPROBE(redis_call) { 
    return __handle_redis_end(ctx); 
}

/**
* @brief uprobe：Redis 读取Key时触发，挂载 lookupKey 函数
* 作用：
* 1. 捕获所有读操作的目标缓存Key；
* 2. 记录热Key访问次数、超大Key读取事件；
* 3. 关联当前命令上下文，上报高频Key、热点Key监控；
*/
SEC("uprobe/lookupKey")
int BPF_UPROBE(redis_lookupKey) {
    return __handle_redis_key(ctx);
}

/**
* @brief uprobe：Redis 准备回复客户端数据时触发，挂载 addReply 函数
* 作用：
* 1. 捕获返回给客户端的Value数据长度；
* 2. 识别超大Value返回场景，定位大Key拖慢响应的问题；
* 3. 统计出入站数据量，监控Redis流量；
*/
SEC("uprobe/addReply")
int BPF_UPROBE(redis_addReply) {
    return __handle_redis_value(ctx);
}
 

// ====================== 模块1：RTT 往返时延采集 ======================
// rtt 模块：采集TCP稳定连接的RTT、RTT波动，衡量链路往返延迟
/**
* @brief kprobe钩子：TCP处于ESTABLISHED稳定连接时，收到对端ACK报文触发
* @param sk 当前TCP连接套接字struct sock*
* @param skb 携带ACK确认标识的数据包
* 触发时机：三次握手完成后，正常业务传输阶段收到有效ACK
* 底层 __tcp_rcv_established 核心逻辑：
* 1. 读取内核tcp_sock中已计算好的srtt、rttvar（平滑RTT、RTT抖动）；
* 2. 提取连接五元组，将实时RTT指标存入BPF Map或上报RingBuffer；
* 3. 统计单连接RTT均值、P95/P99延迟，识别链路抖动、跨机房高延迟。
*/
SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(tcp_rcv_established, struct sock *sk, struct sk_buff *skb) {
return __tcp_rcv_established(sk, skb);
}

// ====================== 模块2：TCP全连接状态流转监控 ======================
// tcpstate 模块：静态稳定tracepoint，捕获所有socket状态变更
/**
* @brief tracepoint 静态埋点，内核修改TCP套接字状态时统一触发
* @param ctx tracepoint原生上下文，内置旧状态、新状态、源/目的IP端口、PID、sk指针
* 优势：相比 kprobe(tcp_set_state)，ABI稳定，内核升级不会失效；完整记录状态跃迁过程
* 底层 __handle_set_state 功能：
* 1. 记录状态切换事件（SYN_SENT → ESTABLISHED → FIN_WAIT → TIME_WAIT → CLOSED）；
* 2. 统计短连接、长连接生命周期时长；
* 3. 连接进入CLOSED时清理BPF Map内该连接缓存，防止内存泄漏；
* 4. 上报异常状态滞留：如大量TIME_WAIT堆积、SYN_SENT阻塞。
*/
SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
return __handle_set_state(ctx);
}

// ====================== 模块3：TCP RST 重置报文监控（连接异常断开） ======================
// RST 模块：捕获主动发RST、收到对端RST两类连接强断异常
/**
 * @brief tracepoint/tcp/tcp_send_reset：本机主动向外发送RST报文
 * @param ctx tracepoint上下文，携带RST报文五元组、sk、发送原因
 * 场景：程序调用close暴力关闭、端口未监听、防火墙拒绝、内核主动销毁连接；
 * 作用：上报「本机主动重置连接」异常事件，统计主动断连次数。
 */
SEC("tracepoint/tcp/tcp_send_reset")
int handle_send_reset(struct trace_event_raw_tcp_send_reset *ctx) {
    return __handle_send_reset(ctx);
}

/**
 * @brief tracepoint/tcp/tcp_receive_reset：收到对端发来的RST报文
 * @param ctx tracepoint上下文，携带远端地址、当前socket状态
 * 场景：对端进程崩溃、服务端口关闭、中间设备丢弃会话、防火墙拦截；
 * 作用：上报「远端强制断开连接」故障，定位服务侧下线/网络拦截问题。
 */
SEC("tracepoint/tcp/tcp_receive_reset")
int handle_receive_reset(struct trace_event_raw_tcp_receive_reset *ctx) {
    return __handle_receive_reset(ctx);
}
