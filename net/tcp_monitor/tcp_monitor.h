#ifndef __TCP_MONITOR_H
#define __TCP_MONITOR_H

#include "common/types.h"

// 兼容内核地址族宏，防止缺少vmlinux.h时未定义
#ifndef AF_INET
	#define AF_INET  2
#endif
#ifndef AF_INET6
	#define AF_INET6 10
#endif

/* ===================== 事件类型枚举 ===================== */
// 区分环形缓冲区投递的TCP事件类别，用户态根据type做不同解析
#define TCP_EV_HANDSHAKE   0   // TCP三次握手完成事件，统计连接延迟
#define TCP_EV_RETRANSMIT  1   // TCP报文重传事件，记录单条重传触发
#define TCP_EV_CLOSE       2   // TCP连接关闭事件，汇总整条连接总重传次数

/* ===================== BPF程序控制配置结构体 ===================== */
/**
 * @struct TcpMonitor_ctrl
 * @brief 用户态下发给内核BPF的全局控制参数，存储在ctrl_map数组Map
 * @field enable 总开关：true开启TCP监控，false直接丢弃所有事件
 * @field min_latency_ns 握手延迟过滤阈值(纳秒)，握手延迟低于该值不上报事件
 * @field target_pid PID过滤：0=监控全部进程；非0仅监控对应TGID(用户态PID)进程
 */
struct TcpMonitor_ctrl {
	bpf_bool_t enable;
	bpf_u64_t  min_latency_ns;
	bpf_s32_t  target_pid;
	bpf_u64_t  pid_ns_dev;
	bpf_u64_t  pid_ns_ino;
};

/* ===================== 建连临时会话缓存结构体 ===================== */
/**
 * @struct tcp_sess
 * @brief 缓存connect阶段上下文，关联connect入口与握手完成事件
 * @note sess_map 以 struct sock 地址为 key，跨软中断上下文保持连接归属
 */
struct tcp_sess {
	bpf_u64_t start_ts;		// connect调用时刻内核纳秒时间戳，握手完成后计算建连耗时
	bpf_u32_t tgid;
	bpf_u32_t tid;
	bpf_u32_t retrans_cnt;
	bpf_bool_t handshake_reported;
	bpf_u16_t sport, dport;
	bpf_s32_t af;
	bpf_u32_t saddr_v4, daddr_v4;
	bpf_u8_t saddr_v6[16], daddr_v6[16];
	bpf_s8_t comm[TASK_COMM_LEN];
};

/* ===================== 环形缓冲区对外输出事件结构体 ===================== */
/**
 * @struct TcpMonitor_event
 * @brief BPF通过ringbuf推送给用户态的标准事件载体，覆盖握手/重传/关闭三类场景
 * @field type 
 * @field ts_ns 事件触发时刻单调时钟纳秒时间戳
 * @field latency_ns 耗时字段：
 *        握手事件=三次握手总耗时(connect到握手完成)；
 *        关闭事件=连接完整存活时长；
 *        重传事件固定填0，无耗时统计
 */
struct TcpMonitor_event {
	bpf_u32_t type;					// 事件类型，对应TCP_EV_*宏区分事件场景
	bpf_u64_t ts_ns;
	bpf_u64_t latency_ns;
	bpf_u32_t retrans_cnt;			// 连接累计重传总次数：握手时0、重传时当前累计值、关闭时全量汇总值
	bpf_u32_t tgid;
	bpf_u32_t tid;
	bpf_u16_t sport, dport;
	bpf_u32_t saddr_v4, daddr_v4;
	int af;
	bpf_u32_t state;				// TCP内核状态枚举(TCP_SYN_SENT/TCP_ESTABLISHED/TCP_CLOSE等)
	bpf_s8_t  comm[TASK_COMM_LEN];
	bpf_u8_t  saddr_v6[16], daddr_v6[16];
};

/* ===================== 全局汇总统计结构体 ===================== */
/**
 * @struct TcpMonitor_stats
 * @brief 持久化到stats_map，程序退出时用户态读取打印汇总报表
 * @field hs_count 捕获到的TCP握手总次数
 * @field hs_total_ns 所有握手延迟累加总纳秒数，可计算平均握手耗时
 * @field hs_max_ns 单次最大握手延迟纳秒值
 * @field rt_count 全局TCP报文重传总次数
 * @field cl_count 捕获到的TCP连接关闭总次数
 * @field cl_total_ns 所有连接存活时长累加值，用于计算平均连接生命周期
 * @field cl_max_ns 最长存活连接时长
 * @field hs_max_sport 最大握手延迟对应的本地源端口
 * @field hs_max_dport 最大握手延迟对应的远端目标端口
 * @field hs_max_saddr 最大握手延迟连接的IPv4源地址
 * @field hs_max_daddr 最大握手延迟连接的IPv4目标地址
 * @field hs_max_comm 产生最大握手延迟的进程名称
 */
struct TcpMonitor_stats {
	bpf_u64_t connect_attempted;
	bpf_u64_t hs_count, hs_total_ns, hs_max_ns;
	bpf_u64_t rt_count;
	bpf_u64_t cl_count, cl_total_ns, cl_max_ns;
	bpf_u64_t filtered_latency;
	bpf_u64_t ringbuf_dropped;
	bpf_u64_t map_update_failed;
	bpf_u64_t untracked_events;
	bpf_u16_t hs_max_sport, hs_max_dport;
	bpf_s32_t hs_max_af;
	bpf_u32_t hs_max_saddr, hs_max_daddr;
	bpf_u8_t  hs_max_saddr_v6[16], hs_max_daddr_v6[16];
	bpf_s8_t  hs_max_comm[TASK_COMM_LEN];
};

/* ===================== 用户态对外API声明，仅非BPF编译时生效 ===================== */
#ifndef __BPF__
#include <stdbool.h>
/**
 * @brief TCP监控主运行入口函数
 * @param poll_timeout_ms ringbuf用户态阻塞读取超时时间(毫秒)
 * @param enable 是否开启监控总开关
 * @param target_pid 过滤指定进程TGID，0=全量采集
 * @param min_latency_ns 握手延迟过滤阈值，低于阈值不上报握手事件
 * @return int 程序执行退出码
 */
int tcp_monitor_run(int poll_timeout_ms, bool enable,
		    bpf_s32_t target_pid, bpf_u64_t min_latency_ns);
#endif

#endif
