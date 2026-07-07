#ifndef __UDP_MONITOR_H
#define __UDP_MONITOR_H

#include "common/types.h"

// 兼容vmlinux缺失场景，手动定义IPv4/IPv6地址族宏
#ifndef AF_INET
	#define AF_INET  2
#endif
#ifndef AF_INET6
	#define AF_INET6 10
#endif

/**
 * @struct UdpMonitor_ctrl
 * @brief UDP监控全局控制配置结构体，存储在ctrl_map数组Map
 * @field enable 监控总开关：true开启采集，false丢弃所有UDP发包事件
 * @field min_latency_ns 延迟过滤阈值(纳秒)，单次sendmsg耗时低于该值不上报事件
 * @field target_pid PID过滤：0=监控全部进程；非0仅采集对应TGID(用户态PID)进程
 */
struct UdpMonitor_ctrl {
	bpf_bool_t enable;
	bpf_u64_t  min_latency_ns;
	bpf_s32_t  target_pid;
};

/**
 * @struct UdpMonitor_event
 * @brief BPF通过ringbuf推送给用户态的UDP发包事件结构体
 * @field ts_ns 内核单调时钟纳秒时间戳，sendmsg返回时的时间
 * @field latency_ns 单次udp_sendmsg系统调用耗时(纳秒)，入口到返回的完整耗时
 * @field len 本次UDP发送报文载荷字节长度
 * @field af 地址族标识：AF_INET=IPv4 / AF_INET6=IPv6
 * @field comm 发起UDP发送的进程名称，固定TASK_COMM_LEN长度
 */
struct UdpMonitor_event {
	bpf_u64_t ts_ns, latency_ns;
	bpf_u64_t len;             // 发送字节数
	bpf_s32_t pid;
	bpf_u32_t tgid;
	bpf_u16_t sport, dport;
	bpf_u32_t saddr_v4, daddr_v4;
	int af;
	bpf_s8_t  comm[TASK_COMM_LEN];
	bpf_u8_t  saddr_v6[16], daddr_v6[16];
};

/**
 * @struct UdpMonitor_stats
 * @brief 全局UDP发包汇总统计，存储在stats_map，程序退出用户态读取打印
 * @field count 捕获到的UDP发送总次数
 * @field total_ns 所有sendmsg调用延迟累加总纳秒，可计算平均调用耗时
 * @field max_ns 单次sendmsg最大耗时纳秒值
 * @field total_bytes 累计发送UDP报文总字节数
 * @field max_pid 产生最大延迟的线程LWP ID
 * @field max_comm 产生最大延迟的进程名称
 */
struct UdpMonitor_stats {
	bpf_u64_t count, total_ns, max_ns, total_bytes;
	bpf_u32_t max_pid;
	bpf_s8_t  max_comm[TASK_COMM_LEN];
};

/* 用户态对外运行API，仅非BPF编译环境生效 */
#ifndef __BPF__
#include <stdbool.h>
/**
 * @brief UDP监控主入口函数
 * @param poll_timeout_ms ringbuf用户态阻塞读取超时毫秒
 * @param enable 是否开启监控总开关
 * @param target_pid 过滤指定进程TGID，0代表全量采集
 * @param min_latency_ns 延迟过滤阈值，低于该耗时不推送事件
 * @return int 程序执行退出码，0正常，非0为错误
 */
int udp_monitor_run(int poll_timeout_ms, bool enable,
		    bpf_s32_t target_pid, bpf_u64_t min_latency_ns);
#endif

#endif
