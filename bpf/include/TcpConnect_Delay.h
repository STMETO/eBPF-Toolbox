// 头文件保护宏，防止重复包含
#ifndef __TCP_CONNECT_DELAY_H
#define __TCP_CONNECT_DELAY_H

// 引入公共类型定义头文件
#include "common.h"

#define AF_INET    2    // IPv4 地址协议簇常量
#define AF_INET6   10   // IPv6 地址协议簇常量

// 最小延迟过滤阈值（单位：微秒），低于该值的事件不会上报
// static const volatile 用于 BPF 全局变量，支持用户态配置
static const volatile bpf_u64_t targ_min_us = 0;
// 目标进程 TGID 过滤，0 表示监控所有进程
static const volatile bpf_u32_t targ_tgid = 0;

// 进程数据结构体：记录 TCP 连接发起时的进程信息
struct piddata {
	char comm[TASK_COMM_LEN];        // 进程名称
	bpf_u64_t ts;                    // 连接发起时间戳（纳秒）
	bpf_u32_t tgid;                  // 进程 ID
};

// 事件上报结构体：BPF 采集后发送给用户态的完整数据
struct event {
    // 源地址：IPv4 或 IPv6 共用联合体
    union {
        bpf_u32_t saddr_v4;          // IPv4 源地址
        bpf_u8_t  saddr_v6[16];      // IPv6 源地址
    };
    // 目标地址：IPv4 或 IPv6 共用联合体
    union {
        bpf_u32_t daddr_v4;          // IPv4 目标地址
        bpf_u8_t  daddr_v6[16];      // IPv6 目标地址
    };
	char comm[TASK_COMM_LEN];        // 进程名称
	bpf_u64_t delta_us;              // TCP 建连延迟（单位：微秒）
	bpf_u64_t ts_us;                 // 事件时间戳（单位：微秒）
	bpf_u32_t tgid;                  // 进程 ID
	int af;                          // 地址协议簇（AF_INET/AF_INET6）
	bpf_u16_t lport;                 // 本地端口
	bpf_u16_t dport;                 // 目标端口
};

/*
 * 控制结构体
 * 用户态通过修改这个结构体，控制eBPF程序的开关
 */
struct TcpConnect_Delay_ctrl {
    bpf_bool_t enable;    // 监控开关：true=开启监控  false=关闭监控
};

#endif
