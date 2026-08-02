#ifndef __DR_SNOOP_H
#define __DR_SNOOP_H
#include "common/types.h"

/**
 * @brief eBPF程序控制结构体，用于用户态下发启停控制指令
 * @field enable 布尔开关，true开启direct reclaim监控，false关闭
 */
struct DrSnoop_ctrl {
    bpf_bool_t enable;
	bpf_u64_t min_delay_ns;
	bpf_s32_t target_pid;
	bpf_u64_t pid_ns_dev;      // bpf_get_ns_current_pid_tgid 的 namespace 设备号
	bpf_u64_t pid_ns_ino;      // bpf_get_ns_current_pid_tgid 的 namespace inode
};

/**
 * @brief direct_reclaim_begin 事件缓存快照结构体
 * 存入 HASH MAP start，保存线程进入直接内存回收瞬间的现场信息
 * @field id pid_tgid 线程唯一标识(高32位PID，低32位TID)
 * @field ts 内核单调时钟纳秒时间戳，回收开始时刻
 * @field name 进程命令名，长度TASK_COMM_LEN(内核标准16字节)
 */
struct val_t {
	bpf_u64_t id;
	bpf_u64_t ts;
	char name[TASK_COMM_LEN];
};

/**
 * @brief 上报至用户态的完整监控事件结构体
 * direct_reclaim_end 钩子组装后写入 RINGBUF 环形缓冲区
 * @field id pid_tgid 线程唯一标识，用于匹配起止事件
 * @field nr_reclaimed 本次直接内存回收成功释放的物理页面总数
 * @field delta 本次回收阻塞耗时，单位纳秒
 * @field ts_ns 事件结束时间戳，单位纳秒
 * @field name 触发回收的进程名称
 */
struct data_t {
	bpf_u64_t id;
	bpf_u64_t nr_reclaimed;
	bpf_u64_t delta;
	bpf_u64_t ts_ns;
	char name[TASK_COMM_LEN];
};

struct DrSnoop_stats {
	bpf_u64_t attempted;        // direct reclaim begin 次数
	bpf_u64_t completed;        // 成功关联 begin/end 的次数
	bpf_u64_t filtered_delay;   // 低于阈值、未输出明细的次数
	bpf_u64_t ringbuf_dropped;  // ringbuf reserve 失败次数
	bpf_u64_t map_update_failed; // begin 上下文写入 LRU Map 失败次数
	bpf_u64_t lookup_missed;    // end 未找到 begin 上下文的次数
	bpf_u64_t total_ns;         // 所有 completed reclaim 的总阻塞时间
	bpf_u64_t max_ns;           // 最大单次 reclaim 阻塞时间
	bpf_u64_t total_reclaimed;  // 所有 completed 事件回收页数之和
	bpf_s32_t max_pid;
	bpf_s8_t max_comm[TASK_COMM_LEN];
};

/* 用户态侧声明，BPF内核程序不编译此段 */
#ifndef __BPF__
#include <stdbool.h>

/**
 * @brief dr_snoop 主运行入口函数
 * 加载eBPF程序、挂载tracepoint、循环消费ringbuf输出回收事件
 * @param poll_timeout_ms ringbuf轮询等待超时时间(毫秒)
 * @param enable 全局监控总开关，true启动采集，false仅加载不采集
 * @return int 执行状态码，0正常退出，负数为异常错误码
 */
int dr_snoop_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid, bpf_u64_t min_delay_ns);
#endif

#endif
