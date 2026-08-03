#ifndef __READ_H
#define __READ_H

#include "common/types.h"

/**
 * @def FS_READ_PATH_SIZE
 * @brief fd反向解析得到的文件名称缓冲区长度
 * 存放dentry基础文件名，统一与write模块缓冲区大小保持一致
 */
#define FS_READ_PATH_SIZE 256

/**
 * @struct Read_ctrl
 * @brief read观测模块运行时控制参数
 * @note 字段语义、结构体布局与Write_ctrl完全对齐，实现整套IO观测工具参数模型统一
 *
 * target_pid 使用观测工具所在PID命名空间内可见的TGID。
 * pid_ns_dev、pid_ns_ino由用户态读取/proc/self/ns/pid得到并下发至BPF；
 * BPF依据这两个值识别任务所属PID命名空间，自动过滤其他命名空间内进程，实现容器隔离采集。
 */
struct Read_ctrl {
	bpf_bool_t enable;          // 全局采集总开关，true启用read采集，false停止采集
	bpf_u64_t min_delay_ns;     // 明细事件最小延迟阈值(纳秒)；调用耗时低于阈值，不向用户态推送事件，但仍计入汇总统计
	bpf_s32_t target_pid;       // 指定观测目标PID；0表示不进行PID过滤，采集命名空间内全部进程
	bpf_s32_t self_pid;         // 监控工具自身TGID；用于防自环，过滤工具自身产生的read调用，避免日志输出引发无限事件风暴
	bpf_u64_t pid_ns_dev;       // 当前进程PID命名空间对应的设备号
	bpf_u64_t pid_ns_ino;       // 当前进程PID命名空间对应的inode号
};

/**
 * @struct Read_event
 * @brief 一次完整read(2)系统调用事件，BPF通过ringbuf下发至用户态
 *
 * pid/tid：均为观测工具所在PID命名空间内可见的进程/线程ID；
 * requested_count：用户调用read传入的预期读取字节数（入参count）；
 * bytes_read：read系统调用原始返回值，正数=成功读取字节数，负数 = -errno错误码；
 * path_name_：仅存储fd对应dentry的基础文件名，**不保证完整绝对路径**。
 */
struct Read_event {
	bpf_s32_t pid;                  // 命名空间内进程TGID
	bpf_s32_t tid;                  // 命名空间内线程TID
	bpf_s32_t fd;                   // read操作使用的文件描述符
	bpf_u32_t _pad;                 // 内存对齐填充，保证后续u64类型8字节对齐，防止用户态与BPF结构体布局错位
	bpf_u64_t requested_count;     // 请求读取字节数量
	bpf_s64_t bytes_read;          // read系统调用返回值
	bpf_u64_t timestamp_ns;         // sys_exit时刻单调纳秒时间戳
	bpf_u64_t latency_ns;           // read系统调用总耗时（enter ~ exit间隔纳秒）
	bpf_s8_t path_name_[FS_READ_PATH_SIZE]; // 文件基础名称
	bpf_s8_t comm[TASK_COMM_LEN];   // 进程名称(task comm，最大16字节)
};

/**
 * @struct Read_stats
 * @brief PER-CPU每CPU独立统计结构体
 * BPF侧采用BPF_MAP_TYPE_PERCPU_ARRAY消除高频路径原子竞争；
 * 用户态程序退出时汇总所有CPU数据，输出全局健康统计面板。
 */
struct Read_stats {
	bpf_u64_t attempted;         // 通过命名空间校验、进入后续过滤流程的read调用总数
	bpf_u64_t completed;         // 成功匹配enter/exit上下文的完成调用（不受延迟阈值影响）
	bpf_u64_t submitted;         // 成功送入ringbuf、下发到用户态的明细事件数量
	bpf_u64_t failed;            // read返回负数（系统调用出错）的调用次数
	bpf_u64_t filtered_pid;      // 因不匹配target_pid被过滤的调用数量
	bpf_u64_t filtered_self;     // 属于观测工具自身进程，防自环过滤的调用数量
	bpf_u64_t filtered_delay;    // 耗时小于min_delay_ns，明细事件被过滤的调用数量
	bpf_u64_t ringbuf_dropped;   // ringbuf空间不足，事件分配失败丢失计数
	bpf_u64_t map_update_failed; // inflight_reads哈希表插入失败（并发上限达到）计数
	bpf_u64_t lookup_missed;     // exit无法找到enter保存的上下文，配对丢失计数
	bpf_u64_t path_lookup_failed;// 根据fd反向解析文件名称失败次数
	bpf_u64_t total_ns;          // 所有completed调用总耗时，可计算平均延迟
	bpf_u64_t max_ns;            // 观测周期内单次read最大耗时
	bpf_s32_t max_pid;           // 最大耗时对应的进程PID
	bpf_s8_t max_comm[TASK_COMM_LEN]; // 最大耗时对应的进程名
};

/**
 * @brief 用户态接口声明，仅在非BPF编译环境生效
 */
#ifndef __BPF__
#include <stdbool.h>

/**
 * @brief Read文件观测模块主入口函数
 * @param poll_timeout_ms ringbuf轮询超时时间(毫秒)
 * @param enable 是否开启采集
 * @param target_pid 指定观测PID，0代表当前命名空间所有进程
 * @param min_delay_ns 明细最小延迟阈值，低于阈值不打印事件
 * @return int 返回码，0正常退出，非0代表异常
 */
int read_run(int poll_timeout_ms, bool enable,
	     bpf_s32_t target_pid, bpf_u64_t min_delay_ns);
#endif

#endif /* __READ_H */
