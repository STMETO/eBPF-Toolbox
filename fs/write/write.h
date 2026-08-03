#ifndef __WRITE_H
#define __WRITE_H

#include "common/types.h"

/**
 * @def FS_WRITE_PATH_SIZE
 * @brief fd解析得到的文件名字缓冲区长度
 * 存储dentry基础文件名，限制最大字符数
 */
#define FS_WRITE_PATH_SIZE 256

/**
 * @struct Write_ctrl
 * @brief write探测模块运行时控制参数
 * @note PID命名空间语义、字段定义与open/read模块完全对齐，保证整套观测工具参数统一
 */
struct Write_ctrl {
	bpf_bool_t enable;          // 全局总开关：true启用write采集，false停止采集
	bpf_u64_t min_delay_ns;     // 最小延迟阈值(纳秒)；系统调用耗时低于该值，不推送明细事件，仅保留统计
	bpf_s32_t target_pid;       // 过滤目标PID；0表示不进行PID过滤，采集全部进程
	bpf_s32_t self_pid;         // 采集程序自身PID，用于防自环：过滤观测工具输出日志产生的write调用，避免无限事件反馈风暴
	bpf_u64_t pid_ns_dev;       // 目标PID命名空间对应的设备号，用于容器PID转换
	bpf_u64_t pid_ns_ino;       // 目标PID命名空间对应的inode号，配合dev定位pidns
};

/**
 * @struct Write_event
 * @brief 完整一次write(2)系统调用事件，BPF通过ringbuf下发至用户态
 *
 * 字段说明：
 * requested_count：应用层调用write传入的预期写入字节数（入参count）
 * bytes_written：内核write系统调用原始返回值，正数=成功写入字节；负数=-errno（错误码）
 * path_name_：fd关联文件dentry的基础文件名（非完整绝对路径）
 */
struct Write_event {
	bpf_s32_t pid;                  // 经过pidns转换后的进程PID（容器内PID）
	bpf_s32_t tid;                  // 经过pidns转换后的线程TID
	bpf_s32_t fd;                   // write操作使用的文件描述符
	bpf_u32_t _pad;                 // 内存对齐填充，保证结构体对齐，避免跨平台内存布局错位
	bpf_u64_t requested_count;     // 用户请求写入的字节数量（write第三个参数count）
	bpf_s64_t bytes_written;        // write系统调用返回值
	bpf_u64_t timestamp_ns;         // sys_exit时刻纳秒时间戳(CLOCK_MONOTONIC)
	bpf_u64_t latency_ns;           // write系统调用耗时（enter到exit间隔纳秒）
	bpf_s8_t path_name_[FS_WRITE_PATH_SIZE]; // fd对应文件名称
	bpf_s8_t comm[TASK_COMM_LEN];   // 进程名称（task comm，最大16字节）
};

/**
 * @struct Write_stats
 * @brief PER-CPU统计结构体，每个CPU独立一份数据
 * 用户态程序退出时，汇总所有CPU数据，输出健康面板，用于排查丢事件、异常负载
 */
struct Write_stats {
	bpf_u64_t attempted;         // 尝试进入write、通过前置过滤的调用总数
	bpf_u64_t completed;         // 成功完成enter+exit配对的write调用总数（不受延迟过滤影响）
	bpf_u64_t submitted;         // 成功送入ringbuf、下发到用户态的明细事件数量
	bpf_u64_t failed;            // write返回负数（发生错误）的调用次数
	bpf_u64_t filtered_pid;      // 因不匹配target_pid被过滤的调用数量
	bpf_u64_t filtered_self;     // 因属于采集进程自身，防自环过滤的调用数量
	bpf_u64_t filtered_delay;    // 耗时小于min_delay_ns，明细事件被过滤的调用数量
	bpf_u64_t ringbuf_dropped;   // ringbuf空间不足，事件丢失计数
	bpf_u64_t map_update_failed; // inflight_writes哈希表插入失败（表满）计数
	bpf_u64_t lookup_missed;     // exit找不到对应的enter上下文（配对丢失）计数
	bpf_u64_t path_lookup_failed;// 根据fd反向读取文件名失败次数
	bpf_u64_t total_ns;          // 所有completed调用总耗时(纳秒)，可计算平均延迟
	bpf_u64_t max_ns;            // 观测周期内最大单次write耗时
	bpf_s32_t max_pid;           // 最大耗时对应的进程PID
	bpf_s8_t max_comm[TASK_COMM_LEN]; // 最大耗时对应的进程名
};

/**
 * @brief 用户态接口声明，仅在非BPF编译环境生效
 */
#ifndef __BPF__
#include <stdbool.h>

/**
 * @brief 启动write系统调用观测主逻辑
 * @param poll_timeout_ms ringbuf轮询超时时间(毫秒)
 * @param enable 是否开启采集
 * @param target_pid 指定观测进程PID，0代表全部进程
 * @param min_delay_ns 明细最小延迟阈值，低于阈值不打印事件
 * @return int 执行返回码，0正常，负数代表异常
 */
int write_run(int poll_timeout_ms, bool enable,
	      bpf_s32_t target_pid, bpf_u64_t min_delay_ns);
#endif

#endif /* __WRITE_H */
