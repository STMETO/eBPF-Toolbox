#ifndef __MUTEXLOCK_H
#define __MUTEXLOCK_H
#include "common/types.h"

struct Mutexlock_ctrl {
	bpf_bool_t enable;
	bpf_u64_t  min_delay_ns;
	bpf_s32_t  target_pid;
	bpf_u64_t  pid_ns_dev;
	bpf_u64_t  pid_ns_ino;
};

/**
 * @struct Mutexlock_event
 * @brief BPF通过ringbuf推送给用户态的锁竞争事件结构体
 * 仅在发生锁阻塞（进入慢路径__mutex_lock_slowpath）时生成推送
 * @field ptr 内核struct mutex对象虚拟地址，唯一标识一把互斥锁
 * @field owner_pid 当前持有锁的进程PID，无持有者则为0
 * @field contender_pid 当前阻塞等待锁的竞争进程PID
 * @field owner_prio 持有锁进程的调度优先级
 * @field contender_prio 竞争阻塞进程的调度优先级
 * @field contender_name 等待锁的竞争进程名称
 * @field owner_name 当前持有锁的进程名称
 */
struct Mutexlock_event {
	bpf_u64_t ptr;
	bpf_s32_t owner_pid, owner_tgid;
	bpf_s32_t contender_pid, contender_tgid;
	bpf_s32_t owner_prio, contender_prio;
	bpf_u64_t contention_ns;    // 竞争等待耗时（纳秒）
	bpf_s8_t  contender_name[TASK_COMM_LEN];
	bpf_s8_t  owner_name[TASK_COMM_LEN];
};

/**
 * @struct Mutexlock_stats
 * @brief 全局互斥锁监控汇总统计，存储在stats_map，程序退出用户态读取打印
 * @field contention_count 全局锁竞争阻塞总次数（进入慢路径次数）
 * 统计慢路径次数、等待时间及 Map/ringbuf 健康指标；按 CPU 独立累计。
 */
struct Mutexlock_stats {
	bpf_u64_t attempted;
	bpf_u64_t contention_count;
	bpf_u64_t filtered_delay;
	bpf_u64_t ringbuf_dropped;
	bpf_u64_t map_update_failed;
	bpf_u64_t lookup_missed;
	bpf_u64_t wait_total_ns;
	bpf_u64_t wait_max_ns;
	bpf_u64_t max_lock_addr;
	bpf_s32_t max_owner_pid, max_contender_pid;
	bpf_s8_t  max_owner_name[TASK_COMM_LEN], max_contender_name[TASK_COMM_LEN];
};

/* 用户态对外运行API，仅非BPF编译环境生效 */
#ifndef __BPF__
#include <stdbool.h>
/**
 * @brief 互斥锁竞争监控主入口函数
 * @param poll_timeout_ms ringbuf用户态阻塞读取超时毫秒
 * @param enable 下发内核的监控总开关
 * @param target_pid 过滤指定进程PID，0代表全量采集所有锁竞争
 * @param min_delay_ns 锁竞争等待时间过滤阈值
 * @return int 程序执行退出码，0正常，非0为错误
 */
int mutexlock_run(int poll_timeout_ms, bool enable,
		  bpf_s32_t target_pid, bpf_u64_t min_delay_ns);
#endif

#endif
