#ifndef __OOM_KILLER_H
#define __OOM_KILLER_H

#include "common/types.h"

/**
 * @struct OomKiller_ctrl
 * @brief BPF控制MAP存储结构体，用户态下发开关控制OOM采集启停
 * @param enable 布尔开关：true开启OOM事件捕获，false关闭
 */
struct OomKiller_ctrl {
	bpf_bool_t enable;
};

/**
 * @struct OomKiller_event
 * @brief 环形缓冲区推送的OOM事件完整数据结构
 * @param triggered_pid 触发本次OOM检测逻辑的进程PID
 * @param oomkill_pid 被OOM杀手选中、即将杀死的目标进程PID
 * @param mem_pages 触发OOM进程的总虚拟内存页数（total_vm）
 * @param comm 被杀死进程的进程名，长度TASK_COMM_LEN（内核标准16字节）
 */
struct OomKiller_event {
	bpf_u32_t triggered_pid;
	bpf_u32_t oomkill_pid;
	bpf_u32_t mem_pages;
	char comm[TASK_COMM_LEN];
};

/* 用户态对外接口，仅用户程序编译生效，BPF内核态跳过 */
#ifndef __BPF__
#include <stdbool.h>
/**
 * @brief OOM杀手监控主运行入口
 * @param poll_timeout_ms 环形缓冲区读取阻塞超时时间(ms)
 * @param enable 采集总开关，true加载BPF探针，false停止监控
 * @return int 0正常退出，负数代表加载/挂载/读取失败
 */
int oom_killer_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid, bpf_u64_t min_delay_ns);
#endif

#endif
