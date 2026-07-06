#ifndef __PR_H
#define __PR_H

#include "common/types.h"

/**
 * @struct Pr_ctrl
 * @brief BPF控制MAP存储结构，控制页面回收探针启停
 * @param enable 布尔开关：true开启页面回收事件采集，false关闭
 */
struct Pr_ctrl { bpf_bool_t enable; };

/**
 * @struct Pr_event
 * @brief RingBuffer上报的页面回收事件结构体，每次执行shrink_page_list上报一次
 * @param reclaim 本次扫描计划回收的目标页面数 nr_to_reclaim
 * @param reclaimed 本次扫描实际成功回收的页面数 nr_reclaimed
 * @param unqueued_dirty 扫描过程中遇到的未排队脏页数量
 * @param congested 存储设备拥塞计数，数值高代表IO瓶颈阻塞回收
 * @param writeback 正在执行磁盘回写的页面数量，回写过多会拖慢内存回收
 */
struct Pr_event {
	bpf_u64_t reclaim;
	bpf_u64_t reclaimed;
	bpf_u32_t unqueued_dirty;
	bpf_u32_t congested;
	bpf_u32_t writeback;
};

/* 仅用户态编译生效，BPF内核代码忽略该段 */
#ifndef __BPF__
#include <stdbool.h>
/**
 * @brief 页面回收监控工具主运行入口
 * @param poll_timeout_ms 环形缓冲区阻塞读取超时时间(ms)
 * @param enable 采集总开关，true加载BPF探针开始监控页面回收
 * @return int 0正常退出，非0代表加载/读取失败
 */
int pr_run(int poll_timeout_ms, bool enable);
#endif

#endif
