#ifndef __PAF_H
#define __PAF_H

#include "common/types.h"

/**
 * @struct Paf_ctrl
 * @brief BPF控制MAP存储结构，用于控制内存水位采集探针启停
 * @param enable 布尔开关，true开启采集，false关闭采集
 */
struct Paf_ctrl {
	bpf_bool_t enable;
};

/**
 * @struct Paf_event
 * @brief RingBuffer上报的内存水位事件结构体，每次页分配触发一次上报
 * @param min zone生效最低水位(基础min + watermark_boost)，低于该值会阻塞同步回收内存
 * @param low zone生效低水位(基础low + watermark_boost)，低于该值后台异步回收页面
 * @param high zone生效高水位(基础high + watermark_boost)，空闲页高于此值停止回收
 * @param present 当前zone内可用有效物理页面总数
 * @param protection zone内存保护预留页数，BPF内核代码暂未采集赋值，预留扩展字段
 * @param flag 本次内存分配的GFP掩码，标识分配约束、可使用内存域、回收策略等
 */
struct Paf_event {
	bpf_u64_t min;
	bpf_u64_t low;
	bpf_u64_t high;
	bpf_u64_t present;
	bpf_u64_t protection;
	bpf_s32_t flag;
};

/* 仅用户态编译可见，BPF内核代码忽略该段 */
#ifndef __BPF__
#include <stdbool.h>
/**
 * @brief 内存水位监控工具主运行入口
 * @param poll_timeout_ms 环形缓冲区阻塞读取超时时间(ms)
 * @param enable 采集总开关，true加载并启动BPF探针，false停止采集
 * @return int 执行结果码，0正常退出，非0代表加载/读取失败
 */
int paf_run(int poll_timeout_ms, bool enable);
#endif

#endif
