#ifndef __PROC_STAT_H
#define __PROC_STAT_H

#include "common/types.h"

/**
 * 控制结构体：用户态下发至内核MAP，控制采集启停
 */
struct ProcStat_ctrl {
	bpf_bool_t enable; // true=开启进程指标采集，false=关闭
};

/**
 * 环形缓冲区事件结构体
 * 每次进程切换时，内核封装该结构体推送至用户态
 * 所有内存单位均为【内核页】，用户态需乘 PAGE_SIZE 换算字节
 */
struct ProcStat_event {
	bpf_s32_t pid;        // 进程PID
	bpf_s64_t nvcsw;      // 自愿上下文切换次数（进程主动放弃CPU，sleep等）
	bpf_s64_t nivcsw;     // 非自愿上下文切换次数（时间片耗尽、被抢占）

	bpf_s64_t vsize;      // 进程总虚拟内存页数 total_vm
	bpf_s64_t size;       // 常驻内存总页数(rssanon + rssfile + rssshmem)

	bpf_s64_t rssanon;    // 匿名常驻内存（堆、私有内存）
	bpf_s64_t rssfile;    // 文件缓存常驻内存（程序、库、文件映射）
	bpf_s64_t rssshmem;   // 共享内存常驻页(shmem/tmpfs)
	bpf_s64_t vswap;      // 已交换到swap分区的匿名页

	bpf_s64_t Hpages;     // 预留大页指标，当前内核代码未采集填充
	bpf_s64_t Vdata;      // 数据段虚拟内存页数 data_vm
	bpf_s64_t Vstk;       // 用户栈虚拟内存页数 stack_vm
	bpf_s64_t VPTE;       // 页表占用虚拟内存，当前内核代码未采集填充
};

/**
 * 用户态接口声明（仅用户态编译生效，BPF内核程序跳过）
 * __BPF__ 宏由bpf编译器自动定义，区分内核/用户态编译分支
 */
#ifndef __BPF__
#include <stdbool.h>
/**
 * 进程统计采集主入口函数
 * @param poll_timeout_ms 环形缓冲区poll超时时间，单位ms
 * @param enable true启动采集，false停止采集
 * @return 0成功，负数错误码
 */
int proc_stat_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid, bpf_u64_t min_delay_ns);
#endif

#endif
