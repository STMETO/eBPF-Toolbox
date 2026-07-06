#ifndef __MEM_LEAK_H
#define __MEM_LEAK_H

/**
 * @file mem_leak.h
 * @brief BPF 内存泄漏检测工具头文件
 * @desc 提供用户态 + BPF 内核态共用结构体、宏定义
 *       同时区分BPF编译环境与用户态编译环境导出接口
 * @feature
 *  1. 捕获用户态堆内存分配释放(malloc/calloc/realloc/mmap等)
 *  2. 捕获内核slab内存分配释放(kmalloc/kmem_cache_alloc/page分配)
 *  3. 按内存地址记录单次分配大小、调用栈ID
 *  4. 按调用栈聚合总分配字节、分配次数，定位泄漏栈
 *  5. 支持堆栈存储、分配时间戳记录、posix_memalign特殊指针读取
 */
#include "common/types.h"

/**
 * @brief allocs map 最大存储条目
 * allocs: key=分配内存地址, value=alloc_info 单次分配记录
 * 限制最大跟踪的未释放内存指针数量，防止哈希溢出OOM
 */
#define ALLOCS_MAX_ENTRIES 1000000

/**
 * @brief combined_allocs map 最大存储条目
 * combined_allocs: key=stack_id, value=聚合分配统计
 * 每条唯一调用栈对应一条聚合记录，数量远小于allocs
 */
#define COMBINED_ALLOCS_MAX_ENTRIES 10240

/**
 * @brief BPF检测总控开关结构体
 * @field enable bpf_bool_t 全局使能标记，用户态下发控制
 */
struct MemLeak_ctrl {
	bpf_bool_t enable;
};

/**
 * @brief 单条内存分配记录结构体
 * 存储在 allocs hash map，key = 分配返回的内存地址
 */
struct alloc_info {
	bpf_u64_t size;     ///< 本次分配的内存字节大小
	int stack_id;       ///< stack_traces 堆栈map中的栈ID，用于回溯调用链
};

/**
 * @brief 按调用栈聚合的分配统计联合体
 * 共用64bit无符号整数，拆分两段存储：总分配大小 + 分配次数
 * 原子加减 __sync_fetch_and_add/sub 直接操作bits整体实现聚合统计
 */
union combined_alloc_info {
	struct {
		bpf_u64_t total_size : 40;    ///< 该栈累计分配总字节数(40bit，最大支持约1TB)
		bpf_u64_t number_of_allocs : 24; ///< 该栈累计分配次数(24bit，最大1677万次)
	};
	bpf_u64_t bits; ///< 原始64位值，用于原子同步增减聚合数据
};

/* ===================== 用户态对外接口 ===================== */
/**
 * __BPF__ 宏由bpf编译脚本定义，仅内核BPF程序可见；
 * 未定义时为用户态程序编译，导出内存泄漏检测运行入口
 */
#ifndef __BPF__
#include <stdbool.h>

/**
 * @brief 内存泄漏检测主运行入口
 * @param poll_timeout_ms 轮询读取BPF map数据的超时时间(ms)
 * @param enable true=开启泄漏检测，false=停止检测清理资源
 * @return int 0成功，负数错误码
 */
int mem_leak_run(int poll_timeout_ms, bool enable);
#endif

#endif
