#ifndef __SLAB_RATE_H
#define __SLAB_RATE_H

#include "common/types.h"

// slab缓存名称最大存储长度
#define CACHE_NAME_SIZE 32

/**
 * 控制结构体：下发至ctrl_map，控制采集启停
 */
struct SlabRate_ctrl {
	bpf_bool_t enable; // true开启slab统计，false关闭
};

/**
 * Hash表value结构体，单类slab缓存统计信息
 */
struct SlabRate_info {
	char name[CACHE_NAME_SIZE]; // slab缓存名称（如kmalloc-64、dentry等）
	bpf_u64_t count;            // 累计分配次数
	bpf_u64_t size;             // 累计分配总字节大小（单块size * 分配次数）
};

/**
 * 用户态API声明，仅用户态编译生效，BPF内核程序忽略
 */
#ifndef __BPF__
#include <stdbool.h>
/**
 * slab分配统计主入口
 * @param poll_timeout_ms 轮询超时时间（本工具实际hash遍历不依赖poll，参数兼容通用框架）
 * @param enable true启动采集，false停止采集
 * @return 0成功，负数错误码
 */
int slab_rate_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid, bpf_u64_t min_delay_ns);
#endif

#endif
