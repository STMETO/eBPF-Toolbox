#ifndef __BLOCK_RQ_H
#define __BLOCK_RQ_H

#include "common/types.h"

#define BLOCK_RQ_MAX_DEVS 8   /* 设备过滤白名单最大数量 */

struct BlockRqIssue_ctrl {
	bpf_bool_t enable;
	bpf_u32_t filter_devs[BLOCK_RQ_MAX_DEVS];  /* 设备号白名单，全 0 = 不过滤 */
};

/*
 * BlockRqIssue_event — 完整描述一次块设备 IO 请求提交事件
 *
 * 数据来源：tracepoint/block/block_rq_issue
 *
 * 与旧版区别：
 *   - 新增 rwbs 字段，区分读 IO / 写 IO
 *   - 新增 curr_io 字段，单次 IO 字节数（nr_sector * 512）
 *   - total_io 保留，但改用 LRU_HASH 自动淘汰过期 PID
 */
struct BlockRqIssue_event {
	bpf_s64_t timestamp;        /* 事件时间戳（纳秒） */
	bpf_s32_t dev;              /* 块设备号 */
	bpf_s32_t sector;           /* 起始扇区号 */
	bpf_s32_t nr_sectors;       /* 本次 IO 扇区数 */
	bpf_s32_t rwbs;             /* 读写标记：1=读, 0=写（从 ctx->rwbs[0] 解析） */
	bpf_s32_t pid;              /* 进程 PID（用户态聚合 PERCPU 时查表用） */
	bpf_u64_t curr_io;          /* 单次 IO 字节数 = nr_sectors * 512 */
	bpf_u64_t total_io;         /* 该进程累计 IO 字节数（PERCPU map，本 CPU 视角） */
	char comm[TASK_COMM_LEN];   /* 进程名称 */
};

/* 用户态入口 */
#ifndef __BPF__
#include <stdbool.h>
int block_rq_issue_run(int poll_timeout_ms, bool enable);
#endif

#endif /* __BLOCK_RQ_H */
