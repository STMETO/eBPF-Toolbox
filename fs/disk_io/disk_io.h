#ifndef __DISK_IO_H
#define __DISK_IO_H

#include "common/types.h"

#define DISK_IO_MAX_DEVS 8

struct DiskIoVisit_ctrl {
	bpf_bool_t enable;
	bpf_u32_t filter_devs[DISK_IO_MAX_DEVS];  /* 设备号白名单，全 0 = 不过滤 */
};

/*
 * DiskIoVisit_event — 块设备 IO 完成事件
 *
 * rwbs 编码:
 *   1 = READ    2 = WRITE    3 = DISCARD
 *   4 = FLUSH   5 = OTHER   -1 = 未知
 */
struct DiskIoVisit_event {
	bpf_s64_t timestamp;        /* 事件时间戳（纳秒） */
	bpf_s32_t blk_dev;          /* 块设备号 */
	bpf_s32_t pid;              /* 进程 PID */
	bpf_s32_t sectors;          /* IO 扇区数 */
	bpf_s32_t rwbs;             /* IO 类型: 1=读,2=写,3=discard,4=flush */
	bpf_s32_t count;            /* 该进程累计 IO 次数（PERCPU map 本 CPU 视角） */
	bpf_u64_t curr_io;          /* 单次 IO 字节数 = sectors * 512 */
	char comm[TASK_COMM_LEN];   /* 进程名称 */
};

/* 用户态入口 */
#ifndef __BPF__
#include <stdbool.h>
int disk_io_visit_run(int poll_timeout_ms, bool enable);
#endif

#endif
