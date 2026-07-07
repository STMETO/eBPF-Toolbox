#ifndef __BLOCK_IO_H
#define __BLOCK_IO_H
#include "common/types.h"

// 块IO事件类型标识
#define BLOCK_IO_EV_ISSUE    0    // IO请求下发至块设备队列事件（当前BPF不单独推送该事件）
#define BLOCK_IO_EV_COMPLETE 1    // IO请求完成事件，仅该类型推送到ringbuf给用户态

struct BlockIo_ctrl {
	bpf_bool_t enable;
	bpf_u64_t  min_latency_ns;
	bpf_s32_t  target_pid;
};

/**
 * @struct BlockIo_event
 * @brief BPF通过ringbuf推送给用户态的块IO完成事件结构体
 * 仅在 block_rq_complete IO请求全部处理完毕时生成推送
 * @field type 事件类型，固定为 BLOCK_IO_EV_COMPLETE
 * @field ts_ns 内核单调时钟纳秒时间戳，IO请求完成时刻
 * @field latency_ns 块IO完整耗时：rq_issue下发时刻 ~ rq_complete完成时刻总纳秒
 * @field pid 发起本次IO操作的进程TGID（用户态ps展示PID）
 * @field dev 块设备主次设备号组合值，唯一区分磁盘/分区设备
 * @field sector IO请求起始扇区号
 * @field nr_sectors 本次IO操作占用扇区数量
 * @field rwbs IO操作类型编码：1读R / 2写W / 3丢弃D / 4刷新F / 5未知
 * @field bytes 本次IO总数据字节数 = nr_sectors * 512
 * @field comm 发起块IO请求的进程名称，固定TASK_COMM_LEN长度
 */
struct BlockIo_event {
	bpf_u32_t type;          // ISSUE or COMPLETE
	bpf_u64_t ts_ns;
	bpf_u64_t latency_ns;    // COMPLETE: issue→complete 延迟
	bpf_s32_t pid, dev;
	bpf_u64_t sector;
	bpf_u32_t nr_sectors;
	bpf_s32_t rwbs;          // 1=Read 2=Write 3=Discard 4=Flush
	bpf_u64_t bytes;
	bpf_s8_t  comm[TASK_COMM_LEN];
};

/**
 * @struct BlockIo_stats
 * @brief 全局块IO汇总统计结构体，存储在stats_map，程序退出用户态读取打印报表
 * @field issue_cnt 下发至块设备队列的IO请求总次数（预留扩展，当前未累加）
 * @field complete_cnt 成功完成并通过过滤的IO请求总次数
 * @field total_lat_ns 所有完成IO请求延迟累加总纳秒，用于计算平均IO耗时
 * @field max_lat_ns 单条IO请求最大耗时纳秒值，用于定位磁盘卡顿慢IO
 */
struct BlockIo_stats {
	bpf_u64_t issue_cnt, complete_cnt;
	bpf_u64_t total_lat_ns, max_lat_ns;
};

/* 用户态对外运行API，仅非BPF编译环境生效 */
#ifndef __BPF__
#include <stdbool.h>
/**
 * @brief 块设备IO延迟监控主入口函数
 * @param poll_timeout_ms ringbuf用户态阻塞读取超时毫秒
 * @param enable 下发内核的监控总开关
 * @param target_pid 过滤指定进程PID，0代表全量采集所有块IO
 * @param min_latency_ns IO耗时过滤阈值，低于该值不上报实时事件
 * @return int 0正常退出，非0为异常错误码
 */
int block_io_run(int poll_timeout_ms, bool enable,
		 bpf_s32_t target_pid, bpf_u64_t min_latency_ns);
#endif

#endif
