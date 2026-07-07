#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "block_io.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ctrl_map、stats_map固定数组使用的key值
const int ctrl_key = 0;

/*
 * io_key：块IO请求唯一匹配键
 * 用于哈希io_map关联一对 block_rq_issue(IO下发) / block_rq_complete(IO完成) 追踪点
 * 同一设备+起始扇区可以唯一标识一条块IO请求
 * @field dev 块设备主次设备号复合值，区分磁盘/分区
 * @field sector 本次IO请求的起始扇区号
 */
struct io_key { 
	bpf_s32_t dev; 
	bpf_u64_t sector; 
};

/**
 * @struct io_start
 * 块IO下发时临时缓存结构体，存储IO请求全量上下文
 * issue追踪点写入io_map哈希；complete追踪点读取计算延迟、组装事件
 * @field start_ts block_rq_issue触发时内核纳秒时间戳，用于计算整套IO耗时
 * @field pid 发起IO操作的进程TGID（用户态PID）
 * @field rwbs 原始读写标识字符 'R'/'W'/'D'/'F'
 * @field bytes 本次IO总数据字节 = nr_sectors * 512
 * @field nr_sectors 本次IO占用扇区数量
 * @field comm 发起块IO的进程名称
 */
struct io_start 
{ 
	bpf_u64_t start_ts; 
	bpf_s32_t pid; 
	bpf_s32_t rwbs; 
	bpf_u64_t bytes; 
	bpf_u32_t nr_sectors; 
	bpf_s8_t  comm[TASK_COMM_LEN]; 
};

/*
 * io_map：块IO临时上下文哈希MAP
 * 类型：BPF_MAP_TYPE_HASH，key为io_key(dev+sector)，value为io_start
 * max_entries=65536：最大缓存65536条未完成IO请求，防止哈希溢出
 * 流程：block_rq_issue插入一条IO现场；block_rq_complete读取、处理后删除本条key释放空间
 * 作用：配对追踪点，保存IO下发起点时间与业务信息，IO完成后算出磁盘全链路延迟
 */
struct { 
	__uint(type, BPF_MAP_TYPE_HASH); 
	__uint(max_entries, 65536); 
	__type(key, struct io_key); 
	__type(value, struct io_start); 
} io_map SEC(".maps");


struct { 
	__uint(type, BPF_MAP_TYPE_ARRAY); 
	__uint(max_entries, 1); 
	__type(key, int); 
	__type(value, struct BlockIo_ctrl); 
} ctrl_map SEC(".maps");

/*
 * stats_map：全局块IO汇总统计数组MAP
 * 持久存储所有符合过滤条件的IO完成指标：总次数、总耗时、单次最大IO延迟
 * 程序退出用户态读取此map打印整机磁盘IO统计报表
 */
struct { 
	__uint(type, BPF_MAP_TYPE_ARRAY); 
	__type(key, int); 
	__type(value, struct BlockIo_stats); 
} stats_map SEC(".maps");


struct { 
	__uint(type, BPF_MAP_TYPE_RINGBUF); 
	__uint(max_entries, 256 * 1024); 
} rb SEC(".maps");

/**
 * @brief 工具内联函数：获取全局监控控制配置指针
 * @return ctrl_map中存储的BlockIo_ctrl结构体指针
 */
static inline struct BlockIo_ctrl *get_ctrl(void) { 
	return bpf_map_lookup_elem(&ctrl_map, &ctrl_key); 
}

/**
 * @brief IO操作类型编码转换工具函数
 * 将内核原始rwbs字符转为数字标识，存入事件结构体方便用户态解析
 * @param c 原始字符 R/W/D/F/?
 * @return 1=读R,2=写W,3=丢弃D,4=刷新F,5=未知类型
 */
static int enc(char c) { 
	switch(c){
		case'R':return 1;
		case'W':return 2;
		case'D':return 3;
		case'F':return 4;
		default:return 5;
	} 
}

/*
 * tracepoint/block/block_rq_issue：块IO请求下发入口追踪点
 * 内核将IO请求下发至块设备队列时触发
 * 功能：构造io_key(dev+sector)，将IO起点时间、进程、扇区、读写信息存入io_map哈希
 * 过滤逻辑：监控开关关闭直接跳过，不写入哈希缓存
 */
/**
 * @brief IO入队钩子，记录IO请求起点上下文存入哈希临时缓存
 * @param ctx tracepoint原生事件结构体，存放dev、sector、rwbs、nr_sector等IO信息
 * @return 0 BPF tracepoint固定返回值
 */
SEC("tracepoint/block/block_rq_issue")
int trace_issue(struct trace_event_raw_block_rq_completion *ctx)
{
	struct BlockIo_ctrl *c = get_ctrl();
	if (!c || !c->enable) 
		return 0;

	// 构造唯一IO匹配键：设备号+起始扇区
	struct io_key k = {
		.dev = (bpf_s32_t)ctx->dev,
		.sector = ctx->sector
	};
	// 初始化临时IO上下文结构体
	struct io_start v = {};

	// 记录IO下发入队时刻纳秒时间戳，用于complete探针计算整套IO耗时
	v.start_ts = bpf_ktime_get_ns();
	// 获取当前发起IO的进程TGID
	v.pid = (bpf_s32_t)(bpf_get_current_pid_tgid() >> 32);
	// 原始读写标识字符 R/W/D/F
	v.rwbs = ctx->rwbs[0];
	// 本次IO占用扇区数量
	v.nr_sectors = ctx->nr_sector;
	// 计算总IO字节数（标准磁盘扇区512字节）
	v.bytes = (u64)ctx->nr_sector * 512;
	// 读取进程名
	bpf_get_current_comm(&v.comm, sizeof(v.comm));

	// 将本条IO上下文插入哈希map，等待complete追踪点读取匹配
	bpf_map_update_elem(&io_map, &k, &v, BPF_ANY);
	return 0;
}

/*
 * tracepoint/block/block_rq_complete：块IO请求完成返回追踪点
 * 与block_rq_issue成对使用：通过dev+sector匹配哈希缓存，计算整套IO延迟
 * 多层过滤：目标PID不匹配 / IO耗时小于阈值直接删除哈希key丢弃事件
 * 符合条件则封装BlockIo_event推送ringbuf，并更新全局IO统计
 * 处理完成删除io_map本条key，释放哈希内存防止溢出
 */
/**
* @brief IO完成钩子，计算磁盘IO全链路耗时、过滤、下发实时IO事件并更新统计
* @param ctx tracepoint原生完成事件结构体，携带dev、sector用于匹配io_map缓存
* @return 0 BPF tracepoint固定返回值
*/
SEC("tracepoint/block/block_rq_complete")
int trace_complete(struct trace_event_raw_block_rq_completion *ctx)
{
	struct BlockIo_ctrl *c = get_ctrl();
	if (!c || !c->enable) 
		return 0;

	// 构造和issue相同的匹配键，查找对应IO起点缓存
	struct io_key k = {
		.dev = (bpf_s32_t)ctx->dev,
		.sector = ctx->sector
	};
	struct io_start *v = bpf_map_lookup_elem(&io_map, &k);
	if (!v) 
		return 0;

	// 获取IO完成时刻时间戳，计算整套块IO从入队到完成总耗时
	u64 now = bpf_ktime_get_ns();
	u64 lat = now - v->start_ts;

	// 过滤规则1：配置目标监控PID，当前IO进程不匹配，删除哈希key丢弃事件
	if (c->target_pid != 0 && v->pid != c->target_pid) { 
		bpf_map_delete_elem(&io_map, &k); 
		return 0; 
	}
	// 过滤规则2：配置最小IO延迟阈值，本次IO耗时不足阈值，丢弃事件
	if (c->min_latency_ns && lat < c->min_latency_ns) { 
		bpf_map_delete_elem(&io_map, &k); 
		return 0; 
	}

	// 从ringbuf分配内存封装IO事件
	struct BlockIo_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) { 
		// ringbuf缓冲区满，分配失败，清理哈希key后丢弃事件
		bpf_map_delete_elem(&io_map, &k); 
		return 0; 
	}

	// 填充IO事件所有字段
	e->type = BLOCK_IO_EV_COMPLETE;  // 事件类型：IO完成
	e->ts_ns = now;                   // IO完成时间戳
	e->latency_ns = lat;              // 整套块IO全链路耗时(ns)
	e->pid = v->pid;                  // IO发起进程PID
	e->dev = k.dev;                   // 块设备号
	e->sector = k.sector;             // IO起始扇区
	e->nr_sectors = v->nr_sectors;    // 占用扇区数
	e->rwbs = enc(v->rwbs);           // 转换读写类型数字编码
	e->bytes = v->bytes;              // IO总字节
	// 拷贝进程名到事件
	__builtin_memcpy(e->comm, v->comm, TASK_COMM_LEN);

	// 将事件提交ringbuf，用户态libbpf可阻塞读取打印实时磁盘IO
	bpf_ringbuf_submit(e, 0);

	/* 更新全局块IO完成统计指标 */
	struct BlockIo_stats *st = bpf_map_lookup_elem(&stats_map, &ctrl_key);
	// 首次运行无统计数据，初始化全零统计结构体写入map
	struct BlockIo_stats z = {};
	if (!st) { 
		bpf_map_update_elem(&stats_map, &ctrl_key, &z, BPF_ANY); 
		st = bpf_map_lookup_elem(&stats_map, &ctrl_key); 
	}
	if (st) {
		st->complete_cnt++;        // IO完成总次数+1
		st->total_lat_ns += lat;   // 累加所有IO总耗时
		if (lat > st->max_lat_ns)  // 刷新单次最大IO延迟
			st->max_lat_ns = lat;
	}

	// 本条IO处理完毕，删除哈希key释放内核内存，防止io_map哈希溢出
	bpf_map_delete_elem(&io_map, &k);
	return 0;
}
