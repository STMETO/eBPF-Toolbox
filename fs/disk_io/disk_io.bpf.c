/*
 * fs/disk_io — 监控块设备 IO 完成事件（tracepoint/block/block_rq_complete）
 * 监控真实落地磁盘 IO 负载，统计各进程磁盘请求完成量。
 */
 #include <vmlinux.h>
 #include <bpf/bpf_helpers.h>
 #include <bpf/bpf_tracing.h>
 #include <bpf/bpf_core_read.h>
 #include "disk_io.h"
 
 // 协议声明，块设备tracepoint依赖该协议才能正常加载
 char LICENSE[] SEC("license") = "Dual BSD/GPL";
 
 // ctrl_map数组固定唯一下标key
 const int ctrl_key = 0;
 
 /**
  * ctrl_map：全局控制数组MAP
  * 单元素数组，存储采集总开关enable、磁盘设备白名单filter_devs
  * 用户态可动态修改开关与过滤设备，无需重载BPF程序
  */
 struct {
	 __uint(type, BPF_MAP_TYPE_ARRAY);
	 __uint(max_entries, 1);
	 __type(key, int);
	 __type(value, struct DiskIoVisit_ctrl);
 } ctrl_map SEC(".maps");
 
 /**
  * rb：环形缓冲区
  * 256KB 无锁内核缓冲，IO完成事件统一推送至用户态libbpf消费
  */
 struct {
	 __uint(type, BPF_MAP_TYPE_RINGBUF);
	 __uint(max_entries, 256 * 1024);
 } rb SEC(".maps");
 
 /*
  * io_count_map — 进程累计 IO 次数（LRU_PERCPU_HASH）
  * key=PID，自动淘汰 + 每 CPU 独立计数，无并发竞争
  * max_entries=65536 支持海量并发进程
  * value：单CPU视角下该进程已完成的磁盘IO总次数
  */
 struct {
	 __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	 __uint(max_entries, 65536);
	 __type(key, u32);        /* PID 进程ID */
	 __type(value, u32);      /* 累计 IO 完成次数 */
 } io_count_map SEC(".maps");
 
 /**
  * @brief 内联读取全局采集控制配置
  * @return ctrl_map控制结构体指针
  */
 static __always_inline struct DiskIoVisit_ctrl *get_ctrl(void)
 {
	 return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
 }
 
 /**
  * @brief 设备过滤：判断当前块设备是否在监控白名单内
  * @param dev 块设备主次设备号
  * @param ctrl 全局控制配置，存放设备白名单数组filter_devs
  * @return true=允许采集；false=过滤丢弃本次IO事件
  * 规则：白名单全部为0 → 监控所有设备；仅匹配列表内设备才放行
  */
 static __always_inline bool dev_is_allowed(bpf_s32_t dev,
						const struct DiskIoVisit_ctrl *ctrl)
 {
	 bool any = false;
	 for (int i = 0; i < DISK_IO_MAX_DEVS; i++) {
		 if (ctrl->filter_devs[i] != 0) {
			 any = true;
			 if ((bpf_u32_t)dev == ctrl->filter_devs[i])
				 return true;
		 }
	 }
	 // 无任何过滤规则，全部设备放行
	 return !any;
 }
 
 /**
  * @brief 将rwbs标识字符转为数字编码，区分多种IO类型
  * @param c ctx->rwbs[0] 原始字符标记
  * @return 标准化数字编码，方便用户态解析展示
  */
 static __always_inline bpf_s32_t encode_rwbs(char c)
 {
	 switch (c) {
	 case 'R': return 1;  /* 读 IO */
	 case 'W': return 2;  /* 写 IO */
	 case 'D': return 3;  /* 磁盘丢弃/trim */
	 case 'F': return 4;  /* 刷盘 flush */
	 default:  return 5;  /* 其他未知类型 */
	 }
 }
 
 /**
  * tracepoint挂载点：block/block_rq_complete
  * 触发时机：磁盘IO请求硬件执行完成，区别于issue下发埋点；
  * 适合统计真实落地完成的IO请求、观测磁盘负载与完成次数
  * ctx：块IO完成上下文，携带设备号、扇区数、IO类型rwbs
  */
 SEC("tracepoint/block/block_rq_complete")
 int tracepoint_block_visit(struct trace_event_raw_block_rq_completion *ctx)
 {
	 // 读取采集总开关，关闭直接返回
	 struct DiskIoVisit_ctrl *ctrl = get_ctrl();
	 if (!ctrl || !ctrl->enable)
		 return 0;
 
	 // 设备白名单过滤，不在列表直接丢弃事件
	 if (!dev_is_allowed(ctx->dev, ctrl))
		 return 0;
 
	 // 获取当前进程PID（pid_tgid高32位为PID）
	 u32 pid = bpf_get_current_pid_tgid() >> 32;
 
	 /* PERCPU 计数：当前CPU独立累加，无并发竞争 */
	 // 查询当前CPU分片内该PID的历史IO完成次数
	 u32 *cntp = bpf_map_lookup_elem(&io_count_map, &pid);
	 u32 old_cnt = cntp ? *cntp : 0;
	 u32 new_cnt = old_cnt + 1;
	 // 更新当前CPU分片的累计计数
	 bpf_map_update_elem(&io_count_map, &pid, &new_cnt, BPF_ANY);
 
	 // 环形缓冲区预留事件内存，分配失败直接丢弃
	 struct DiskIoVisit_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	 if (!e)
		 return 0;
 
	 // 填充完整事件字段
	 e->timestamp = bpf_ktime_get_ns();    // 单调纳秒时间戳
	 e->blk_dev   = ctx->dev;              // 块设备主次设备号
	 e->pid       = (bpf_s32_t)pid;        // 当前进程PID
	 e->sectors   = ctx->nr_sector;        // 本次IO占用扇区数量
	 e->rwbs      = encode_rwbs(ctx->rwbs[0]); // 标准化IO类型编码
	 e->count     = (bpf_s32_t)new_cnt;    // 当前CPU视角该进程累计IO完成次数
	 e->curr_io   = (u64)ctx->nr_sector * 512; // 本次IO字节大小
	 bpf_get_current_comm(e->comm, sizeof(e->comm)); // 进程程序名
 
	 // 提交完整事件到环形缓冲区，推送用户态
	 bpf_ringbuf_submit(e, 0);
	 return 0;
 }
 