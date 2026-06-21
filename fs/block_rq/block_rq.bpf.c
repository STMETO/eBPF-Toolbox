/*
 * fs/block_rq — 监控块设备 IO 请求提交（tracepoint/block/block_rq_issue）
 *
 * 注：total_io 为 per-CPU 近似累计值（用户态可 sum 各 CPU 副本获取精确值），
 *     curr_io 为单次 IO 准确值。
 */
// 通过 block 子系统 tracepoint 捕获块设备 IO 下发事件，统计每个进程累计块 IO 读写总量，上报磁盘 IO 事件到用户态
// 内核下发磁盘 IO 请求到块设备队列

 #include <vmlinux.h>
 #include <bpf/bpf_helpers.h>
 #include <bpf/bpf_tracing.h>
 #include <bpf/bpf_core_read.h>
 #include "block_rq.h"
 
 // 协议声明，块设备tracepoint依赖该协议加载
 char LICENSE[] SEC("license") = "Dual BSD/GPL";
 
 // ctrl_map 数组map固定唯一下标key
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
	 __type(value, struct BlockRqIssue_ctrl);
 } ctrl_map SEC(".maps");
 
 /**
  * rb：环形缓冲区
  * 256KB 内核无锁缓冲，块IO事件统一推送至用户态libbpf消费
  */
 struct {
	 __uint(type, BPF_MAP_TYPE_RINGBUF);
	 __uint(max_entries, 256 * 1024);
 } rb SEC(".maps");
 
 /*
  * io_size_map — 进程累计 IO 字节数（LRU + PERCPU）
  *
  * LRU_PERCPU_HASH：长时间无 IO 的 PID 自动淘汰；每个 CPU 独立存储
  * 一份值，消除并发读写竞争。用户态通过遍历所有 CPU 副本求和得到精确总量。
  * max_entries=65536 支持海量并发进程；key=PID，value=单CPU累计IO字节
  */
 struct {
	 __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	 __uint(max_entries, 65536);     /* 支持大量并发进程 */
	 __type(key, u32);               /* PID */
	 __type(value, u64);             /* 单CPU视角累计IO字节 */
 } io_size_map SEC(".maps");
 
 /**
  * @brief 内联函数读取全局采集控制配置
  * @return ctrl_map控制结构体指针
  */
 static __always_inline struct BlockRqIssue_ctrl *get_ctrl(void)
 {
	 return bpf_map_lookup_elem(&ctrl_map, (void *)&ctrl_key);
 }
 
 /*
  * @brief 检查当前块设备号是否在监控白名单内
  * @param dev 块设备号
  * @param ctrl 全局控制配置，存放filter_devs白名单数组
  * @return true=允许采集该设备IO；false=过滤丢弃
  * 规则：白名单全部为0则不过滤，监控所有块设备；否则仅匹配列表内设备
  */
 static __always_inline bool dev_is_allowed(bpf_s32_t dev,
						const struct BlockRqIssue_ctrl *ctrl)
 {
	 /* 标记是否存在有效过滤设备 */
	 bool any_filter = false;
	 // 遍历设备白名单数组
	 for (int i = 0; i < BLOCK_RQ_MAX_DEVS; i++) {
		 if (ctrl->filter_devs[i] != 0) {
			 any_filter = true;
			 // 当前设备匹配白名单，放行采集
			 if ((bpf_u32_t)dev == ctrl->filter_devs[i])
				 return true;
		 }
	 }
	 // 无任何过滤规则，全部设备放行
	 return !any_filter;
 }
 
 /**
  * tracepoint挂载点：block/block_rq_issue
  * 触发时机：内核向块设备下发真实磁盘IO请求（page cache命中不会触发）
  * ctx：块IO埋点上下文，携带设备号、扇区、扇区数量、IO类型标识rwbs
  */
 SEC("tracepoint/block/block_rq_issue")
 int tracepoint_block_rq_issue(struct trace_event_raw_block_rq_completion *ctx)
 {
	 // 读取采集开关，关闭则直接退出
	 struct BlockRqIssue_ctrl *ctrl = get_ctrl();
	 if (!ctrl || !ctrl->enable)
		 return 0;
 
	 /* 设备过滤：不在白名单直接丢弃本次IO事件 */
	 if (!dev_is_allowed(ctx->dev, ctrl))
		 return 0;
 
	 struct BlockRqIssue_event *e;
	 // 获取当前进程PID（pid_tgid高32位是PID）
	 u32 pid = bpf_get_current_pid_tgid() >> 32;
 
	 // 环形缓冲区预留事件内存，分配失败丢弃
	 e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	 if (!e)
		 return 0;
 
	 // 获取进程名存入事件
	 bpf_get_current_comm(e->comm, sizeof(e->comm));
 
	 // 填充基础IO元数据
	 e->timestamp  = bpf_ktime_get_ns();  // 单调纳秒时间戳
	 e->pid        = (bpf_s32_t)pid;      // 进程PID（用户态聚合用）
	 e->dev        = ctx->dev;            // 块设备主次设备号
	 e->sector     = ctx->sector;         // IO起始逻辑扇区
	 e->nr_sectors = ctx->nr_sector;      // 本次IO连续扇区数量
 
	 /* 解析读写标记：ctx->rwbs[0] 为 'R'=读, 'W'=写, 'D'=discard, 'F'=flush 等 */
	 if (ctx->rwbs[0] == 'R') {
		 e->rwbs = 1;  /* 读 IO */
	 } else if (ctx->rwbs[0] == 'W') {
		 e->rwbs = 0;  /* 写 IO */
	 } else {
		 e->rwbs = -1; /* 其他类型（discard/flush/trim） */
	 }
 
	 /* 单次 IO 字节数（准确值），内核块层标准512字节每扇区 */
	 const u64 sector_size = 512;
	 e->curr_io = (u64)ctx->nr_sector * sector_size;
 
	 /*
	  * PERCPU_HASH 累计：每个 CPU 独立累加，无锁无竞争。
	  * bpf_map_lookup_percpu_elem 读取对应 CPU 的值。
	  * 注：如果 key 不存在，*valp = 0（bpf_map_lookup_elem 返回 NULL 时我们当作 0）
	  */
	  
	// 根据PID查询当前CPU分片里保存的累计IO字节
	u64 *valp = bpf_map_lookup_elem(&io_size_map, &pid);

	// 如果该PID在当前CPU没有记录，old_val = 0；有记录就取出历史累计值
	u64 old_val = valp ? *valp : 0;

	// 历史总字节 + 本次IO字节 = 新的累计总量
	u64 new_val = old_val + e->curr_io;

	// 把新的累计值写回当前CPU对应的map分片，覆盖旧值
	bpf_map_update_elem(&io_size_map, &pid, &new_val, BPF_ANY);

	// 将当前CPU视角下该进程累计总IO写入事件，上报用户态展示
	e->total_io = new_val;

	 // 提交完整事件给用户态环形缓冲区
	 bpf_ringbuf_submit(e, 0);
	 return 0;
 }
 