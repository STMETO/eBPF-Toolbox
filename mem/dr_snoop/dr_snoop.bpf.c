/**
* dr_snoop.bpf.c
* eBPF tracepoint 探针：追踪内核 direct‑reclaim（直接内存回收）事件
* 监听 mm_vmscan_direct_reclaim_begin / mm_vmscan_direct_reclaim_end tracepoint
* 统计直接回收耗时、回收页面数，支持 PID‑Namespace 穿透过滤、目标PID过滤、耗时阈值过滤
* 统计指标存入 percpu map，详细事件通过 ringbuf 输出到用户态
*
* direct‑reclaim：当进程申请内存、zone空闲页不足，进程自身进入同步内存回收路径，
* 进程会阻塞，直接影响业务延迟；kswapd 是内核后台异步回收，与此探针不覆盖。
*/

/*
应用程序发起内存分配（malloc / mmap / brk，触发缺页）
    ↓
用户态陷入内核，进入__alloc_pages分配物理页
    ↓
空闲页不足，唤醒kswapd后台异步回收（kswapd路径，dr_snoop不统计）
    ↓
水位依旧不够，业务进程进入同步直接回收路径 __alloc_pages_direct_reclaim
    ↓
try_to_free_pages() 入口
*	trace_mm_vmscan_direct_reclaim_begin：进入direct‑reclaim（dr_snoop开始计时val->ts）
	    ↓
	do_try_to_free_pages() 页面回收主干逻辑
	    shrink_zones / shrink_node 扫描内存zone、LRU链表
	    │   ↳ shrink_inactive_list 回收不活跃页
	    │   ↳ shrink_folio_list：处理待回收folio
	    │       ├─ 匿名页：发起swap写，落到块设备IO（进程阻塞等待swap IO完成）
	    │       ├─ 文件脏页：发起pageout回写，落到块设备IO（进程阻塞等待磁盘IO）
	    │       └─ cond_resched：回收中被调度器切出CPU，睡眠时间计入dr_snoop延时
	    ↓
*	trace_mm_vmscan_direct_reclaim_end：direct‑reclaim逻辑执行完毕（dr_snoop停止计时now，计算delay_ns = now‑val->ts）
    ↓
try_to_free_pages返回nr_reclaimed，回到__alloc_pages_slowpath
    ↓
再次尝试get_page_from_freelist从buddy系统分配物理页【不在dr_snoop统计区间】
    ↓
分配成功：返回用户态，应用程序malloc/mmap返回；分配失败触发OOM killer【不在dr_snoop统计区间】

*/

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "dr_snoop.h"
#include "common/pid_namespace.bpf.h"

// eBPF 程序许可证，Dual BSD/GPL 允许使用 GPL tracepoint 相关内核 helper
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ctrl_map array map 的固定下标 key，只使用 index=0 存储全局控制配置
const int ctrl_key = 0;

/**
* start map：保存每个进程 direct‑reclaim begin 事件的起始上下文
* 类型 LRU_HASH：LRU自动淘汰，防止 begin 丢失 end 造成内存泄漏（例如内核崩溃、tracepoint丢事件）
* key：app_current_pid_tgid_ns 返回的 64bit id；高32位 tgid(进程PID)，低32位 tgid(线程tid)，已经做pid namespace转换
* value：struct val_t，保存开始时间戳、进程comm、id
* max_entries 16384：最多缓存16384个正在进行direct‑reclaim的任务
*
* 注意：direct reclaim过程中任务可能睡眠、被调度迁移到其他CPU，
* 不能用 per‑cpu array 存起始时间；必须用进程唯一id做全局hash关联 begin/end。
*/
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, bpf_u64_t);
	__type(value, struct val_t);
} start SEC(".maps");

/**
* ctrl_map：全局控制参数，Array map，仅index=0有效
* 用户态向这里写入配置：开关enable、target_pid、min_delay_ns、pid namespace设备号/ino
* eBPF程序读取该map来做过滤控制
*/
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct DrSnoop_ctrl);
} ctrl_map SEC(".maps");

/**
* stats_map：per‑cpu array，每个CPU一份统计结构体 DrSnoop_stats
* 优点：每个CPU写自己的slot，不需要锁，BPF中禁止自旋锁；用户态遍历所有cpu slot做聚合求和
* 存放：尝试次数、完成次数、总耗时、总回收页数、最大耗时记录、各类错误计数（丢事件、ringbuf丢包、map更新失败等）
*/
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct DrSnoop_stats);
} stats_map SEC(".maps");

/**
* rb：BPF RingBuffer，高性能环形缓冲区，向用户态输出direct‑reclaim详细事件
* max_entries 256*1024 = 256KB ringbuf大小
* bpf_ringbuf_reserve / bpf_ringbuf_submit 完成事件提交；预留失败代表ringbuf满，事件丢弃
*/
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
* struct trace_event_raw_mm_vmscan_direct_reclaim_end_template___local
* CO‑RE 本地镜像结构体，**只声明我们需要使用的字段 nr_reclaimed**
*
* tracepoint raw上下文的内核结构体名字为 trace_event_raw_mm_vmscan_direct_reclaim_end_template
* 后缀 ___local 是 libbpf CO‑RE 的约定：加载阶段重定位 nr_reclaimed 字段的偏移，
* 不需要复制整个巨大tracepoint原始结构体，不需要关心内核其他字段布局差异，实现多内核版本兼容。
* preserve_access_index 属性：开启 BPF CO‑RE 重定位，访问成员时bpf_core_read自动做偏移重写。
*
* 字段 nr_reclaimed：本次 direct‑reclaim 成功回收的页面数量（PAGE_SIZE 页）
*/
struct trace_event_raw_mm_vmscan_direct_reclaim_end_template___local {
	unsigned long nr_reclaimed;
} __attribute__((preserve_access_index));

/**
* get_ctrl
* @brief 读取全局控制配置，从 ctrl_map index 0 取出 DrSnoop_ctrl
* @return 返回map value指针；返回NULL代表map查找失败（未初始化）
* __always_inline：强制内联，tracepoint上下文函数调用栈深度有限，减少BPF栈使用
*/
static __always_inline struct DrSnoop_ctrl *get_ctrl(void)
{
	return bpf_map_lookup_elem(&ctrl_map, &ctrl_key);
}

/**
* get_stats
* @brief 获取当前CPU的per‑cpu统计结构体slot指针
* @return 当前CPU的 DrSnoop_stats*；NULL代表map查找失败
* 注意：percpu array，bpf_map_lookup_elem返回当前CPU对应的value副本，写操作只影响本CPU统计
*/
static __always_inline struct DrSnoop_stats *get_stats(void)
{
	return bpf_map_lookup_elem(&stats_map, &ctrl_key);
}

/**
* trace_direct_reclaim_begin
* @tracepoint: vmscan:mm_vmscan_direct_reclaim_begin
* @ctx tracepoint原始上下文指针
*
* 内核进入direct reclaim路径触发：进程申请内存，空闲内存不足，进程开始同步回收内存。
* 主要工作：
* 1. 判断探针总开关enable是否打开；关闭直接返回
* 2. app_current_pid_tgid_ns：传入pid‑ns的dev、ino，获取该pid namespace视角下的pid/tgid；支持容器场景追踪
* 3. target_pid过滤：配置目标PID，只观测指定进程的direct reclaim事件
* 4. 更新统计 attempted（direct‑reclaim发起尝试计数）
* 5. 获取当前进程comm，记录进入时刻ktime时间戳
* 6. 将<namespace‑aware pid_tgid, val_t>存入 LRU_HASH start map，等待end事件来匹配
*
* note：direct reclaim过程任务可能睡眠、CPU迁移，所以使用namespace pid_tgid作为全局key，不能用cpu局部存储。
* LRU map 限制最大条目，防止 end tracepoint丢失时，start map无限累积残留key。
*/
SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin")
int trace_direct_reclaim_begin(void *ctx)
{
	struct DrSnoop_ctrl *ctrl = get_ctrl();
	struct DrSnoop_stats *stats;
	struct val_t val = {};
	bpf_u64_t id;
	bpf_s32_t tgid;

	// 未使用参数消除编译器告警
	(void)ctx;

	// 探针未启用，直接退出
	if (!ctrl || !ctrl->enable)
		return 0;

	/*
	* app_current_pid_tgid_ns: common/pid_namespace.bpf.h中实现
	* 根据传入的pid‑ns dev、ino，转换current任务的pid/tgid到目标pid namespace的编号；
	* 返回0表示不在目标pid‑namespace内，直接忽略该事件。
	* id格式：高32位 tgid(进程组id，用户态PID)，低32位 tid(线程id)
	*/
	id = app_current_pid_tgid_ns(ctrl->pid_ns_dev, ctrl->pid_ns_ino);
	if (!id)
		return 0;

	// 提取进程tgid(用户态PID)
	tgid = (bpf_s32_t)(id >> 32);

	// 设置target_pid并且不匹配，则跳过该事件
	if (ctrl->target_pid && ctrl->target_pid != tgid)
		return 0;

	// per‑cpu统计：direct‑reclaim 发起次数 +1
	stats = get_stats();
	if (stats)
		stats->attempted++;

	// 填充start map的value：id、进入时间戳、进程名字
	val.id = id;
	val.ts = bpf_ktime_get_ns(); // 获取内核单调时钟，纳秒，不受系统wall‑time修改影响
	bpf_get_current_comm(val.name, sizeof(val.name)); // 获取task_struct->comm，进程名，最多TASK_COMM_LEN字节

	/*
	* BPF_ANY：key存在就覆盖，不存在新增。
	* 返回非0代表map更新失败：LRU达到上限无法分配新entry；统计map_update_failed计数。
	* 风险：如果map更新失败，后续end事件到来会发生lookup_missed。
	*/
	if (bpf_map_update_elem(&start, &id, &val, BPF_ANY) && stats)
		stats->map_update_failed++;

	return 0;
}

/**
* trace_direct_reclaim_end
* @tracepoint vmscan:mm_vmscan_direct_reclaim_end
* @ctx tracepoint原始事件上下文，cast为我们本地CO‑RE结构体
*
* direct‑reclaim回收结束时触发，不管回收成功、失败、提前退出都会走到这个tracepoint。
* 核心逻辑：
* 1. 通过namespace pid‑tgid id查找start map，拿到begin时刻的时间戳与comm
* 2. 找不到key：统计lookup_missed（两种场景：begin丢tracepoint；map LRU淘汰了旧entry）
* 3. 检查运行时开关变化：如果探针关闭/PID过滤不再匹配，必须清理残留map entry，防止泄漏
* 4. 计算本次direct‑reclaim阻塞耗时 delay_ns = 当前时间 - begin时间戳
* 5. CO‑RE读取 nr_reclaimed，本次回收成功的page数目
* 6. 更新per‑cpu统计：completed、total_ns、total_reclaimed；更新全局最大耗时max_ns记录
* 7. min_delay_ns阈值过滤：小于阈值只更新统计，不向ringbuf输出明细事件，减少用户态流量
* 8. 满足阈值：ringbuf_reserve分配事件buffer，填充data_t事件，ringbuf_submit提交给用户态
* 9. 无论成功输出、过滤、ringbuf满丢弃，**必须删除start map中的id**，释放hash表条目
*/
SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_end")
int trace_direct_reclaim_end(void *ctx)
{
	// ctx是tracepoint原始raw缓冲区指针，用CO‑RE本地结构体解释
	struct trace_event_raw_mm_vmscan_direct_reclaim_end_template___local *args = ctx;
	struct DrSnoop_ctrl *ctrl = get_ctrl();
	struct DrSnoop_stats *stats = get_stats();
	struct val_t *val;
	struct data_t *event;
	bpf_u64_t id;
	bpf_u64_t now, delay_ns, reclaimed;
	bpf_s32_t tgid;

	// 控制map不存在，直接返回
	if (!ctrl)
		return 0;

	// 同样做pid namespace转换，拿到本次end事件对应的任务id
	id = app_current_pid_tgid_ns(ctrl->pid_ns_dev, ctrl->pid_ns_ino);
	if (!id)
		return 0;
	tgid = (bpf_s32_t)(id >> 32);

	// 在start hash map查找begin阶段保存的上下文
	val = bpf_map_lookup_elem(&start, &id);
	if (!val) {
		/*
		* lookup miss：没有找到对应的begin记录。
		* 产生原因：
		* 1. begin tracepoint丢事件；
		* 2. LRU‑HASH max_entries打满，旧entry被LRU淘汰；
		* 3. begin被过滤掉，但end事件仍然命中tracepoint。
		* 只有探针开启，并且匹配target_pid条件，才计入lookup_missed统计。
		*/
		if (ctrl && ctrl->enable && stats &&
			(!ctrl->target_pid || ctrl->target_pid == tgid))
			stats->lookup_missed++;
		return 0;
	}

	/*
	* 边界case：begin事件时探针开启；在direct‑reclaim执行过程中，用户态关闭探针 / 修改target_pid。
	* 此时虽然找到了val，但是过滤条件已经不满足；必须删除map entry，否则start map残留脏key。
	* 注意：此时不输出事件，也不计入completed统计，直接清理状态返回。
	*/
	if (!ctrl || !ctrl->enable ||
		(ctrl->target_pid && ctrl->target_pid != tgid)) {
		bpf_map_delete_elem(&start, &id);
		return 0;
	}

	// 计算本次direct‑reclaim耗时，纳秒
	now = bpf_ktime_get_ns();
	delay_ns = now - val->ts;

	// CO‑RE安全读取tracepoint参数 nr_reclaimed：本次回收成功的页面数量
	reclaimed = BPF_CORE_READ(args, nr_reclaimed);

	// 更新per‑cpu统计指标
	if (stats) {
		stats->completed++;                 // direct‑reclaim正常完成计数
		stats->total_ns += delay_ns;        // 累加总direct‑reclaim耗时
		stats->total_reclaimed += reclaimed;// 累加回收总page数

		// 更新最大耗时记录：保存最大delay、对应pid、进程comm名字
		if (delay_ns > stats->max_ns) {
			stats->max_ns = delay_ns;
			stats->max_pid = tgid;
			__builtin_memcpy(stats->max_comm, val->name, TASK_COMM_LEN);
		}
	}

	/*
	* min_delay_ns：用户配置最小输出耗时阈值。
	* 小于阈值：只更新聚合统计，不输出ringbuf明细事件，减少高频短回收事件带来用户态IO压力。
	* filtered_delay 统计被阈值过滤掉的事件数量。
	* 仍然要delete map entry释放hash key。
	*/
	if (ctrl->min_delay_ns && delay_ns < ctrl->min_delay_ns) {
		if (stats)
			stats->filtered_delay++;
		bpf_map_delete_elem(&start, &id);
		return 0;
	}

	/*
	* ringbuf 分配事件内存。
	* bpf_ringbuf_reserve：从ringbuf预留一块sizeof(*event)大小缓冲区。
	* 返回NULL代表ringbuf缓冲区已满，无法存放新事件；统计 ringbuf_dropped。
	* 无论分配成功失败，必须删除start map entry，避免内存泄漏。
	*/
	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event) {
		if (stats)
			stats->ringbuf_dropped++;
		bpf_map_delete_elem(&start, &id);
		return 0;
	}

	// 填充输出事件结构体 data_t，给用户态解析
	event->id = val->id;
	event->delta = delay_ns;        // direct‑reclaim耗时ns
	event->ts_ns = now;             // end事件发生的内核单调时间戳
	event->nr_reclaimed = reclaimed;// 回收页面数
	__builtin_memcpy(event->name, val->name, TASK_COMM_LEN);

	// 提交ringbuf事件，0标志：不使用BPF_RB_FORCE_WAKEUP；有数据用户态poll会被唤醒
	bpf_ringbuf_submit(event, 0);

	// 事件处理完毕，删除hash中保存的begin上下文，释放map条目
	bpf_map_delete_elem(&start, &id);

	return 0;
}
