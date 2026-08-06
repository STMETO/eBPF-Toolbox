/*
* 内核 slab 分配吞吐采集器。
*
* 指标边界：本模块统计一段时间内成功发生的内核 slab 分配次数和实际槽位
* 字节数，用于发现分配热点。它不跟踪 free，也不表示当前 slab 占用量，更
* 不能单独证明内存泄漏。
*
* 覆盖范围：
*   1. raw_tp/kmem_cache_alloc：新内核按 cache 名称、旧内核按大小聚合；
*   2. tracepoint/kmem/kmalloc：通用 kmalloc 分配，按实际分配大小聚合。
*
* 使用 tracepoint 而不是只探测 kmem_cache_alloc 函数，可以覆盖 node 等
* 其他调用入口最终发出的统一分配事件。该 raw tracepoint 的第 3 个参数是
* 标准 tracepoint 格式未导出的 struct kmem_cache *，用它保留 cache 名称。
*
* 基于 eBPF 的内核 slab 分配吞吐量（分配频率与带宽）采集器。
* 它统计的是 成功发生的内核 slab / kmalloc 分配事件的次数和实际分配的字节数
*
* 【重要业务边界说明】
* 1. 只统计分配成功事件（分配返回非NULL指针）；分配失败返回NULL直接丢弃不计入统计；
* 2. 只统计分配吞吐（alloc），完全不跟踪释放free；输出count是一段时间总分配次数，不是现存对象数量；
* 3. 不能直接等价内存泄漏判断：泄漏需要同时看alloc+free配对，本模块只看alloc侧；
* 4. 统计的bytes是slab对象实际槽位大小，不是用户调用kmalloc传入的申请size，包含slab对齐、元数据padding；
* 5. 支持PID命名空间转换：适配容器场景，用户态传入工具自身PID ns的dev/ino，内核侧把内核全局TGID转换为容器内可见TGID；
* 6. 内核版本兼容：5.x/6.x kmem tracepoint参数布局发生变化，依靠`accounted`字段是否存在做CO‑RE特征检测，区分新旧raw_tp参数布局；
* 7. PERCPU_HASH设计：每个CPU维护独立统计副本，BPF程序只写本CPU副本，无锁无原子操作保证热点路径性能；用户态读取时遍历全部CPU做累加，得到全局统计；
* 8. raw tracepoint风险：raw_tp直接读取tracepoint原始args数组，内核升级如果修改tracepoint参数顺序，会导致解析错乱，需要同步适配下标。
*/

/*
内核内存分配事件（alloc 侧）
│
├─ 1. 具名 slab cache 分配 (kmem_cache_alloc / kmem_cache_alloc_node)
│   │  触发路径：通过具体 kmem_cache 对象分配（如 dentry, inode_cache 等）
│   │
│   ├── [主挂载点] raw_tp/kmem_cache_alloc
│   │   内核版本：5.x / 6.x 均存在
│   │   作用：
│   │     • 6.x：args[2] = kmem_cache *cachep → 按 cache 名称 + size 聚合
│   │     • 5.x：无 cache 指针 → 按大小降级聚合（SLAB_RATE_CACHE_SIZE）
│   │   覆盖范围：
│   │     • 5.x：覆盖非 NUMA 的 kmem_cache_alloc 调用
│   │     • 6.x：覆盖所有 kmem_cache_alloc（含 node 分配，因为 6.x 已将
│   │            kmem_cache_alloc_node 合并入此事件）
│   │
│   └── [辅助挂载点，仅旧内核] raw_tp/kmem_cache_alloc_node
│       内核版本：仅 5.x 存在（6.x 已移除）
│       作用：捕获 kmem_cache_alloc_node 的 NUMA 指定分配
│       聚合方式：无 cache 指针，一律降级为按大小聚合
│       注：用户态通过 attach 存在性探测，不存在则跳过，故不会在新内核加载失败
│
└─ 2. 通用 kmalloc 分配 (kmalloc / kmalloc_trace / kmalloc_node)
    │  触发路径：直接调用 kmalloc(size, flags) 等通用接口
    │
    ├── [主挂载点] tracepoint/kmem/kmalloc
    │   内核版本：5.x / 6.x 均存在（稳定 tracepoint）
    │   作用：按 bytes_alloc 大小档位聚合（SLAB_RATE_KMALLOC）
    │   覆盖范围：
    │     • 5.x：覆盖非 NUMA 的 kmalloc
    │     • 6.x：覆盖所有 kmalloc（含 kmalloc_node，6.x 已合并）
    │
    └── [辅助挂载点，仅旧内核] raw_tp/kmalloc_node
        内核版本：仅 5.x 存在（6.x 已移除）
        作用：捕获 kmalloc_node 的 NUMA 指定分配
        聚合方式：从 args[3] 取 bytes_alloc，按大小聚合
        注：同样通过可选 attach 兼容新内核
*/

#include <vmlinux.h>           /* CO-RE 所需的内核类型定义头文件，由 bpftool 生成 */
#include <bpf/bpf_core_read.h> /* BPF CO-RE 辅助读取宏，如 BPF_CORE_READ */
#include <bpf/bpf_helpers.h>   /* BPF 程序基础辅助函数定义 */
#include <bpf/bpf_tracing.h>   /* BPF tracing 相关辅助定义，如 bpf_raw_tracepoint_args */

#include "slab_rate.h"              /* 自定义结构体：SlabRate_ctrl, SlabRate_key, SlabRate_info, SlabRate_stats */
#include "common/pid_namespace.bpf.h" /* PID 命名空间转换辅助函数声明 */

/* BPF程序许可证，Dual BSD/GPL满足GPL兼容tracepoint挂载要求 */
char LICENSE[] SEC("license") = "Dual BSD/GPL";

/**
* @brief map数组固定下标0，ctrl_map、stats_map都是max_entries=1的PERCPU_ARRAY/ARRAY，只使用下标0。
* 定义为const变量，避免栈上分配，bpf_map_lookup_elem传入key的安全写法。
*/
static const bpf_u32_t zero_key = 0; /* 下标固定为0，作为查找单元素map的key */

/**
* @brief 控制参数MAP，普通ARRAY，全局唯一一份控制配置，由用户态写入。
* 用户态下发SlabRate_ctrl配置：采集开关、target_pid过滤、pid namespace转换参数。
* BPF侧通过get_ctrl()读取，所有tracepoint处理逻辑共享同一份配置。
*/
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);        /* 普通数组型map，全局共享，非per-CPU */
	__uint(max_entries, 1);                  /* 只有下标0一项 */
	__type(key, bpf_u32_t);                  /* key类型：u32 */
	__type(value, struct SlabRate_ctrl);    /* value类型：控制结构体 */
} ctrl_map SEC(".maps");

/*
* 每 CPU 独立累计同一个 cache 的计数。普通 HASH 的 vp->count++ 会让多个
* CPU 对同一 value 并发读改写并丢失增量；PERCPU_HASH 从根本上消除了这
* 个数据竞争，用户态读取时再把各 CPU 副本相加。
*
* @note PERCPU_HASH关键行为：
* 1. 每个CPU拥有独立hash表副本；BPF tracepoint运行在哪个CPU，就读写该CPU的副本；
* 2. BPF_NOEXIST标志：多CPU并发第一次遇到同一个key，只有一个CPU可以成功创建hash条目；其余CPU lookup查找已经存在的key，再做累加；
* 3. max_entries=SLAB_RATE_MAX_ENTRIes限制hash总key数量，防止内核不可换出内存无限膨胀；map满时map_update_failed统计计数+1；
* 4. BPF内核侧不会做自动GC，key常驻map，由用户态周期清空map做窗口采样。
*/
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);          /* 每CPU独立副本的hash map */
	__uint(max_entries, SLAB_RATE_MAX_ENTRIES);      /* 限制key总数，防止内存膨胀 */
	__type(key, struct SlabRate_key);                /* 聚合键：类型 + 分配大小/cache名称 */
	__type(value, struct SlabRate_info);             /* 统计值：计数 + 字节数 */
} slab_entries SEC(".maps");

/**
* @brief 模块自身健康状态统计MAP，PERCPU_ARRAY，每个CPU独立维护一份SlabRate_stats。
* 存放采集器自身运行指标：事件总数、分配失败数、PID过滤丢弃数、map满失败、读cache名称失败、内核降级计数。
* 用户态读取时聚合全部CPU副本，用于排查探针采集异常，不属于业务slab统计。
*/
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);   /* 每CPU独立副本的数组 */
	__uint(max_entries, 1);                    /* 只有一个元素，索引0 */
	__type(key, bpf_u32_t);                    /* key使用zero_key */
	__type(value, struct SlabRate_stats);      /* 统计结构体 */
} stats_map SEC(".maps");

/**
* @brief 获取用户态下发的全局控制配置。
* @return 返回ctrl_map[0]的指针；map查找失败返回NULL，此时直接丢弃本次tracepoint事件。
* @note __always_inline强制内联，消除函数调用开销，tracepoint热点路径要求。
*/
static __always_inline struct SlabRate_ctrl *get_ctrl(void)
{
	/* 使用zero_key查找唯一元素，返回其指针。若map不存在或未初始化则返回NULL */
	return bpf_map_lookup_elem(&ctrl_map, &zero_key);
}

/**
* @brief 获取当前CPU的健康统计结构体指针。
* @return stats_map[0] per‑cpu副本指针；失败返回NULL，此时不再更新统计指标。
*/
static __always_inline struct SlabRate_stats *get_stats(void)
{
	/* 查找当前CPU对应的stats_map[0]副本，若map创建失败等会返回NULL */
	return bpf_map_lookup_elem(&stats_map, &zero_key);
}

/*
* target_pid 表示“执行本次内核分配的 current 进程”，并不代表该对象最终
* 由谁持有。只有用户明确配置 -p 时才做 namespace 转换；全量模式保留
* 中断上下文和内核线程产生的分配事件。
*
* @param ctrl 用户态下发控制配置
* @param stats 当前CPU的统计结构体，过滤命中时更新filtered_pid计数器，可以传NULL
* @return true：匹配PID过滤规则，继续处理本次分配事件；false：不匹配，直接丢弃事件。
*
* @note 关键语义：
* 1. target_pid=0代表全量采集，直接返回true，不做PID校验；
* 2. app_current_pid_tgid_ns：把当前task的内核全局TGID，转换为工具所在PID namespace视角下的TGID；适配容器sidecar部署；
* 3. 中断上下文current是内核线程，同样参与判断；内核线程tgid为0；
* 4. 注意：是**分配发生时刻的current进程**，不是内存对象后续被哪个进程使用；slab对象可以跨进程生命周期。
*/
static __always_inline bool pid_matches(const struct SlabRate_ctrl *ctrl,
					struct SlabRate_stats *stats)
{
	bpf_u64_t pid_tgid;     /* 低32位为内核TGID，高32位为内核PID（线程ID），此处主要用TGID */
	bpf_u32_t tgid;

	/* target_pid为0代表全量采集，不进行PID过滤 */
	if (!ctrl->target_pid)
		return true;

	/* 
	* 获取当前进程在内核中的TGID，并转换为工具所在PID namespace下的TGID。
	* 若当前进程不在同一命名空间或转换失败，返回0。
	* pid_ns_dev/pid_ns_ino由用户态通过stat /proc/self/ns/pid获得。
	*/
	pid_tgid = app_current_pid_tgid_ns(ctrl->pid_ns_dev, ctrl->pid_ns_ino);
	tgid = pid_tgid >> 32;   /* 提取TGID */
	/* 若转换失败，或者转换后的TGID不等于目标PID，丢弃事件，同时递增过滤计数 */
	if (!pid_tgid || tgid != (bpf_u32_t)ctrl->target_pid) {
		if (stats)
			stats->filtered_pid++; /* 记录被PID过滤丢弃的事件数 */
		return false;
	}
	return true;
}

/*
* 将一次成功分配累计到当前 CPU 的 value。多个 CPU 首次看到同一 key 时
* 可能同时插入：BPF_NOEXIST 只允许一个创建成功，其余 CPU 随后重新 lookup
* 自己的 per‑CPU 副本即可，不会覆盖已经存在的累计值。
*
* @param key slab聚合键（具名cache / kmalloc档位 / size降级档位）
* @param bytes 本次分配对象slab槽字节大小
* @param stats 当前CPU统计结构体，用于记录map插入失败计数，可为NULL
*
* 执行流程：
* 1. lookup当前CPU副本中是否已经存在该key；
* 2. key不存在，使用zero空value + BPF_NOEXIST尝试插入；
* 3. 插入失败代表map已满，stats->map_update_failed自增，直接返回；
* 4. 拿到有效info指针后，本CPU副本count、allocated_bytes做自增累加。
*
* @warning PERCPU_HASH特性：只会修改当前运行CPU对应的value副本；其他CPU副本完全不受影响，需要用户态做全CPU聚合。
*/
static __always_inline void account_alloc(const struct SlabRate_key *key,
					bpf_u64_t bytes,
					struct SlabRate_stats *stats)
{
	struct SlabRate_info zero = {};   /* 用于初始化新条目的零值结构体 */
	struct SlabRate_info *info;

	/* 在当前CPU的hash副本中查找key对应的value */
	info = bpf_map_lookup_elem(&slab_entries, key);
	if (!info) {
		/* 
		* key不存在：尝试插入一个空计数的条目。
		* BPF_NOEXIST确保只有第一个插入的CPU成功，避免并发覆盖。
		* 其他CPU随后会通过自己的lookup拿到已存在的条目。
		*/
		bpf_map_update_elem(&slab_entries, key, &zero, BPF_NOEXIST);
		/* 重新查找，确保拿到刚插入或已存在的条目 */
		info = bpf_map_lookup_elem(&slab_entries, key);
		if (!info) {
			/* 
			* 如果更新后仍然查找失败，说明map已满（达到max_entries）或
			* 其他错误，此时记录失败计数并放弃本次累加。
			*/
			if (stats)
				stats->map_update_failed++;
			return;
		}
	}

	/* 
	* 累加：count自增1，allocated_bytes累加本次分配字节数。
	* 因为操作的是当前CPU的独立副本，无需加锁或原子操作。
	*/
	info->count++;
	info->allocated_bytes += bytes;
}

/*
* Linux 5.x 的 kmem_cache_alloc tracepoint 只给出 bytes_req/bytes_alloc，
* 没有 struct kmem_cache *。这种情况下仍可准确统计分配次数和字节数，只是
* 无法恢复 cache 名称，因此用 kmem_cache‑N 大小档位作为聚合键。
*
* @param bytes slab对象实际分配字节
* @param stats 当前CPU统计，size_fallback计数器+1，标记本次为降级路径
*
* 降级路径说明：内核版本不支持拿到struct kmem_cache*指针，无法读取cache名字；
* 聚合类型置SLAB_RATE_CACHE_SIZE，只按size聚合，用户态展示为cache‑size:N。
*/
static __always_inline void account_cache_size(bpf_u64_t bytes,
					struct SlabRate_stats *stats)
{
	struct SlabRate_key key = {};   /* 初始化key为全零 */

	key.kind = SLAB_RATE_CACHE_SIZE;   /* 标记为按大小降级聚合 */
	key.alloc_size = bytes;           /* 直接使用实际分配字节作为聚合键 */
	if (stats)
		stats->size_fallback++;      /* 记录降级次数，便于观察有多少事件走了降级路径 */
	/* 调用通用累加函数 */
	account_alloc(&key, bytes, stats);
}

/*
* 具名 cache 的标准 tracepoint format 没有 cache 指针，无法按名称聚合；
* raw tracepoint 参数依次为 call_site、ptr、cachep、gfp_flags、node。这里
* 读取 ptr 判断分配是否成功，再对 cachep‑>name/size 做 CO‑RE 字段读取。
*
* 注意：CO‑RE 只能适配 kmem_cache 字段偏移，不能适配 tracepoint 参数顺序。
* Linux 目标版本若改变该 tracepoint 原型，需要同步调整 args 下标。
*
* raw_tp/kmem_cache_alloc：捕获kmem_cache_alloc系列具名slab缓存分配事件
* 内核版本分支逻辑：
*  1. 旧内核5.x：trace_event_raw_kmem_cache_alloc没有accounted成员；args[2]/args[3]是bytes_req/bytes_alloc，没有cachep指针，走account_cache_size降级；
*  2. 新内核6.x+：存在accounted字段；args[2]为struct kmem_cache* cachep；读取cachep->name、cachep->size，使用SLAB_RATE_NAMED_CACHE按cache名称聚合。
*
* ctx->args[1] = ptr：分配返回对象指针；ptr==NULL代表分配失败，直接统计alloc_failed，不进入统计。
*/
SEC("raw_tp/kmem_cache_alloc")
int handle_kmem_cache_alloc(struct bpf_raw_tracepoint_args *ctx)
{
	struct SlabRate_stats *stats;
	struct SlabRate_ctrl *ctrl;
	struct SlabRate_key key = {};         /* 用于构建聚合键 */
	const void *ptr = (const void *)ctx->args[1]; /* 分配返回的对象指针，args[1]为ptr */
	struct kmem_cache *cachep;            /* 内核slab缓存描述符 */
	const char *name;                     /* 缓存名称字符串指针 */
	int name_len;                         /* 读取到的名称长度 */

	/* 读取全局控制配置，未开启采集直接返回 */
	ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	/* 获取当前CPU统计结构体（可能为NULL，后续判空使用） */
	stats = get_stats();
	if (stats)
		stats->events_seen++;   /* 每调用一次该tracepoint，总事件数+1 */

	/* ptr为NULL，slab分配失败，统计失败计数，直接退出 */
	if (!ptr) {
		if (stats)
			stats->alloc_failed++;
		return 0;
	}

	/* PID过滤校验，不匹配直接丢弃事件 */
	if (!pid_matches(ctrl, stats))
		return 0;

	/*
	* 6.x tracepoint raw 参数 #2 是 cachep；5.x 参数 #2/#3 分别是
	* bytes_req/bytes_alloc。accounted 字段与新原型一同出现，可作为
	* CO‑RE 特征判断，避免在旧内核把 bytes_req 错当成内核指针。
	* 
	* bpf_core_field_exists：编译时检测类型是否存在该字段。
	* 若accounted字段不存在，说明是5.x内核，走降级路径。
	*/
	if (!bpf_core_field_exists(
			((struct trace_event_raw_kmem_cache_alloc *)0)->accounted)) {
		/* 旧内核：直接将args[3] (bytes_alloc) 当作分配字节聚合 */
		account_cache_size(ctx->args[3], stats);
		return 0;
	}

	/* 新内核路径：拿到kmem_cache结构体指针，读取cache名称与对象size */
	cachep = (struct kmem_cache *)ctx->args[2]; /* args[2]即为cachep指针 */
	key.kind = SLAB_RATE_NAMED_CACHE;           /* 聚合类型为具名缓存 */
	key.alloc_size = BPF_CORE_READ(cachep, size); /* 通过CO-RE读取cache对象大小 */

	/* 读取缓存名字字符串的指针 */
	name = BPF_CORE_READ(cachep, name);
	/* 将内核空间的cache名称字符串安全拷贝到key.name缓冲区，返回实际拷贝长度（包含'\0'） */
	name_len = bpf_probe_read_kernel_str(key.name, sizeof(key.name), name);
	/*
	* name_len<=1代表读取失败或名字为空字符串。空字符串无聚合意义，
	* 统计name_read_failed，放弃本次事件统计。
	*/
	if (name_len <= 1) {
		if (stats)
			stats->name_read_failed++;
		return 0;
	}

	/* 使用构建好的key和读取到的size进行统计累加 */
	account_alloc(&key, key.alloc_size, stats);
	return 0;
}

/*
* Linux 5.x 为 NUMA node 分配保留独立的 kmem_cache_alloc_node 事件；6.x
* 已把 node 合入主事件。用户态把本程序设为手动可选 attach，目标事件不存在
* 时直接跳过，所以不会让新内核加载失败。
*
* raw_tp/kmem_cache_alloc_node：NUMA节点指定的具名slab分配；仅5.x内核存在独立tracepoint；
* 5.x该tracepoint raw参数没有输出struct kmem_cache*指针，只能拿到bytes_alloc，固定走size降级聚合路径。
* ctx->args[1]：分配返回对象指针，NULL代表分配失败。
*/
SEC("raw_tp/kmem_cache_alloc_node")
int handle_kmem_cache_alloc_node(struct bpf_raw_tracepoint_args *ctx)
{
	struct SlabRate_stats *stats;
	struct SlabRate_ctrl *ctrl;

	/* 检查是否启用采集 */
	ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	stats = get_stats();
	if (stats)
		stats->events_seen++; /* 事件计数 */

	/* 判断分配返回指针是否为空，分配失败计数 */
	if (!ctx->args[1]) {         /* args[1] 为 ptr */
		if (stats)
			stats->alloc_failed++;
		return 0;
	}

	/* PID过滤 */
	if (!pid_matches(ctrl, stats))
		return 0;

	/*
	* 5.x kmem_cache_alloc_node tracepoint无法拿到cache指针，只能按size降级聚合。
	* 5.x 原型：call_site, ptr, bytes_req, bytes_alloc, gfp_flags, node。
	* 此处args[3]为bytes_alloc。
	*/
	account_cache_size(ctx->args[3], stats);
	return 0;
}

/*
* kmalloc 与具名 kmem_cache 使用不同 tracepoint，不会重复统计。kmalloc 的
* 标准 tracepoint 已直接提供实际槽位大小 bytes_alloc，因此无需依赖内核
* 函数参数或私有结构；按大小档位聚合后由用户态显示为 kmalloc‑N。
*
* tracepoint/kmem/kmalloc：标准稳定tracepoint，捕获kmalloc/kmalloc_trace路径分配；
* 该tracepoint提供稳定结构体ctx，直接取ctx->bytes_alloc得到slab实际分配槽大小；
* 聚合类型SLAB_RATE_KMALLOC，用户态展示kmalloc‑${bytes_alloc}；
* ctx->ptr为NULL代表分配失败。
*/
SEC("tracepoint/kmem/kmalloc")
int handle_kmalloc(struct trace_event_raw_kmalloc *ctx)
{
	struct SlabRate_stats *stats;
	struct SlabRate_ctrl *ctrl;
	struct SlabRate_key key = {};

	/* 控制检查 */
	ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	stats = get_stats();
	if (stats)
		stats->events_seen++;

	/* 分配失败检查：标准tracepoint中ptr字段为NULL表示失败 */
	if (!ctx->ptr) {
		if (stats)
			stats->alloc_failed++;
		return 0;
	}

	/* PID过滤 */
	if (!pid_matches(ctrl, stats))
		return 0;

	/* 构建kmalloc聚合键：类型标记为KMALLOC，使用实际分配大小作为键值 */
	key.kind = SLAB_RATE_KMALLOC;
	key.alloc_size = ctx->bytes_alloc; /* 直接使用tracepoint提供的实际分配字节数 */
	account_alloc(&key, key.alloc_size, stats);
	return 0;
}

/*
* Linux 5.x 的 kmalloc_node 也是独立事件，由用户态按存在性可选 attach。
* raw_tp/kmalloc_node：NUMA指定node的kmalloc分配；5.x内核存在独立raw tracepoint；
* raw tracepoint拿不到稳定tracepoint结构体，直接读取args数组；args[1]=ptr，args[3]=bytes_alloc；
* 聚合类型SLAB_RATE_KMALLOC，按分配字节档位聚合。
* 用户态加载逻辑：探测tracepoint是否存在，不存在跳过attach，保证6.x内核加载不会报错。
*/
SEC("raw_tp/kmalloc_node")
int handle_kmalloc_node(struct bpf_raw_tracepoint_args *ctx)
{
	struct SlabRate_stats *stats;
	struct SlabRate_ctrl *ctrl;
	struct SlabRate_key key = {};

	ctrl = get_ctrl();
	if (!ctrl || !ctrl->enable)
		return 0;

	stats = get_stats();
	if (stats)
		stats->events_seen++;

	/* raw参数：args[1]为ptr，检查NULL */
	if (!ctx->args[1]) {
		if (stats)
			stats->alloc_failed++;
		return 0;
	}

	if (!pid_matches(ctrl, stats))
		return 0;

	/* 按kmalloc类型聚合，大小从args[3]获取（bytes_alloc） */
	key.kind = SLAB_RATE_KMALLOC;
	key.alloc_size = ctx->args[3];
	account_alloc(&key, key.alloc_size, stats);
	return 0;
}