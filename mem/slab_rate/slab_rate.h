#ifndef __SLAB_RATE_H
#define __SLAB_RATE_H

#include "common/types.h"

/*
 * Linux 中实际的 slab cache 数量通常只有数百个。这里给不同名称的 cache
 * 和 kmalloc 大小档位留出足够空间，同时用有限上界避免异常场景无限占用
 * 不可换出的 BPF Map 内存。
 */
#define SLAB_RATE_MAX_ENTRIES 1024
#define CACHE_NAME_SIZE 48

/**
 * @brief slab分配事件分类枚举
 * SLAB_RATE_NAMED_CACHE：内核自定义命名slab缓存，如task_struct、inode等专用cache
 * SLAB_RATE_KMALLOC：kmalloc系列接口分配，无固定cache名称，按分配字节大小聚合
 * SLAB_RATE_CACHE_SIZE：按slab对象实际size聚合（旧内核兼容降级路径使用）
 */
enum SlabRate_kind {
	SLAB_RATE_NAMED_CACHE = 0,
	SLAB_RATE_KMALLOC = 1,
	SLAB_RATE_CACHE_SIZE = 2,
};

/**
 * slab_entries 的聚合键。
 *
 * 具名 slab 以 cache 名称和实际槽位大小聚合；kmalloc tracepoint 不提供
 * cache 名称，因此按 bytes_alloc 大小档位聚合，用户态显示为 kmalloc‑N。
 * 整个结构在 BPF 侧先清零，padding 也保持确定值，避免哈希键不稳定。
 *
 * @note BPF hashmap做key匹配时，会对比整个结构体全部字节；padding必须置零，
 *       否则栈上残留垃圾数据将导致相同业务key生成不同hash条目，统计重复错乱。
 * @field alloc_size slab对象单对象字节大小；kmalloc场景为申请字节数，named cache为对象槽大小
 * @field kind 枚举SlabRate_kind，区分分配来源类型：具名cache / kmalloc / size降级模式
 * @field padding[7] 补齐对齐填充字节，让结构体整体8字节对齐，消除hash key随机垃圾字节
 * @field name[CACHE_NAME_SIZE] slab cache名字；kmalloc模式下该字段置空字符串
 */
struct SlabRate_key {
	bpf_u64_t alloc_size;
	bpf_u8_t kind;
	bpf_u8_t padding[7];
	char name[CACHE_NAME_SIZE];
};

/** 用户态下发的运行配置。
 * 该结构体通过BPF map从用户态下发至内核BPF程序，动态控制采集开关、PID过滤、PID命名空间转换。
 * @field enable true才采集分配事件；false直接丢弃所有slab tracepoint事件，关闭采集
 * @field target_pid 0=全量；非0=按分配时 current TGID 过滤；注意：是分配发生时刻的当前进程TGID，不是内存归属进程
 * @field pid_ns_dev 工具所在 PID namespace 的设备号，用于将内核内部pid namespace的tgid转换为工具所在命名空间的PID
 * @field pid_ns_ino 工具所在 PID namespace 的 inode，配合pid_ns_dev完成PID命名空间转换逻辑
 */
struct SlabRate_ctrl {
	bpf_bool_t enable;       // true 才采集分配事件
	bpf_s32_t target_pid;    // 0=全量；非0=按分配时 current TGID 过滤
	bpf_u64_t pid_ns_dev;    // 工具所在 PID namespace 的设备号
	bpf_u64_t pid_ns_ino;    // 工具所在 PID namespace 的 inode
};

/**
 * 单个聚合键的累计计数。Map 使用 PERCPU_HASH，每个 CPU 独立自增，用户态
 * 定时合并所有 CPU 的值，因此热分配路径上没有共享 value 的写竞争。
 *
 * @note PERCPU_HASH：每个CPU拥有独立value副本；BPF程序中各个CPU只写自己副本，无锁无原子操作，分配热点路径性能高。
 * 用户态读取时遍历全部CPU副本，累加得到全局统计值。
 * @field count 成功分配对象的累计次数；仅统计分配成功返回有效对象指针的事件，失败分配不计入
 * @field allocated_bytes 成功分配的累计槽位字节数；对象实际slab槽大小，不是用户申请size，包含slab内部对齐padding
 */
struct SlabRate_info {
	bpf_u64_t count;             // 成功分配对象的累计次数
	bpf_u64_t allocated_bytes;   // 成功分配的累计槽位字节数
};

/** 模块健康统计，同样使用 PERCPU_ARRAY 避免跨 CPU 竞争。
 * 存放模块自身运行状态指标，用于排查采集异常，不存放业务slab统计；
 * PERCPU_ARRAY保证tracepoint热点路径写操作无锁竞争。
 * @field events_seen 两类 tracepoint 收到的事件数：kmem_alloc / kmem_cache_alloc 触发总事件，包含被过滤、失败的事件
 * @field alloc_failed tracepoint 中返回指针为空的分配次数，slab分配失败，返回NULL
 * @field filtered_pid 未匹配 target_pid 的事件数，PID过滤规则丢弃的事件计数
 * @field map_update_failed 聚合键插入失败，通常表示 Map 已满，SLAB_RATE_MAX_ENTRIES达到上限
 * @field name_read_failed 无法读取具名 cache 名称的次数，bpf_core_read读取cache->name失败，内核结构体偏移异常或者内存非法
 * @field size_fallback 旧内核无 cache 指针，退化为大小档位的次数，内核版本过低无法拿到slab_cache指针，降级仅按size聚合
 */
struct SlabRate_stats {
	bpf_u64_t events_seen;       // 两类 tracepoint 收到的事件数
	bpf_u64_t alloc_failed;      // tracepoint 中返回指针为空的分配次数
	bpf_u64_t filtered_pid;      // 未匹配 target_pid 的事件数
	bpf_u64_t map_update_failed; // 聚合键插入失败，通常表示 Map 已满
	bpf_u64_t name_read_failed;  // 无法读取具名 cache 名称的次数
	bpf_u64_t size_fallback;     // 旧内核无 cache 指针，退化为大小档位的次数
};

#ifndef __BPF__
#include <stdbool.h>

/**
 * 启动内核 slab 分配速率监控。
 * @param poll_timeout_ms 输出采样窗口，单位毫秒
 * @param enable 是否启用采集
 * @param target_pid 分配发生时 current 进程的 TGID；0 表示全量
 * @param min_delay_ns 兼容统一模块接口；速率模块没有延迟语义，会忽略此值
 * @return int 0成功，负数为负errno错误码，代表bpf加载、map初始化失败
 * @note 该接口为用户态侧API；负责加载BPF字节码、初始化控制map、启动轮询读取per‑cpu统计，定时输出slab分配速率统计。
 */
int slab_rate_run(int poll_timeout_ms, bool enable, bpf_s32_t target_pid,
		  bpf_u64_t min_delay_ns);
#endif

#endif
