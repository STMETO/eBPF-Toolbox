#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "dr_snoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// BPF哈希表，用于缓存 direct_reclaim_begin 事件上下文，实现begin/end事件配对
struct {
    __uint(type, BPF_MAP_TYPE_HASH);    // Map类型：哈希表，pid_tgid作为key快速查找
    __uint(max_entries, 256 * 1024);    // 最大存储256*1024=262144条并发回收事件，防止多进程同时进入回收时溢出丢数据
    __type(key, u64);                   // Key类型：u64，存放 bpf_get_current_pid_tgid()  高32bit = PID(进程ID)，低32bit = TID(线程ID)，唯一标识线程
    __type(value, struct val_t);        // Value类型：自定义val_t，保存回收开始时刻全量现场快照
} start SEC(".maps");            


// BPF环形缓冲区，内核侧高性能无锁buffer，专门向用户态推送监控事件
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);     // 类型：环形缓冲区，BPF推荐用于大批量事件上报，优于perf buffer
    __uint(max_entries, 256 * 1024);        // 缓冲区总大小 256*1024=256KB，内核与用户态共享一块环形内存
} rb SEC(".maps");


// BPF数组Map，全局单元素缓存，存放内核全局vm_stat结构体虚拟地址
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);   // Map类型：定长数组，访问O(1)，查找性能高于哈希
    __uint(max_entries, 1);             // 仅1个存储单元，只需要存一个全局vm_stat指针
    __type(key, u32);                   // 数组下标key固定为u32=0，唯一有效索引
    __type(value, u64);                 // Value：u64，存放内核vm_stat全局变量的虚拟地址（内核指针）
} vm_stat_map SEC(".maps");


// 适配tracepoint mm_vmscan_direct_reclaim_end的参数结构体，用于BPF CO-RE安全读取事件参数
struct trace_event_raw_mm_vmscan_direct_reclaim_end_template___x {
    long unsigned int nr_reclaimed;   // tracepoint原生参数：本次直接内存回收成功释放的页面数量
} __attribute__((preserve_access_index));




// 挂载到内核tracepoint埋点：vmscan模块-直接内存回收开始事件
SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin")
int trace_mm_vmscan_direct_reclaim_begin(void *ctx) {   // tracepoint钩子固定入参void *ctx，本埋点无需要读取的入参，ctx未使用
    struct val_t val = {};      // 定义本地临时变量val，存储本次direct reclaim开始时的现场快照
    u64 id = bpf_get_current_pid_tgid();    // 获取当前线程唯一标识：高32位PID，低32位TID，用作hash map的key
    u64 *vm_stat_addr;          // 指针，用来接收vm_stat_map中存储的内核全局vm_stat结构体虚拟地址
    __u32 key = 0;              // vm_stat_map是单元素ARRAY map，唯一下标固定为0，和用户态写入逻辑对齐

    // 捕获进程名、时间戳、整机内存快照等现场信息
    // bpf_get_current_comm：读取当前进程名称，存入val.name缓冲区
    // 返回0代表读取进程名成功，才继续保存快照到hash map
    if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
        val.id = id;    // 把当前线程pid_tgid存入快照结构体
        val.ts = bpf_ktime_get_ns();    // 获取内核单调时钟纳秒时间戳，记录回收开始时刻

        vm_stat_addr = bpf_map_lookup_elem(&vm_stat_map, &key);  // 从vm_stat_map数组map中查询下标0对应的元素
        // 判断是否成功拿到vm_stat全局变量地址（用户态初始化时写入）
        if (vm_stat_addr) {
            // *vm_stat_addr：内核vm_stat结构体的虚拟地址
            // bpf_probe_read_kernel：安全读取内核地址，拷贝整机内存统计数据到val.vm_stat
            bpf_probe_read_kernel(&val.vm_stat, sizeof(val.vm_stat), (const void *)*vm_stat_addr);
        } else {
            // map里没找到vm_stat地址，说明用户态初始化异常，打印内核日志
            bpf_printk("vm_stat address not found in map\n");
        }

        // 将当前线程的回收起始快照存入HASH表start
        // key=线程pid_tgid，value=val快照；BPF_ANY：存在则覆盖，不存在则新增
        bpf_map_update_elem(&start, &id, &val, BPF_ANY);
    }

    // eBPF tracepoint钩子返回0代表执行正常，无特殊返回码含义
    return 0;
}



// 挂载内核tracepoint：直接内存回收完成事件
SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_end")
int trace_mm_vmscan_direct_reclaim_end(void *ctx)
{
    // 1. 将void*类型的tracepoint上下文强转为自定义CO-RE模板结构体，读取本次回收产出页数
    struct trace_event_raw_mm_vmscan_direct_reclaim_end_template___x *args = ctx;

    // 获取当前线程唯一标识pid_tgid，和begin钩子使用同一个key用于事件配对
    u64 id = bpf_get_current_pid_tgid();
    // 指针：指向哈希表start中缓存的回收起始快照 val_t
    struct val_t *valp;
    // 指针：指向ringbuf中预分配的上报事件缓冲区 data_t
    struct data_t *data;
    // 获取回收结束时刻的内核单调时钟（纳秒），用于计算阻塞耗时
    u64 ts = bpf_ktime_get_ns();
    
    // 2. 根据当前线程id去哈希表查询回收开始时保存的现场快照
    valp = bpf_map_lookup_elem(&start, &id);
    // 找不到对应begin记录：说明事件丢失、map满覆盖、或者begin钩子执行失败
    if (!valp) {
        // id高32位是PID，打印日志用于排查丢事件问题
        bpf_printk("No start record found for PID %llu\n", id >> 32);
        return 0;
    }

    // 3. 从环形缓冲区rb中申请一块内存，存放要发给用户态的完整事件
    // 参数：ringbuf map、申请大小、flags=0
    data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
    // ringbuf已满，无法分配空间，事件直接丢弃
    if (!data) {
        bpf_printk("Failed to reserve space in ringbuf\n");
        return 0;
    }

    // 4. 填充上报事件data_t各个字段
    // 线程唯一id
    data->id = valp->id;
    // delta = 回收阻塞总耗时（单位ns），业务卡顿核心指标
    data->delta = ts - valp->ts;
    // 转换为微秒时间戳存入上报事件
    data->ts = ts / 1000;
    // 安全拷贝起始快照里保存的进程名到上报事件
    bpf_probe_read_kernel(&data->name, sizeof(data->name), valp->name);
    // 安全拷贝回收触发瞬间整机vm_stat内存统计快照
    bpf_probe_read_kernel(&data->vm_stat, sizeof(data->vm_stat), valp->vm_stat);
    // CO-RE安全读取tracepoint参数：本次回收成功释放的物理页面数量
    data->nr_reclaimed = BPF_CORE_READ(args, nr_reclaimed);

    // 5. 将组装完成的事件提交到ringbuf，用户态程序即可读取
    bpf_ringbuf_submit(data, 0);
    // 事件上报完成，删除哈希表中该线程的起始快照，释放map内存，避免泄漏
    bpf_map_delete_elem(&start, &id);
    
    // tracepoint钩子正常返回
    return 0;
}
