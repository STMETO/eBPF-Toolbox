/*
这套 BPF 程序是用户态堆内存 + 内核 Slab / 物理页 统一内存泄漏检测器：
通过 uprobe 监控 libc 分配 / 释放函数、tracepoint 监控内核 kmalloc/kfree/page_alloc 等内核内存操作；
用多组 BPF Map 缓存分配大小、临时指针、存活内存、调用栈、栈聚合统计；
分配时新增记录、释放时删除记录，最终allocs 中残留的 key 就是泄漏内存；
配套栈信息可以定位是哪一行代码 / 内核函数造成泄漏。
*/

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "mem_leak.h"

/**
 * @brief 全局可配置BPF变量，用于控制bpf_get_stackid采集堆栈行为
 * volatile 修饰：用户态可通过bpftool/libbpf动态下发修改值
 * 取值参考 bpf_get_stackid flag 宏(BPF_F_*)：
 *  BPF_F_SKIP_FIELD_MASK 跳过若干栈帧、BPF_F_USER_STACK仅采集用户栈、BPF_F_KERNEL_STACK仅内核栈等
 * 默认0：同时采集内核+用户完整调用栈
 */
 const volatile __u64 stack_flags = 0;

 
/**
 * @brief 临时缓存分配大小，分配入口与分配返回探针间传递size
 * key：pid_t 当前进程PID
 * value：u64 本次申请分配内存字节数
 * max_entries：10240 限制并发分配探针缓存上限，防止哈希膨胀
 * 使用流程：
 *  1. malloc/calloc/kmalloc等分配enter探针执行 gen_alloc_enter，写入当前pid与size
 *  2. retprobe/tracepoint分配返回时读取size，读取后立即删除本条记录
 *  3. realloc会先执行gen_free_enter释放旧指针，再写入新size到sizes
 */
 struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t); // pid
    __type(value, u64); // size for alloc
} sizes SEC(".maps");

 
/**
 * @brief 记录每一条活跃未释放的内存分配
 * key：u64 分配返回的内存虚拟地址(用户堆/内核slab/页PFN统一用u64存储)
 * value：struct alloc_info 单条分配详情：分配size + stack_traces栈ID
 * max_entries：ALLOCS_MAX_ENTRIES(1000000) 最大跟踪百万个未释放指针
 * 生命周期：
 *  alloc成功返回时插入；free/kfree/munmap释放时删除本条
 *  作用：标记哪些指针存在内存泄漏，关联对应调用栈
 */
 struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, ALLOCS_MAX_ENTRIES);
    __type(key, u64); /* alloc return address */
    __type(value, struct alloc_info);
} allocs SEC(".maps");


/**
相同调用栈分配出来的内存会聚合到一条 combined_allocs 记录
 * @brief 按堆栈ID聚合内存分配统计，泄漏分析核心表
 * key：u64 stack_id stack_traces堆栈映射ID
 * value：union combined_alloc_info 位域结构体
 *      total_size：该栈累计分配总字节
 *      number_of_allocs：该栈累计分配次数
 * max_entries：COMBINED_ALLOCS_MAX_ENTRIES(10240) 最多存储10240种不同调用栈
 * 逻辑：
 *  alloc：原子add 总size+分配次数+1
 *  free：原子sub 总size-分配次数-1
 *  用户态直接遍历此表，快速定位占用内存最高的泄漏调用栈
 */
 struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, COMBINED_ALLOCS_MAX_ENTRIES);
    __type(key, u64); /* stack id */
    __type(value, union combined_alloc_info);
} combined_allocs SEC(".maps");


/**
存储原始调用栈帧，用于还原泄漏代码位置
 * @brief BPF专用堆栈存储MAP，保存完整调用栈帧
 * 类型：BPF_MAP_TYPE_STACK_TRACE 内核专用栈存储map
 * key：u32 stack_id 栈唯一编号，bpf_get_stackid自动生成
 * value：内核自动存储栈帧数组(用户态创建时动态设置存储深度)
 * 说明：
 *  max_entries与value长度不在BPF代码静态定义，由用户态libbpf在memleak_bpf__open后动态配置
 *  bpf_get_stackid 采集栈时自动存入此map，返回stack_id供allocs/combined_allocs引用
 */
 struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    //__uint(max_entries, xxx); memleak_bpf__open 之后再动态设置
    __type(key, u32); /* stack id */
    //__type(value, xxx);       memleak_bpf__open 之后再动态设置
} stack_traces SEC(".maps");


/**
 * @brief 专门适配posix_memalign的临时缓存map
 * posix_memalign(void **memptr, size_t align, size_t size)特性：
 *  分配结果不通过返回值返回，而是写入传入的二级指针*memptr
 *  流程：
 *  1. enter探针：保存当前pid与用户态二级指针地址到memptrs
 *  2. retprobe探针：根据pid取出二级指针，bpf_probe_read_user读取真实分配内存地址
 * key：u64 当前进程PID
 * value：u64 用户态二级指针变量memptr的地址
 * max_entries：10240 限制并发posix_memalign调用缓存
 */
 struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64); // pid
    __type(value, u64); // 用户态指针变量 memptr
} memptrs SEC(".maps");


/**
 * @brief 记录每个内存地址的操作时间戳
 * key：u64 分配内存虚拟地址
 * value：u64 时间戳(单位ns)
 * 当前代码逻辑：alloc/free时统一置0，预留扩展能力：
 *  可扩展：记录首次分配时间、最后访问时间，计算泄漏时长
 */
 struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64); /* alloc return address */
    __type(value, u64); /* timestamp */
    __uint(max_entries, 10240);
} addr_times SEC(".maps");


/**
 * @brief 预留MAP，用于存储每个内存地址第一次分配的时间戳
 * 类型：HASH哈希表
 * key：u64 分配内存虚拟地址
 * value：u64 首次分配高精度时间戳
 * 当前代码未写入逻辑，为后续泄漏时长统计功能预留
 */
 struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64); /* alloc return address */
    __type(value, u64); /* timestamp */
    __uint(max_entries, 10240);
} first_time SEC(".maps");


char LICENSE[] SEC("license") = "Dual BSD/GPL";

/**
 * @brief 统一处理内存分配入口逻辑
 * @param size 本次申请分配的内存字节大小
 * @return int 固定返回0，BPF探针无错误返回逻辑
 * @desc
 * 1. 分配函数（malloc/calloc/kmalloc/mmap等）进入时触发
 * 2. 获取当前进程PID，将本次分配大小临时存入 sizes 哈希Map
 * 3. sizes 作为临时中转站：enter探针保存size，retprobe/tracepoint返回时读取size
 * 4. BPF_ANY：存在则覆盖，不存在则新增，适配并发分配场景
 */
 static int gen_alloc_enter(size_t size) {
    // 返回64位值：高32位PID，低32位TID
    const pid_t pid = bpf_get_current_pid_tgid() >> 32;

    // 以PID为key，本次分配size为value写入sizes临时哈希表
    // BPF_ANY：不管key是否存在，直接更新/插入
    bpf_map_update_elem(&sizes, &pid, &size, BPF_ANY);

    return 0;
}

/**
 * @brief 内存分配返回统一处理核心函数
 * @param ctx 探针上下文，uprobe/tracepoint传入，用于采集调用栈
 * @param address 本次分配成功返回的内存虚拟地址（用户堆指针 / 内核PFN）
 * @return int 固定返回0，BPF探针无异常抛出机制
 * @function
 * 1. 从临时map sizes取出本次分配大小，用完立即清理临时缓存
 * 2. 若分配地址有效（非0，分配成功）：
 *    ① 采集当前调用栈，获取stack_id存入alloc_info
 *    ② 将单条分配记录写入allocs哈希（key=内存地址，跟踪未释放内存）
 *    ③ 初始化该地址时间戳映射addr_times为0（预留泄漏时长统计）
 *    ④ 按stack_id聚合统计：总分配字节+分配次数+1，使用原子操作保证并发安全
 * @note
 * 复用给：用户态malloc/calloc/mmap等uretprobe、内核kmalloc/slab/page tracepoint
 */
 static int gen_alloc_exit2(void *ctx, u64 address) {
    // 分配返回的内存地址统一转为u64，兼容用户指针、内核PFN页号
    const u64 addr = (u64)address;
    // 获取当前进程PID，用于查询临时缓存sizes
    const pid_t pid = bpf_get_current_pid_tgid() >> 32;
    // 单条分配信息结构体：保存本次分配大小、对应堆栈ID
    struct alloc_info info;

    // 1. 查询临时哈希sizes，取出alloc入口探针暂存的分配size
    const u64 *size = bpf_map_lookup_elem(&sizes, &pid);
    // 异常分支：没找到对应size，说明分配流程异常，直接退出不记录
    if (NULL == size) {
        return 0;
    }

    // 清空alloc_info结构体，避免脏数据干扰
    __builtin_memset(&info, 0, sizeof(info));
    // 赋值本次分配字节大小
    info.size = *size;

    // 用完临时size，立刻删除sizes中当前pid的缓存，释放map空间
    bpf_map_delete_elem(&sizes, &pid);

    // 分配地址不为0代表分配成功，0为分配失败，无需记录
    if (0 != address) {
        // 采集当前调用栈，存入stack_traces栈map，返回唯一stack_id
        // stack_flags由用户态下发，控制是否采集用户栈/内核栈、跳过栈帧等
        info.stack_id = bpf_get_stackid(ctx, &stack_traces, stack_flags);

        // 将单条未释放内存记录写入allocs map
        // key=内存地址，value=分配大小+堆栈ID，free时通过addr删除本条
        bpf_map_update_elem(&allocs, &addr, &info, BPF_ANY);

        // 初始化该内存地址的时间戳为0，预留后续记录分配/释放时间、计算泄漏时长
        __u64 zero_ts = 0;
        bpf_map_update_elem(&addr_times, &addr, &zero_ts, BPF_ANY);

        // 构造本次分配的聚合增量：size累加1次分配
        union combined_alloc_info add_cinfo = {
            .total_size = info.size,
            .number_of_allocs = 1
        };

        // 根据堆栈ID查询聚合统计表combined_allocs
        union combined_alloc_info *exist_cinfo = bpf_map_lookup_elem(&combined_allocs, &info.stack_id);
        if (NULL == exist_cinfo) {
            // 该堆栈首次出现，插入新聚合记录，BPF_NOEXIST防止并发重复插入
            bpf_map_update_elem(&combined_allocs, &info.stack_id, &add_cinfo, BPF_NOEXIST);
        }
        else {
            // 该堆栈已有历史分配记录，原子叠加总size与分配次数
            // 直接操作联合体64位bits，位域会同步完成total_size、number_of_allocs自增
            __sync_fetch_and_add(&exist_cinfo->bits, add_cinfo.bits);
        }
    }

    return 0;
}


/**
 * @brief 通用分配返回探针包装函数，适配标准libc分配函数(无输出型参数)
 * @param ctx 探针寄存器上下文 pt_regs
 * @return int 转发 gen_alloc_exit2 的返回值
 * @desc
 * 1. PT_REGS_RC(ctx)：从当前CPU寄存器中读取函数返回值，也就是malloc/calloc/valloc等分配出来的内存指针
 * 2. 封装目的：统一提取返回地址，转发给底层通用处理函数 gen_alloc_exit2
 * 3. 适用场景：绝大多数标准分配接口，分配结果直接通过函数返回值带回
 */
 static int gen_alloc_exit(struct pt_regs *ctx) {
    // PT_REGS_RC(ctx) 获取分配函数返回的内存指针，作为第二个参数传给通用处理逻辑
    return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}


/**
 * @brief 统一处理内存释放入口逻辑，free/kfree/munmap 共用
 * @param address 待释放的内存虚拟地址（用户堆指针 / 内核页PFN）
 * @return int 固定返回0，BPF探针无错误抛出机制
 * @desc 对称于 gen_alloc_exit2 的反向统计逻辑：
 *  1. 根据释放地址查询单条分配记录 allocs
 *  2. 通过记录内的 stack_id 找到对应栈聚合统计 combined_allocs
 *  3. 原子扣减该栈的总占用内存、存活分配次数
 *  4. 删除 allocs 中该地址的记录（标记内存已释放，不再视为泄漏）
 *  5. 重置该地址时间戳映射 addr_times 为0，预留时长统计扩展
 */
 static int gen_free_enter(const void *address) {
    // 将释放地址统一转为64位无符号整数，兼容用户指针、内核PFN页号
    const u64 addr = (u64)address;

    // 1. 查询allocs表：查找该内存地址对应的分配记录（size + stack_id）
    const struct alloc_info *info = bpf_map_lookup_elem(&allocs, &addr);
    // 分支：没有这条分配记录，说明该内存从未被跟踪/已经释放，直接退出不处理
    if (NULL == info) {
        return 0;
    }

    // 2. 根据分配记录里的stack_id，查询该调用栈的聚合统计数据
    union combined_alloc_info *exist_cinfo = bpf_map_lookup_elem(&combined_allocs, &info->stack_id);
    // 分支：该栈无聚合统计数据，数据不一致，直接退出
    if (NULL == exist_cinfo) {
        return 0;
    }

    // 3. 构造释放减量：本次要扣除的内存大小、扣除1次分配计数
    // 和alloc时add_cinfo完全对称，alloc是加，free是减
    const union combined_alloc_info sub_cinfo = {
        .total_size = info->size,
        .number_of_allocs = 1
    };

    // 4. 原子减法：并发安全地从栈聚合统计中扣减size与分配次数
    // 联合体bits为完整64位整数，位域自动分别对40bit总大小、24bit次数做减法
    __sync_fetch_and_sub(&exist_cinfo->bits, sub_cinfo.bits);

    // 5. 删除allocs中该内存地址的记录
    // 关键：allocs里残留的条目 = 未释放泄漏内存；删除代表内存已归还
    bpf_map_delete_elem(&allocs, &addr);

    // 6. 重置该地址时间戳为0，预留后续记录释放时间、计算内存存活时长功能
    __u64 zero_ts = 0;
    bpf_map_update_elem(&addr_times, &addr, &zero_ts, BPF_ANY);

    return 0;
}


/**
 * @brief uprobe 挂钩 libc malloc 函数入口
 * SEC("uprobe")：标记为用户态静态探针，挂载在 malloc 函数开头
 * BPF_KPROBE：uprobe 入口探针宏，函数参数对应 malloc 入参 size_t size
 * @param size malloc 申请分配的字节大小
 * @return int 转发通用分配入口处理函数返回值
 * 执行时机：程序调用 malloc，刚进入函数内部，还未执行实际内存分配逻辑
 */
 SEC("uprobe")
 int BPF_KPROBE(malloc_enter, size_t size) {
     // 调用通用分配前置逻辑，把本次分配size存入sizes临时map
     return gen_alloc_enter(size);
 }
  
 /**
  * @brief uretprobe 挂钩 libc malloc 函数返回点
  * SEC("uretprobe")：用户态返回探针，malloc执行完毕、返回堆指针前触发
  * BPF_KRETPROBE：返回探针宏，内置ctx=pt_regs寄存器上下文
  * @return int 转发封装后的分配后置处理逻辑
  * 执行时机：malloc分配完成，即将把堆内存指针返回给调用方
  */
 SEC("uretprobe")
 int BPF_KRETPROBE(malloc_exit) {
     // gen_alloc_exit内部自动读取rax返回寄存器拿到分配地址，再调用gen_alloc_exit2做统计
     return gen_alloc_exit(ctx);
 }
 
 
/**
 * @brief 用户态free函数入口uprobe探针
 * SEC("uprobe")：挂载在libc free函数入口处的用户态探针
 * BPF_KPROBE：uprobe入口探针宏，参数自动匹配free的入参 void *address
 * @param address 待释放的堆内存指针，即free传入的内存地址
 * @return int 直接转发通用释放处理函数返回值
 * 触发时机：程序执行free(ptr)，刚进入free函数，还未执行内存回收逻辑
 */
 SEC("uprobe")
 int BPF_KPROBE(free_enter, void *address) {
     // 调用统一释放逻辑：查询分配记录、扣减栈聚合统计、删除存活内存记录
     return gen_free_enter(address);
 }
 

/**
 * @brief uprobe 挂钩 posix_memalign 函数入口
 * SEC("uprobe")：用户态入口探针，挂载libc posix_memalign符号开头
 * BPF_KPROBE：uprobe入口宏，参数完全匹配posix_memalign原型：
 * int posix_memalign(void **memptr, size_t alignment, size_t size);
 * @param memptr 二级输出指针，分配成功后内存地址会写入 *memptr
 * @param alignment 内存对齐字节数
 * @param size 待分配内存字节大小
 * @return int 转发通用分配前置处理函数返回值
 * @special 与malloc/calloc最大区别：分配结果不通过函数返回值带出，
 *          而是写入传入的二级指针*memptr，因此需要临时缓存memptr地址给retprobe读取
 */
 SEC("uprobe")
 int BPF_KPROBE(posix_memalign_enter, void **memptr, size_t alignment, size_t size) {
     // 将用户态二级指针 void** 强转为64位整型，存入map
     const u64 memptr64 = (u64)(size_t)memptr;
     // 获取当前进程PID，作为memptrs哈希表的key
     const u64 pid = bpf_get_current_pid_tgid() >> 32;
     // 临时存储当前进程对应的二级指针地址，供posix_memalign_exit返回探针读取
     bpf_map_update_elem(&memptrs, &pid, &memptr64, BPF_ANY);
 
     // 复用通用分配入口逻辑：将本次分配size存入sizes临时map
     return gen_alloc_enter(size);
 }
 
 
/**
 * @brief posix_memalign 返回钩子 uretprobe，配套 posix_memalign_enter 使用
 * SEC("uretprobe") 用户态函数返回探针，posix_memalign 执行完毕返回前触发
 * BPF_KRETPROBE 返回探针宏，内置上下文 ctx（pt_regs）
 * @desc
 * posix_memalign 特殊点：分配地址不从函数返回值带出，而是写入入参二级指针 **memptr；
 * enter 探针提前缓存了二级指针地址到 memptrs map，本函数取出该地址，
 * 调用 bpf_probe_read_user 读取用户空间拿到真实分配堆指针，再走统一分配后置逻辑 gen_alloc_exit2
 */
 SEC("uretprobe")
 int BPF_KRETPROBE(posix_memalign_exit) {
     // 获取当前进程PID，用于查询 enter 阶段缓存的二级指针
     const u64 pid = bpf_get_current_pid_tgid() >> 32;
     u64 *memptr64;
     void *addr;
 
     // 从memptrs临时哈希取出当前进程缓存的二级指针地址（void** memptr）
     memptr64 = bpf_map_lookup_elem(&memptrs, &pid);
     // 没有缓存记录，流程异常，直接退出不做统计
     if (!memptr64)
         return 0;
 
     // 读取完成，立刻清理memptrs中本条临时缓存，避免map残留脏数据
     bpf_map_delete_elem(&memptrs, &pid);
 
     /*
      * memptr64 存储的是用户态二级指针变量地址：void **memptr
      * *memptr64 = &buf；真实分配地址存在用户空间 *(&buf) 即 buf
      * bpf_probe_read_user：在内核BPF上下文读取用户空间内存，拿到分配出的堆指针addr
      * 读取失败（非法用户地址、权限问题）直接返回，放弃本次记录
      */
     if (bpf_probe_read_user(&addr, sizeof(void *), (void *)(size_t)*memptr64))
         return 0;
 
     // 将用户态指针统一转为64位无符号整数，适配gen_alloc_exit2入参
     const u64 addr64 = (u64)(size_t)addr;
 
     // 复用通用分配后置处理逻辑：采集栈、写入allocs、更新栈聚合统计
     return gen_alloc_exit2(ctx, addr64);
 }
 

/**
 * @brief uprobe 挂钩 libc calloc 函数入口
 * calloc 原型：void *calloc(size_t nmemb, size_t size);
 * @param nmemb 元素个数
 * @param size 单个元素字节大小
 * @desc 先计算总分配字节 = nmemb * size，再调用通用分配前置逻辑
 */
 SEC("uprobe")
 int BPF_KPROBE(calloc_enter, size_t nmemb, size_t size) {
     // calloc申请总内存 = 元素数量 × 单个元素大小
     return gen_alloc_enter(nmemb * size);
 }
  
 /**
  * @brief uretprobe 挂钩 calloc 返回点
  * calloc分配成功后会把堆指针通过函数返回值带出，和malloc一致
  * 直接复用通用封装函数，从寄存器读取返回地址
  */
 SEC("uretprobe")
 int BPF_KRETPROBE(calloc_exit) {
     return gen_alloc_exit(ctx);
 }
 
 
/**
 * @brief uprobe 挂钩 libc realloc 入口函数
 * realloc 原型：void *realloc(void *ptr, size_t size);
 * @param ptr 旧内存块指针，为NULL等价于malloc
 * @param size 新申请的内存总字节大小
 * @desc realloc 语义：释放旧内存，再分配一块新内存；
 *  探针模拟该行为：先执行释放统计，再执行新分配缓存
 */
 SEC("uprobe")
 int BPF_KPROBE(realloc_enter, void *ptr, size_t size) {
     // 1. 先处理旧指针：模拟realloc释放原有内存，扣减聚合统计、删除allocs旧记录
     gen_free_enter(ptr);
     // 2. 缓存新分配大小，供uretprobe拿到新地址后做分配统计
     return gen_alloc_enter(size);
 }
  
 /**
  * @brief uretprobe 挂钩 realloc 返回点
  * realloc 将新内存指针通过返回寄存器带出，和malloc/calloc逻辑一致
  * 复用通用封装函数读取返回地址，执行完整分配记录逻辑
  */
 SEC("uretprobe")
 int BPF_KRETPROBE(realloc_exit) {
     return gen_alloc_exit(ctx);
 }
 
 
/**
 * @brief uprobe 挂钩 libc mmap 入口函数
 * mmap 原型：void *mmap(void *address, size_t length, int prot, int flags, int fd, off_t offset);
 * @param address 用户期望映射的起始虚拟地址，一般传NULL由内核自动分配
 * @param size 要映射的内存字节长度
 * @desc mmap用于申请页对齐的内存（文件映射、匿名堆、大内存分配），属于分配行为，
 *  仅提取size存入临时sizes map，复用统一分配前置逻辑
 */
 SEC("uprobe")
 int BPF_KPROBE(mmap_enter, void *address, size_t size) {
     return gen_alloc_enter(size);
 }
 
 /**
  * @brief uretprobe 挂钩 mmap 返回点
  * mmap分配成功后，映射内存的起始虚拟地址作为函数返回值返回，
  * 和malloc/calloc/realloc逻辑完全一致，直接复用gen_alloc_exit读取寄存器返回地址
  */
 SEC("uretprobe")
 int BPF_KRETPROBE(mmap_exit) {
     return gen_alloc_exit(ctx);
 }
 
 /**
  * @brief uprobe 挂钩 libc munmap 入口函数
  * munmap原型：int munmap(void *addr, size_t length);
  * @param address 需要解除映射的内存起始虚拟地址
  * @desc munmap是mmap配套释放接口，传入待回收内存地址，直接调用统一释放统计逻辑
  * 无需uretprobe，入参直接携带内存地址，进入函数即可完成释放数据更新
  */
 SEC("uprobe")
 int BPF_KPROBE(munmap_enter, void *address) {
     return gen_free_enter(address);
 }
 
 
/**
 * @brief uprobe 挂钩 libc aligned_alloc 函数入口
 * aligned_alloc 标准原型：void *aligned_alloc(size_t alignment, size_t size);
 * @param alignment 内存对齐字节数
 * @param size 实际需要分配的内存总字节大小
 * @desc 仅关注有效分配字节size，忽略对齐参数，复用通用分配前置缓存逻辑
 */
 SEC("uprobe")
 int BPF_KPROBE(aligned_alloc_enter, size_t alignment, size_t size) {
     // 只需要分配字节数size存入sizes临时map，对齐参数不参与内存占用统计
     return gen_alloc_enter(size);
 }
  
 /**
  * @brief uretprobe 挂钩 aligned_alloc 返回点
  * aligned_alloc 分配成功后将对齐后的堆内存指针通过函数返回值返回，
  * 和malloc/calloc/mmap逻辑完全一致，直接使用封装函数读取寄存器地址
  */
 SEC("uretprobe")
 int BPF_KRETPROBE(aligned_alloc_exit) {
     return gen_alloc_exit(ctx);
 }
 
 
/**
 * @brief uprobe 挂钩 libc valloc 入口函数
 * valloc(size_t size)：按页大小对齐分配堆内存
 * @param size 待分配内存字节数
 * @desc 仅缓存分配大小到临时map，复用通用分配前置逻辑
 */
 SEC("uprobe")
 int BPF_KPROBE(valloc_enter, size_t size) {
     return gen_alloc_enter(size);
 }
 
 /**
  * @brief uretprobe 挂钩 valloc 返回点
  * valloc分配成功后内存指针通过寄存器返回，统一复用gen_alloc_exit读取返回地址
  */
 SEC("uretprobe")
 int BPF_KRETPROBE(valloc_exit) {
     return gen_alloc_exit(ctx);
 }
 
 /**
  * @brief uprobe 挂钩 libc memalign 入口函数
  * memalign(size_t alignment, size_t size)：自定义对齐分配堆内存
  * @param alignment 对齐字节数，仅用于地址排布，不参与内存占用统计
  * @param size 实际分配字节大小
  * @desc 忽略对齐参数，只将size存入sizes临时哈希
  */
 SEC("uprobe")
 int BPF_KPROBE(memalign_enter, size_t alignment, size_t size) {
     return gen_alloc_enter(size);
 }
 
 /**
  * @brief uretprobe 挂钩 memalign 返回点
  * 分配指针由函数返回值带出，复用统一分配后置处理封装函数
  */
 SEC("uretprobe")
 int BPF_KRETPROBE(memalign_exit) {
     return gen_alloc_exit(ctx);
 }
 
 /**
  * @brief uprobe 挂钩 libc pvalloc 入口函数
  * pvalloc(size_t size)：页对齐分配，向上取整到页大小
  * @param size 用户申请内存字节数
  * @desc 缓存用户传入size用于内存占用统计
  */
 SEC("uprobe")
 int BPF_KPROBE(pvalloc_enter, size_t size) {
     return gen_alloc_enter(size);
 }
 
 /**
  * @brief uretprobe 挂钩 pvalloc 返回点
  * 分配完成后堆指针存入返回寄存器，统一读取并执行分配统计逻辑
  */
 SEC("uretprobe")
 int BPF_KRETPROBE(pvalloc_exit) {
     return gen_alloc_exit(ctx);
 }
 
/////////////////////////////////////////////////////////////////////

/**
 * @brief CO-RE兼容层：kmem_alloc_node tracepoint 自定义包装结构体
 * @attribute preserve_access_index：开启CO-RE字段重定位，适配不同内核结构体偏移
 * 对应内核tracepoint：kmem/kmalloc_node
 * @ptr 内核分配出来的内存虚拟地址
 * @bytes_alloc 本次分配的内存字节大小
 */
 struct trace_event_raw_kmem_alloc_node___x {
	const void *ptr;
	size_t bytes_alloc;
} __attribute__((preserve_access_index));   // 关闭编译期硬编码偏移，开启 CO-RE 重定位

/**
 * @brief 判断当前内核是否存在 kmem_alloc_node tracepoint 类型
 * @return true 内核有该tracepoint，可正常读取；false 不存在，跳过对应探针逻辑
 * bpf_core_type_exists：CO-RE辅助函数，运行时检测内核是否存在该结构体定义
 */
static __always_inline bool has_kmem_alloc_node(void) {
    if (bpf_core_type_exists(struct trace_event_raw_kmem_alloc_node___x))
        return true;
    return false;
}

/**
 * @brief CO-RE兼容层：通用kmem_alloc tracepoint包装结构体
 * 部分新版内核统一使用 kmem_alloc 作为slab分配通用事件
 */
struct trace_event_raw_kmem_alloc___x {
	const void *ptr;
	size_t bytes_alloc;
} __attribute__((preserve_access_index));

/**
 * @brief CO-RE兼容层：老版本内核 kmalloc 专属tracepoint结构体
 * 旧内核单独提供 kmalloc 独立tracepoint，字段与kmem_alloc一致
 */
struct trace_event_raw_kmalloc___x {
	const void *ptr;
	size_t bytes_alloc;
} __attribute__((preserve_access_index));

/**
 * @brief CO-RE兼容层：kmem_cache_alloc slab缓存分配tracepoint结构体
 * 内核slab缓存分配事件，同样携带分配指针与分配字节数
 */
struct trace_event_raw_kmem_cache_alloc___x {
	const void *ptr;
	size_t bytes_alloc;
} __attribute__((preserve_access_index));

/**
 * @brief 判断当前内核是否存在通用 kmem_alloc tracepoint 类型
 * @return true=存在kmem_alloc事件，优先使用；false=回落使用旧kmalloc结构体
 */
static __always_inline bool has_kmem_alloc(void)
{
	if (bpf_core_type_exists(struct trace_event_raw_kmem_alloc___x))
		return true;
	return false;
}


/**
 * @brief tracepoint 捕获内核 kmalloc 内存分配事件
 * SEC("tracepoint/kmem/kmalloc")：挂载内核 kmalloc 静态跟踪点，内核每次执行kmalloc都会触发
 * @param ctx tracepoint 上下文指针，指向当前内核tracepoint原始事件结构体
 * @return int 固定返回0，BPF tracepoint无返回值业务逻辑
 * @feature CO-RE 多内核兼容：自动区分新旧内核tracepoint结构体，统一提取分配指针与分配大小
 * @reuse 完全复用用户态堆内存同一套统计逻辑 gen_alloc_enter / gen_alloc_exit2，统一管理内核slab内存泄漏
 */
 SEC("tracepoint/kmem/kmalloc")
 int memleak__kmalloc(void *ctx)
 {
     // 定义变量存储本次内核分配的内存地址、分配字节大小
     const void *ptr;
     size_t bytes_alloc;
 
     // CO-RE兼容判断：当前内核是否存在新版通用 kmem_alloc tracepoint
     if (has_kmem_alloc()) {
         // 新内核：使用通用kmem_alloc事件结构体解析上下文
         struct trace_event_raw_kmem_alloc___x *args = ctx;
         // BPF_CORE_READ：CO-RE安全读取结构体成员，自动适配内核结构体偏移
         ptr = BPF_CORE_READ(args, ptr);
         bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
     } else {
         // 旧内核：无kmem_alloc通用事件，回落使用老版本独立kmalloc结构体解析
         struct trace_event_raw_kmalloc___x *args = ctx;
         ptr = BPF_CORE_READ(args, ptr);
         bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
     }
 
     // 分配前置逻辑：将本次分配字节大小存入sizes临时map，与用户态malloc共用同一逻辑
     gen_alloc_enter(bytes_alloc);
 
     // 分配后置统一处理：传入tracepoint上下文、内核分配的虚拟地址
     // 内部完成：采集内核调用栈、写入allocs存活内存表、按stack_id聚合内存占用统计
     return gen_alloc_exit2(ctx, (u64)ptr);
 }
 

/**
 * @brief tracepoint 捕获内核 kmalloc_node NUMA节点内存分配事件
 * SEC("tracepoint/kmem/kmalloc_node")：内核静态跟踪点，调用kmalloc_node分配内存时触发
 * kmalloc_node：指定NUMA节点进行slab内存分配，多用于多CPU服务器内核内存申请
 * @param ctx tracepoint原始事件上下文，指向内核trace_event结构体
 * @return int BPF探针统一返回0
 * @compat CO-RE兼容：运行时检测当前内核是否存在kmalloc_node tracepoint，不存在则直接退出不处理
 * @reuse 与kmalloc探针逻辑完全对齐，复用同一套内存分配统计逻辑
 */
 SEC("tracepoint/kmem/kmalloc_node")
 int memleak__kmalloc_node(void *ctx)
 {
     // 存储本次NUMA节点分配的内核内存地址、分配字节大小
     const void *ptr;
     size_t bytes_alloc;
 
     // 运行时CO-RE检测：当前内核是否存在kmem_alloc_node事件结构体
     if (has_kmem_alloc_node()) {
         // 内核存在该tracepoint，使用预定义的CO-RE兼容结构体解析上下文
         struct trace_event_raw_kmem_alloc_node___x *args = ctx;
         // BPF_CORE_READ 安全跨内核读取字段，自动适配不同内核结构体偏移
         ptr = BPF_CORE_READ(args, ptr);
         bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
 
         // 通用分配前置逻辑：将分配大小存入sizes临时map
         gen_alloc_enter(bytes_alloc);
         // 通用分配后置处理：采集内核调用栈、写入存活内存记录、聚合栈占用统计
         return gen_alloc_exit2(ctx, (u64)ptr);
     } else {
         // 当前内核无kmalloc_node tracepoint，直接返回0，跳过统计逻辑
         // 注释说明：内核不存在该tracepoint时直接返回，消除未使用变量编译告警
         /* tracepoint is disabled if not exist, avoid compile warning */
         return 0;
     }
 }
 

struct trace_event_raw_kmem_free___x {
	const void *ptr;
} __attribute__((preserve_access_index));

struct trace_event_raw_kfree___x {
	const void *ptr;
} __attribute__((preserve_access_index));

struct trace_event_raw_kmem_cache_free___x {
	const void *ptr;
} __attribute__((preserve_access_index));

static __always_inline bool has_kfree()
{
	if (bpf_core_type_exists(struct trace_event_raw_kfree___x))
		return true;
	return false;
}

static __always_inline bool has_kmem_cache_free()
{
	if (bpf_core_type_exists(struct trace_event_raw_kmem_cache_free___x))
		return true;
	return false;
}

SEC("tracepoint/kmem/kfree")
int memleak__kfree(void *ctx)
{
	const void *ptr;

	if (has_kfree()) {
		struct trace_event_raw_kfree___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	} else {
		struct trace_event_raw_kmem_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	}

	return gen_free_enter(ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc")
int memleak__kmem_cache_alloc(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc()) {
		struct trace_event_raw_kmem_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	} else {
		struct trace_event_raw_kmem_cache_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	}

	gen_alloc_enter(bytes_alloc);

	return gen_alloc_exit2(ctx, (u64)ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc_node")
int memleak__kmem_cache_alloc_node(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc_node()) {
		struct trace_event_raw_kmem_alloc_node___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

		gen_alloc_enter(bytes_alloc);

		return gen_alloc_exit2(ctx, (u64)ptr);
	} else {
		/* tracepoint is disabled if not exist, avoid compile warning */
		return 0;
	}
}

SEC("tracepoint/kmem/kmem_cache_free")
int memleak__kmem_cache_free(void *ctx)
{
	const void *ptr;

	if (has_kmem_cache_free()) {
		struct trace_event_raw_kmem_cache_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	} else {
		struct trace_event_raw_kmem_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	}

	return gen_free_enter(ptr);
}

/**
 * @brief tracepoint 捕获内核页分配 mm_page_alloc
 * SEC("tracepoint/kmem/mm_page_alloc")：内核分配物理页时触发
 * @param ctx tracepoint原始事件结构体，直接使用vmlinux原生类型，未做CO-RE兼容封装
 * @desc
 * order：页阶，一页默认4KB，实际分配字节 = 4096 << order
 * pfn：物理页帧号，统一作为内存唯一标识存入allocs map
 */
 SEC("tracepoint/kmem/mm_page_alloc")
 int memleak__mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
 {
     // 计算本次分配总字节：单页4096字节，order代表连续2^order个物理页
     gen_alloc_enter(4096 << ctx->order);
     // 把pfn物理页号作为地址传入通用分配统计逻辑
     return gen_alloc_exit2(ctx, ctx->pfn);
 }
 
 /**
  * @brief tracepoint 捕获内核页释放 mm_page_free
  * @param ctx tracepoint页释放事件结构体
  * @desc 取出pfn物理页号，强转指针后调用统一释放逻辑
  */
 SEC("tracepoint/kmem/mm_page_free")
 int memleak__mm_page_free(struct trace_event_raw_mm_page_free *ctx)
 {
     return gen_free_enter((void *)ctx->pfn);
 }
 