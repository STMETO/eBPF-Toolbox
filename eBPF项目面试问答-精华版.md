# eBPF 项目面试问答（精华版）

> 面试设定：面试官只能看到简历项目描述，候选人可以结合自己的源码回答。
>
> 本文只围绕简历中的五类代表模块：调度延迟、mutex 锁竞争、openat 文件 I/O、TCP 网络监控、direct reclaim 内存监控。答案以当前仓库实现为准，同时坦诚说明代码现状与简历表述之间的差距。

## 一、项目总览

### 1. 面试官：先用两分钟介绍一下这个项目。

**面试官关注：**候选人能否先讲业务问题，再讲技术方案，而不是罗列技术名词。

**我的回答：**

这个项目是一个面向 Linux 线上性能排障的 eBPF 观测工具。它主要解决一个问题：当接口出现长尾延迟时，传统应用日志只能说明请求慢了，却很难判断时间消耗在调度、锁、文件系统、网络还是内存回收。我把这些问题拆成五类代表模块，在相应的内核路径采集事件和延迟，再将慢事件发送到用户态。

整体链路分为三层。第一层是 BPF 程序，通过 tracepoint、tp_btf、kprobe/kretprobe 和 fentry 采集内核事件；第二层是 Map，分别承担运行开关、入口/出口上下文关联、统计聚合和 ringbuf 事件传输；第三层是 libbpf 用户态框架，负责加载 skeleton、写控制参数、attach 探针、轮询事件以及退出时读取统计。

我在设计上尽量把过滤放在内核侧，例如按 PID 和最小延迟阈值丢弃无关的高频短事件，避免所有事件都进入用户态。不过当前代码仍是项目原型，有些模块已经完整实现过滤和统计，有些模块还只实现了采集主链路。面试中我会把已实现能力与后续改进分开说明。

### 2. 面试官：这五个模块为什么能帮助定位长尾延迟？

**面试官关注：**五个模块是否只是功能堆砌，还是形成了可解释的排障体系。

**我的回答：**

这五类问题对应线上延迟的不同来源：调度模块观察线程有没有及时获得 CPU；锁模块观察线程是否因内核 mutex 竞争而阻塞；openat 模块观察文件打开事件和失败情况；TCP 模块观察建连、重传和关闭；direct reclaim 模块观察业务线程是否同步参与内存回收。

真正排障时不能只看一个模块。例如一次文件操作很慢，可能并不是存储设备慢，而是执行 openat 的线程长时间没有获得 CPU，或者触发了直接内存回收。因此事件应携带统一的时间戳、TGID/TID、进程名和 CPU 等字段，用户态再按线程和时间窗口进行关联。这才是“慢在内核哪条路径”的含义。

当前统一入口通过 `MODULE_TABLE` 和相同的 `run(timeout, enable, pid, delay)` 函数签名管理模块。不过当前命令行一次只执行一个 `-m`，还没有真正实现多个模块同时加载后的时间线关联。所以简历里的“组合式观测”属于目标设计，若保持现有代码，我会把它改成“支持统一入口下的模块化观测”。

### 3. 面试官：五个模块的内核态与用户态是如何解耦的？

**面试官关注：**候选人是否理解项目架构，而不只是会写一个 BPF demo。

**我的回答：**

每个模块由 BPF 程序、用户态程序和共享事件头文件组成。共享头文件定义控制结构、ringbuf 事件结构和统计结构，保证内核态与用户态使用相同的二进制布局。BPF 程序只负责采集、过滤、关联和聚合，不负责复杂格式化；用户态通过 skeleton 访问 Map 和 program，负责配置、输出及资源管理。

构建系统使用 clang 将每个 `.bpf.c` 编译为 BPF ELF，再用 bpftool 生成 skeleton；普通 C 编译器编译各模块的 `user.c`，最后链接 libbpf。Makefile 会自动扫描模块源码，因此新增目录后不需要手写每个编译目标；但仍然要在公共枚举和 `MODULE_TABLE` 中注册模块。

这种结构的好处是模块之间不直接依赖，公共入口只依赖统一的 `run_fn`。不足是目前每个模块仍重复编写了 open/load、ringbuf、signal 和 cleanup 逻辑，后续可以抽成统一的 module runtime。

### 4. 面试官：你说支持启停和组合观测，代码中具体怎么实现？

**面试官关注：**验证简历中的工程能力是否真实。

**我的回答：**

当前模块启停有两个层次。启动时由 `-m` 选择一个模块；模块内部再把 `enable` 写入单元素 `ctrl_map`，BPF 程序每次触发时先检查开关，关闭后快速返回。这种方式修改配置成本低，但探针仍然处于 attach 状态，所以它是逻辑停用，不是完全卸载。

当前代码的组合观测还不完整，因为 `main()` 只找到并运行一个模块，事件循环也是单模块 ringbuf。真正实现组合观测时，我会允许 `-m context,mutexlock,tcp_monitor` 这样的模块集合，为每个 skeleton 管理独立 bpf_link，并用统一 epoll/ring-buffer manager 消费事件；同时定义公共事件头，使不同模块事件能按单调时间排序。

另外，五个模块对 `enable` 的接入并不完全一致。例如调度、mutex、openat 和 TCP 使用了 `ctrl_map`，而 direct reclaim 用户态虽然构造了 `DrSnoop_ctrl`，BPF 侧并没有相应控制 Map。因此面试时我不会说所有模块已经完整支持动态启停，而会说明这是当前待统一的部分。

## 二、调度延迟模块

### 5. 面试官：你的调度延迟是怎么定义和计算的？

**面试官关注：**能否区分 run-queue latency、上下文切换耗时和调度器执行耗时。

**我的回答：**

当前代码在 `tp_btf/sched_switch` 触发时记录时间及 prev/next 任务信息，再在 `finish_task_switch.isra.0` 的 kprobe 中计算时间差。中间状态保存在 key 为 0 的 `PERCPU_ARRAY` 中，因为这一对事件属于同一 CPU 的切换路径。输出事件包含 prev/next 的 PID、TGID、comm、优先级、任务状态、CPU 和是否抢占。

但我需要准确说明：当前测量值更接近从 `sched_switch` tracepoint 到 `finish_task_switch` 探针位置的上下文切换路径耗时，并不是严格的“任务从 runnable 到真正上 CPU”的调度等待时间。若要测 run-queue latency，我会在 `sched_wakeup/sched_wakeup_new` 记录目标 TID 的唤醒时间，在该 TID 成为 `sched_switch` 的 next 时结算，使用 TID HASH 而不是 per-CPU 槽。

所以当前简历中的“调度等待”表述偏强。要么补上 wakeup-to-switch-in 逻辑，要么把简历改为“上下文切换路径延迟”。这是我会主动向面试官说明的边界。

### 6. 面试官：为什么这里选 PERCPU_ARRAY？它真的消除了竞态吗？

**面试官关注：**是否真正理解 per-CPU Map 的适用边界。

**我的回答：**

调度模块的 `start_map` 每个 CPU 只有一份当前切换快照。不同 CPU 同时发生调度时，各自写自己的 value，不会覆盖其他 CPU，因此不需要全局锁，也减少了共享缓存行竞争。`sched_switch` 和 `finish_task_switch` 都位于同一次 CPU 切换路径中，所以这里采用 per-CPU 临时槽是有依据的。

不过“PERCPU_ARRAY 消除多核竞态”只能限定在这个临时 Map。模块的 `stats_map` 是普通单元素 ARRAY，多个 CPU 同时执行 `count++`、`total_ns += delay` 或更新最大值时仍可能丢更新，最大延迟和对应进程字段也可能不一致。

更完整的实现应将统计改成 `PERCPU_ARRAY`，退出时用户态遍历所有 possible CPU 并合并 count、total 和 max。这样既避免热点路径上的锁，也能保证统计准确性。

### 7. 面试官：这个调度探针在不同内核上稳定吗？

**面试官关注：**候选人是否理解 CO-RE 不能解决所有兼容问题。

**我的回答：**

`tp_btf/sched_switch` 依赖目标内核 BTF，而 `finish_task_switch.isra.0` 的风险更大：`.isra.0` 是编译器优化产生的符号后缀，可能随内核版本、编译器和配置变化。有的内核可能只有 `finish_task_switch`，也可能出现其他后缀，导致 skeleton attach 失败。

CO-RE 能解决 `task_struct` 字段偏移变化，但不能解决函数符号不存在。工程上我会在启动时做 capability probe，优先使用稳定 tracepoint；若必须使用 kprobe，则从多个候选符号中选择实际存在的一个，并把 attach 失败原因明确返回给用户。

## 三、mutex 锁竞争模块

### 8. 面试官：锁竞争模块如何区分“获取锁”和“发生竞争”？

**面试官关注：**是否理解 mutex fastpath/slowpath，而非看见 `mutex_lock` 就认为发生竞争。

**我的回答：**

我同时观察了 `mutex_lock`、`mutex_unlock` 和 `__mutex_lock_slowpath`。进入 `mutex_lock` 只表示线程尝试获取内核 mutex，不一定发生竞争；真正进入 `__mutex_lock_slowpath` 才说明没有直接走完快路径，需要进入等待逻辑。

当前代码在 slowpath 的 kprobe 中记录锁地址、竞争者、owner、双方优先级和开始时间，在 kretprobe 中计算 `contention_ns`。低于 `min_delay_ns` 的等待在内核中直接丢弃，超过阈值才 reserve ringbuf 并发送事件。锁地址作为 `kmutex_map` key，用于维护同一把内核 mutex 的统计信息。

这个模块监控的是内核 `struct mutex`，不是用户态 `pthread_mutex_t`。如果要监控应用 pthread 锁，应使用 uprobe/uretprobe 观察 libc，或者观察竞争后进入的 futex 路径。

### 9. 面试官：如何得到 owner？这个值一定可靠吗？

**面试官关注：**是否理解内核结构字段、标志位和 CO-RE 读取。

**我的回答：**

代码读取 `lock->owner`，去掉低位标志后将其解释为 `task_struct *`，再读取 owner 的 PID、comm 和 prio。竞争者则来自当前任务。这样用户态可以看到“谁持有锁、谁在等待、等待了多久”。

当前实现只用 `owner & ~0x1L` 清理最低一位，但 Linux mutex owner 的低位可能包含 WAITERS、HANDOFF、PICKUP 等多个标志。更稳妥的实现应按目标内核定义清除完整 `MUTEX_FLAGS`，并对 owner 为空或字段读取失败做标记。

另外，owner 信息只是进入 slowpath 时的快照。等待过程中 owner 可能发生变化，因此它适合帮助定位，但不能被解释为整个等待期间唯一的持有者。

### 10. 面试官：你测到的是等待时间还是持锁时间？

**面试官关注：**延迟区间定义是否准确。

**我的回答：**

slowpath 入口到返回的 `contention_ns` 是竞争者的慢路径耗时，可近似看作等待获取锁的时间。代码还尝试在 `mutex_lock` 入口记录 `acquire_time`，在 `mutex_unlock` 计算 `held`，但这个值不能严格叫持锁时间，因为竞争线程进入 `mutex_lock` 时可能还没有获得锁，等待时间也会被算进去。

如果要准确测持有时间，起点必须放在确认锁已成功获得之后，终点放在 unlock；等待时间则单独从 slowpath 入口到成功获取。两套状态应分开维护。当前用户态最终只打印 `contention_count`，共享头中虽然定义了 total/max 持锁统计字段，但 BPF 侧没有完整更新它们。

### 11. 面试官：锁模块还有哪些并发或关联问题？

**面试官关注：**候选人是否能审视自己的代码，而不是只讲理想设计。

**我的回答：**

第一，slowpath 上下文使用固定 key 的 `PERCPU_ARRAY`。如果函数执行期间任务迁移 CPU，kretprobe 可能读不到入口 CPU 的数据；更稳妥的是使用 `pid_tgid` HASH，并在返回后删除。第二，代码把 `bpf_get_current_pid_tgid()` 直接截断到 32 位变量，得到的是低 32 位 TID，但命名为 PID；如果命令行 `target_pid` 传入 TGID，多线程进程会过滤错误。

第三，多个 CPU 可能更新同一个锁地址对应的普通 HASH value，`locked_total += held` 和 max 更新并非天然原子。可使用 per-CPU 聚合，或在 value 中加入 `bpf_spin_lock` 保护复合字段。第四，锁对象释放后地址可能复用，长期运行时要设计淘汰或生命周期清理。

这些问题不会否定 slowpath 观测思路，但说明当前版本更适合作为诊断原型，若长期线上运行还需补强数据一致性。

## 四、openat 文件 I/O 模块

### 12. 面试官：openat 模块如何关联入口和出口？

**面试官关注：**是否理解系统调用成对探针与线程并发。

**我的回答：**

模块使用 `syscalls/sys_enter_openat` 和 `sys_exit_openat` tracepoint。入口从 `bpf_get_current_pid_tgid()` 取低 32 位 TID 作为 HASH key，保存 TGID 和用户传入的 pathname；出口用相同 TID 查询，读取返回值和 comm，组装事件后删除条目。

这里选择 TID 而不是 TGID，是因为同一进程的多个线程可以同时调用 openat，使用 TGID 会互相覆盖。pathname 是用户空间指针，代码使用 `bpf_probe_read_user_str()` 有界读取 256 字节，符合用户内存读取语义。

异常路径也要清理：PID 不匹配或 ringbuf reserve 失败时，代码都会删除 `tid_map` 条目，避免 HASH 持续增长。仍应增加 map update failure 和 lookup miss 计数，才能判断事件是否完整。

### 13. 面试官：你说监控文件 I/O 延迟，openat 能代表文件 I/O 吗？

**面试官关注：**能否区分文件打开、文件系统路径和块设备 I/O。

**我的回答：**

openat 只能观察文件打开路径，它包含路径解析、dentry/inode 查找、权限检查和文件系统锁等，不等于 read/write 数据 I/O，更不等于块设备服务时间。openat 慢也未必是磁盘慢，例如网络文件系统、目录锁或线程调度都可能造成延迟。

因此如果简历只保留这个代表模块，我会写“文件打开事件监控”，而不是笼统写“文件 I/O 延迟”。若要完整定位文件 I/O，需要再把 syscall latency 与 block request 的排队和完成事件关联起来。

此外，openat 失败时内核返回负 errno。当前代码把所有失败统一转换为 fd=-1，丢失了具体错误原因；更合理的是原样保留 `ret`，用户态区分 ENOENT、EACCES 等错误热点。

### 14. 面试官：代码真的计算并过滤了 openat 延迟吗？

**面试官关注：**直接验证简历中的“延迟阈值”和“退出统计”是否落地。

**我的回答：**

当前版本还没有完整实现。`entry_data` 和事件结构已经预留 `enter_ts`、`latency_ns`，控制结构也有 `min_delay_ns`，但入口没有给 `enter_ts` 赋值，出口没有计算 `latency_ns`，也没有应用阈值。用户态却会打印 `latency_ns`，这个字段目前不可信。

同样，虽然定义了 `Open_stats` 和 `stats_map`，BPF 侧没有更新 count、total 和 max，所以退出时通常不会打印有效统计。修复方式很直接：入口记录 `bpf_ktime_get_ns()`；出口先计算 latency，再进行 PID/阈值过滤，随后更新统计并上报；失败返回值也应保留。

因此当前简历把这些能力描述成所有模块的统一能力并不准确。我会先补齐实现；如果面试前不改代码，就应明确说“调度和锁模块已支持阈值，openat 模块完成了事件关联但统计仍在补充”。

## 五、TCP 网络模块

### 15. 面试官：TCP 模块具体观测什么？

**面试官关注：**“网络监控”不能停留在宽泛描述，必须给出事件模型。

**我的回答：**

当前 TCP 模块包含三类事件：主动连接握手、重传和关闭。`tcp_v4_connect/tcp_v6_connect` 使用 fentry 记录连接开始时间和进程上下文；`tcp_rcv_state_process` 用来尝试识别客户端处于 `TCP_SYN_SENT` 时收到响应的阶段并计算握手延迟；`tcp_retransmit_skb` kprobe 记录重传；`tcp_close` kprobe 汇总该 socket 的累计重传次数。

事件中保存 IPv4/IPv6 地址、端口、TCP 状态、TGID/TID、comm、时间戳、握手延迟和累计重传数。`retrans_map` 以 `struct sock *` 地址为 key，重传时递增，close 时取出并删除。

这个模块的目标是回答“连接建立是否慢、是否发生重传、关闭时该连接累计重传多少”，而不是完整的网络延迟分析；它没有直接测应用请求 RTT 或收发队列时延。

### 16. 面试官：connect 和握手完成是如何关联的？可靠吗？

**面试官关注：**网络事件经常发生在软中断上下文，这是区分熟练与不熟练的关键问题。

**我的回答：**

当前 `sess_map` 使用 `pid_tgid` 作为 key：connect 时写入，`tcp_rcv_state_process` 时用当前 `pid_tgid` 查询。这个方案存在可靠性问题，因为接收 SYN+ACK 的路径可能运行在 softirq 或 ksoftirqd 上下文，当前任务不一定是发起 connect 的应用线程，因此会出现 map miss。

更可靠的设计是 connect 时就用 `struct sock *` 或 `bpf_get_socket_cookie()` 作为连接 key，把进程上下文挂到 socket 上；后续握手、重传和 close 都通过同一 socket 查找。这样也能解决重传路径中 current PID 不代表 socket owner 的问题。

另外，当前握手事件在 `sport==0` 时 discard 后没有删除 `sess_map`，会留下条目；最小握手延迟字段也写入了控制 Map，但 BPF 侧没有实际过滤。这些都需要在工程化版本中修复。

### 17. 面试官：TCP 模块还有哪些数据正确性问题？

**面试官关注：**能否从字节序、上下文和统计竞态三个层面检查网络代码。

**我的回答：**

第一，`skc_num` 是主机序本地端口，而 `skc_dport` 是网络序目的端口；当前用户态格式化函数对两者都执行 `ntohs()`，源端口可能显示错误。事件结构应明确每个字段的字节序，或者在内核侧统一转换。

第二，重传可能由定时器或软中断触发，当前 `bpf_get_current_pid_tgid()` 和 comm 不一定属于连接发起进程，所以 PID 过滤和进程归属可能错误，仍应通过 socket 映射解决。第三，`stats_map` 是普通 ARRAY，多 CPU 更新握手、重传和 max 字段会有竞态。

第四，close 事件把 `latency_ns` 设为 0，但统计函数却把它当连接存活时长累加，所以当前 `cl_total_ns/cl_max_ns` 没有真实含义。若要统计连接生命周期，应在 connect 时保存起点并在 close 时用 socket key 计算。

## 六、direct reclaim 内存模块

### 18. 面试官：为什么内存模块选择监控 direct reclaim？

**面试官关注：**候选人是否理解内存压力如何转化为业务长尾。

**我的回答：**

direct reclaim 是业务线程申请内存时发现可用页不足，被迫同步执行页面回收。与后台 kswapd 不同，它直接占用业务线程的执行路径，因此非常容易表现为接口偶发长尾。

模块挂载 `mm_vmscan_direct_reclaim_begin/end` tracepoint，以 `pid_tgid` 为 HASH key 保存开始时间、进程名和内存快照；end 时计算 `delta`，读取本次 `nr_reclaimed`，通过 ringbuf 输出 PID、comm、空闲页和回收延迟。这里用线程 key 比 per-CPU 槽更合适，因为回收过程可能调度和迁移。

这个模块能回答“某个业务线程是否因同步回收卡住、卡了多久、回收了多少页”，但不能单独回答内存压力根因；还要结合 memcg、zone 水位、匿名页/文件页、compaction 和 OOM 上下文。

### 19. 面试官：为什么用户态要从 `/proc/kallsyms` 读取 `vm_stat` 地址？兼容吗？

**面试官关注：**CO-RE 与读取内核全局变量是两个不同问题。

**我的回答：**

当前实现从 `/proc/kallsyms` 查找 `vm_stat` 或 `vm_zone_stat` 的地址，写入 `vm_stat_map`，BPF 入口再按该地址读取一个内存统计数组。这让事件能携带回收开始时的空闲页快照，但兼容性和安全性较弱。

在开启 `kptr_restrict`、kernel lockdown 或符号不可见的环境中，用户态可能拿不到有效地址；不同内核中全局变量的定义也可能变化。CO-RE 可以重定位结构字段，却不会自动修复用户态硬取全局符号地址的问题。

更好的方案是优先使用 tracepoint 已提供的参数、BPF 可用的 kfunc/helper，或通过 BTF global variable/内核兼容接口获取所需统计；至少也应对符号类型和读取大小做严格校验，而不能把 `vm_stat` 与 `vm_zone_stat` 当作无差别替代。

### 20. 面试官：这个内存模块支持简历中的开关、PID 和阈值过滤吗？

**面试官关注：**验证公共框架是否真的覆盖全部模块。

**我的回答：**

当前没有完整支持。`dr_snoop_run()` 接收 enable、target_pid 和 min_delay_ns，也构造了 `DrSnoop_ctrl`，但 BPF 侧没有 ctrl_map，三个参数都没有参与过滤；模块也没有 stats_map，所以退出时不会像简历描述的那样打印统一汇总。

此外，end 探针在 ringbuf reserve 失败时直接返回，没有删除 `start` Map 中对应条目，会形成残留；`start` 的 `max_entries` 设置为 262144，对于入口 value 还包含内存快照的场景需要重新做容量估算。

我会增加单元素 ctrl_map，在 begin 最早位置执行开关和 TGID 过滤，在 end 计算 delta 后执行阈值过滤；所有出口路径统一删除 start 条目，并增加 reserve_failed、start_miss 和 map_update_failed 统计。这样才与统一框架的描述一致。

## 七、公共数据通路与 eBPF 原理

### 21. 面试官：为什么使用 ringbuf，而不是 perf buffer？

**面试官关注：**是否理解数据通道的真实优势，而不是只会说“零拷贝”。

**我的回答：**

BPF ringbuf 是所有 CPU 共享的环形缓冲区，不需要像 perf buffer 那样为每个 CPU 预留独立空间，因此在 CPU 较多、事件分布不均时内存利用率更好；它还能保留跨 CPU 的提交顺序。BPF 侧先 `reserve` 一块记录空间，直接填充事件，再 `submit`；用户态通过 libbpf 的 mmap 消费区读取。

我会谨慎使用“零拷贝”这个词。它避免了用户态逐事件 read syscall 和额外的数据搬运，但 BPF 仍然要把内核字段写入 ringbuf，用户态也要读取和格式化，所以更准确的说法是“基于共享内存的低拷贝数据通道”。

当前每个模块 ringbuf 为 256 KiB，reserve 失败时大多直接丢事件，却没有统一 dropped counter。生产环境必须记录丢失数，否则“没有观察到慢事件”可能只是缓冲区已满。

### 22. 面试官：用户态 100ms 批量轮询会增加 100ms 延迟吗？

**面试官关注：**是否真正理解 `ring_buffer__poll()` 的语义。

**我的回答：**

不会固定增加 100ms。100ms 是 `ring_buffer__poll()` 的最大阻塞超时；ringbuf 有新事件时 poll 可以提前被唤醒并执行回调。这个超时主要决定无事件时多久返回一次，以便检查退出标志或执行周期任务。

当前代码在回调中逐事件格式化并打印，事件量高时真正的瓶颈更可能是 stdout，而不是 poll 超时。线上版本应让回调只做轻量解析，将事件交给批量队列，或者优先输出直方图、top-N 和聚合指标。

另外，部分模块在信号处理函数里调用 Map lookup、printf 后 `_exit()`。这些操作不是严格的 async-signal-safe，且 `_exit()` 会跳过正常 cleanup。更合理的是统一只在 handler 中设置 `sig_atomic_t` 标志，让主循环退出后打印 stats 并销毁 skeleton。

### 23. 面试官：ctrl_map、上下文 Map 和 stats_map 分别解决什么问题？

**面试官关注：**能否按状态生命周期选择 Map，而不是机械套模板。

**我的回答：**

`ctrl_map` 是单元素 ARRAY，保存 enable、目标 PID 和阈值，属于用户态向内核下发的低频配置；入口/出口上下文 Map 保存短生命周期状态，key 必须能唯一标识逻辑事件，例如 openat 用 TID、TCP 应使用 socket、direct reclaim 用 pid_tgid；`stats_map` 保存 count、total、max 和 drop 等长期聚合。

Map 类型不能只看“是否多核”。per-CPU Map 适合每 CPU 独立计数或确实不跨 CPU 的状态；可能发生 CPU 迁移的线程级入口/出口应该用 pid_tgid HASH。普通 ARRAY/HASH 的 value 并不会自动获得原子更新语义，多 CPU 执行 `++` 仍会竞态。

我还会为每个数据通路增加可观测性计数：入口次数、Map update 失败、出口 miss、阈值过滤、ringbuf reserve 失败和成功提交。没有这些计数，监控工具自身的数据质量无法证明。

### 24. 面试官：CO-RE 到底解决了什么？为什么仍可能 attach 失败？

**面试官关注：**区分数据结构兼容与挂载点兼容。

**我的回答：**

Clang 编译时将 BTF 类型和 CO-RE relocation 保存进 BPF ELF，libbpf 加载时读取目标内核 BTF，对 `BPF_CORE_READ()` 等字段访问进行重定位。因此 `task_struct`、`sock` 等结构字段偏移变化时，通常不需要为每个内核重新编译。

但 CO-RE 不保证目标函数、tracepoint、helper 或程序类型存在。例如 `finish_task_switch.isra.0` 的符号名可能变化，fentry 目标也必须有 BTF，direct reclaim tracepoint 在不同内核的字段可能不同。工程上仍需要 feature probe、字段存在性判断和 fallback。

当前 Makefile 会按架构选择仓库中的 `vmlinux_*.h` 编译，并由 bpftool 生成 skeleton。跨内核依赖目标机 `/sys/kernel/btf/vmlinux` 完成重定位；跨 CPU 架构则仍需分别构建，并正确设置 `__TARGET_ARCH_xxx`。

### 25. 面试官：libbpf 加载一个模块的完整流程是什么？

**面试官关注：**候选人是否亲自实现过用户态，而不是只写 BPF C。

**我的回答：**

模块先调用 skeleton 的 `open_and_load()`：open 阶段解析 BPF ELF，load 阶段创建 Map、加载 program 并经过 verifier。加载成功后，用户态通过 `bpf_map__update_elem()` 把控制配置写入 ctrl_map，再用 `ring_buffer__new()` 绑定 ringbuf fd 和事件回调，随后调用 skeleton attach 创建 bpf_link。

事件循环中通过 `ring_buffer__poll()` 消费数据，收到 EINTR 时按正常退出处理；结束后读取 stats_map，最后 free ring buffer 并 destroy skeleton。destroy 会关闭 object、Map fd 和 link，从而 detach 探针。

如果失败，我会把 open/load、配置 Map、创建 ringbuf 和 attach 分开报错。load 失败重点看 verifier log；attach 失败重点检查目标 hook、BTF、符号名、权限和内核 feature。当前代码部分错误日志过于笼统，后续应统一开启 libbpf debug callback。

### 26. 面试官：verifier 主要保证什么？这个项目最容易在哪些地方失败？

**面试官关注：**必要的 eBPF 八股知识，以及能否联系实际项目。

**我的回答：**

verifier 通过静态分析保证所有可达路径上的内存访问有界、指针类型合法、helper 参数正确、程序能够终止，并限制栈空间和控制流复杂度。BPF 程序不能任意解引用内核或用户指针，必须使用适合上下文的 helper 或 CO-RE 读取方式。

结合本项目，风险点包括读取 `mutex->owner` 和 `sock` 字段时的指针合法性、读取 openat 用户字符串时的长度边界、ringbuf reserve 后所有路径必须 submit 或 discard、tracepoint 自定义 context 与目标内核字段是否匹配，以及大结构体是否造成 BPF 栈超限。

排查时我会开启 libbpf verifier log，根据报错指令回到 C 代码，检查判空、范围推导和指针来源，而不是反复试错。必要时减少栈对象、拆分函数或简化分支状态。

## 八、性能、可靠性与项目复盘

### 27. 面试官：你如何证明这是一个“低开销”工具？

**面试官关注：**是否有性能工程意识，而不是把 eBPF 自动等同于低开销。

**我的回答：**

我会设计四组对照：完全不运行工具；程序 attach 但 enable=false；开启 PID/阈值过滤；全量采集。对业务测吞吐、平均延迟和 P99/P999，对工具测用户态 CPU、BPF program run count/run time、事件速率、Map 占用和 ringbuf drop。

不同探针的风险不同。调度和 mutex 属于热点内核路径，逐事件读取字符串、更新共享 Map 和打印都可能放大开销；TCP 和 direct reclaim 频率相对低，但关联 Map 可能残留。优化顺序应是尽早过滤、减少事件字段、使用 per-CPU 聚合、对明细事件采样，以及避免用户态逐事件同步打印。

当前仓库没有完整的 benchmark 结果，因此我不会在面试中声称已经量化证明“低开销”。我会说代码采用了低开销设计，并给出上述验证方案；如果要把“低开销”写成结果，简历中最好补充实际数据。

### 28. 面试官：线上出现大量事件，但用户态没输出，你怎么排查？

**面试官关注：**能否系统定位 BPF 数据链路故障。

**我的回答：**

我会按链路分段排查。先确认 program 已加载并 attach，可用 bpftool 查看 prog/link 和运行次数；再检查 ctrl_map 的 enable、PID 和阈值是否正确；然后查看入口 Map update 是否失败、出口是否 lookup miss；最后看 ringbuf reserve failure 和用户态 poll 返回值。

如果 program 有运行次数但没有事件，常见原因是过滤条件错误、入口出口 key 不一致、current PID 语义错误、hook 上下文不同或 ringbuf 已满。例如 TCP 握手用 pid_tgid 跨软中断关联就可能 miss；openat 当前根本没有真正计算阈值；direct reclaim 的公共配置没有接入。

因此监控程序本身必须具备内部健康指标。仅在 BPF 中 `bpf_printk()` 不适合生产环境，应该用 per-CPU stats 记录 attempted、filtered、missed、dropped 和 submitted，用户态定期打印。

### 29. 面试官：你认为当前项目最需要改进的三点是什么？

**面试官关注：**候选人是否具备真实复盘和优先级判断能力。

**我的回答：**

第一是数据正确性。调度模块要明确改为 wakeup-to-switch-in 才能叫调度等待；mutex 要修复 TGID/TID、owner flags 和入口出口关联；TCP 要改用 socket key；openat 和 direct reclaim 要补齐阈值及统计。

第二是并发与数据质量。所有全局 stats 应改成 per-CPU 聚合或使用正确同步，并统一增加 Map failure、association miss 和 ringbuf drop 指标。这样工具输出才能被信任。

第三是工程框架。真正支持多模块同时运行，统一 signal/cleanup、事件公共头、feature probe 和 fallback，再补充自动化正确性测试与开销基准。相比继续增加模块数量，这三点的优先级更高。

### 30. 面试官：如果我质疑你的简历写得比代码完成度高，你怎么回答？

**面试官关注：**诚信、边界意识和面对代码缺陷的反应。

**我的回答：**

这个质疑是成立的。当前仓库已经完成五类观测的主要探针、Map 和用户态链路，但简历把一些公共目标写成了所有模块都已完整支持。例如组合式观测目前还是单模块入口；openat 没有真正计算 latency 和 stats；direct reclaim 没有接入统一开关、PID 和阈值；普通 ARRAY stats 也仍有并发问题。

我不会用设计意图替代实现事实。面试时我会明确哪些能力已经落地、哪些是下一步计划，并优先修正简历或补齐代码。更准确的表述可以是：“实现五类 eBPF 观测模块和统一 libbpf 控制框架；部分延迟型模块支持 PID/阈值过滤与退出汇总，并完成 ringbuf 事件链路和 CO-RE 适配。”

我认为能解释缺陷产生的原因、影响范围、修复方案和验证方法，比坚持代码没有问题更能体现项目经验。

## 面试前必须准备的数据

仅靠代码描述还不足以支撑“线上、低开销、快速定位”三个关键词。面试前建议准备以下真实结果：

1. 一组受控故障案例：如何制造问题、工具输出什么、最终如何判断根因。
2. 一组性能对照：关闭、过滤、全量采集下的 CPU、吞吐和 P99/P999。
3. 一组数据质量指标：入口数、出口数、关联 miss、Map 更新失败和 ringbuf drop。
4. 五个模块各自准确的计时区间、Map key、事件字段和已知边界。
5. 至少两个真实兼容问题，例如 kprobe 符号变化、目标内核缺少 BTF，以及对应 fallback。
