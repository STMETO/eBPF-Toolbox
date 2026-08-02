# eBPF-Toolbox

基于 eBPF 的 Linux 系统可观测性工具集，当前注册 15 个监测模块，提供统一命令行接口。

## 架构

```
My_eBPF_Poj/
├── fs/                         # 文件系统监测
│   ├── read/                   #   bpf.c + user.c + read.h
│   ├── write/                  #   bpf.c + user.c + write.h
│   ├── open/                   #   ...
│   └── block_io/
├── mem/                        # 内存监测
│   ├── proc_stat/ oom_killer/
│   └── slab_rate/ dr_snoop/
├── sched/                       # 调度延迟监测
│   ├── context_switch/ preempt/
├── lock/                        # 同步/IPC 监测
│   ├── syscall/ msgqueue/
│   └── mutexlock/
├── net/                         # 网络监测
│   ├── tcp_monitor/
│   └── udp_monitor/
├── common/                     # 基础设施
│   ├── main.c                  # 统一入口
│   ├── cli.c / cli.h           # 命令行+信号
│   └── types.h                 # 跨端类型
├── lib/                        # git submodules
│   ├── libbpf/ bpftool/ blazesym/
├── vmlinux/                    # 多架构 CO-RE
├── Makefile                    # 自动扫描 */bpf.c + */user.c
└── README.md
```

## 模块设计原则

- **每个模块一个目录**：3 个文件 — `模块名.bpf.c` (内核态) + `user.c` (用户态) + `模块名.h` (共享)
- **Makefile 自动扫描**：新增模块只需创建目录和 3 个文件，无需修改 Makefile
- **统一入口**：`./test -m <mode> -t <timeout_ms> -e <0|1>`

## 快速开始

运行环境需要内核 BTF、BPF ring buffer，以及所选模块使用的 tracepoint/fentry/kprobe；
通常需要 root 或等价的 BPF/perfmon 权限。五个延迟模块使用
`bpf_get_ns_current_pid_tgid()`，因此建议使用 Linux 5.7 或更新内核。

```bash
# 编译
make

# 单模块运行
sudo ./test -m fs_read     -t 100 -e 1
sudo ./test -m slab_rate       -t 100 -e 1
sudo ./test -m tcp_monitor -t 100 -e 1

# 组合观测（逗号分隔）
sudo ./test -m context,mutexlock,fs_open,tcp_monitor,dr_snoop \
  -p 1234 -d 100000 -t 100
```

- `-p` 按启动工具所在 PID namespace 的用户可见 TGID 过滤，`0` 表示全部。
- `-d` 是最小延迟阈值，单位 ns；低于阈值的明细不会进入 ringbuf。
- `-t` 是 ringbuf poll 的最大等待时间，事件到达时会提前唤醒。
- `-e 0` 保持程序加载和 attach，但关闭内核态采集。

五个代表模块的计时语义分别是：`context` 为 wakeup 到 switch-in 的
run-queue 等待，`mutexlock` 为内核 mutex slowpath 等待，`fs_open` 为
openat 入口到出口，`tcp_monitor` 为主动建连/重传/关闭生命周期，
`dr_snoop` 为 direct reclaim begin 到 end。`mutexlock` 不监控用户态
`pthread_mutex_t`。

## 所有模块 (15)

| 类别 | 命令 |
|------|------|
| 调度延迟 | `context` `preempt` |
| 同步/IPC | `syscall` `msgqueue` `mutexlock` |
| 文件系统 | `fs_open` `fs_read` `fs_write` `block_io` |
| 内存 | `proc_stat` `dr_snoop` `oom_killer` `slab_rate` |
| 网络 | `tcp_monitor` `udp_monitor` |
