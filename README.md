# eBPF-Toolbox

基于 eBPF 的 Linux 系统可观测性工具集，支持多种内核事件的延迟监控与性能分析。

> ⚡ **项目仍在积极开发中，功能持续更新，欢迎关注！**

## 项目简介

eBPF-Toolbox 是一套轻量级的系统监控工具，利用 eBPF 技术在内核态高效采集数据，用户态负责解析和展示。所有监控模块通过统一的命令行接口调用，使用方式简洁一致。

### 已支持的监控模块

| 模块 | 命令 | 类型 | 说明 |
|------|------|------|------|
| 进程上下文切换延迟 | `context` | kprobe | 监控进程上下文切换的耗时，定位调度延迟问题 |
| 系统调用延迟 | `syscall` | tracepoint | 测量每个系统调用的执行耗时，按 PID/TID/系统调用号分类 |
| TCP 建连延迟 | `tcp_connect` | fentry | 测量客户端 TCP 三次握手中 SYN → SYN-ACK 的往返耗时 |
| 消息队列延迟 | `msgqueue` | kprobe | 追踪 POSIX 消息队列的发送→接收全链路延迟 |
| 互斥锁竞争 | `mutexlock` | kprobe/uprobe | 监控内核及用户态互斥锁的竞争事件，记录持有者/等待者信息 |
| 抢占延迟 | `preempt` | tp_btf/kprobe | 监控进程被强制抢占的延迟，捕获 sched_switch 事件 |
| 调度延迟 | `schedule` | tp_btf/tracepoint | 测量进程从唤醒到实际运行的调度延迟，统计系统全局数据 |

## 架构概览

```
eBPF-Toolbox/
├── bpf/                          # eBPF 内核态程序
│   ├── include/                  # BPF 共享头文件（数据结构定义）
│   │   ├── common.h              #   公共类型定义（bpf_u64_t 等）
│   │   ├── ContextSwitch_Delay.h
│   │   ├── SystemCall_Delay.h
│   │   ├── TcpConnect_Delay.h
│   │   ├── MsgQueue_Delay.h
│   │   ├── MutexLock_Delay.h
│   │   ├── Preempt_Delay.h
│   │   └── Schedule_Delay.h
│   ├── perf/                     # 性能监控类 BPF 程序
│   │   ├── ContextSwitch_Delay.bpf.c
│   │   ├── SystemCall_Delay.bpf.c
│   │   ├── MsgQueue_Delay.bpf.c
│   │   ├── MutexLock_Delay.bpf.c
│   │   ├── Preempt_Delay.bpf.c
│   │   └── Schedule_Delay.bpf.c
│   └── net/                      # 网络类 BPF 程序
│       └── TcpConnect_Delay.bpf.c
├── src/                          # 用户态程序
│   ├── include/                  # 用户态头文件
│   │   ├── app_common.h          #   公共枚举 & 配置声明
│   │   ├── context_switch_delay.h
│   │   ├── syscall_delay.h
│   │   ├── tcp_connect_delay.h
│   │   ├── msgqueue_delay.h
│   │   ├── mutexlock_delay.h
│   │   ├── preempt_delay.h
│   │   └── schedule_delay.h
│   ├── common/                   # 公共模块
│   │   └── app_common.c          #   命令行解析 / 信号处理 / 公共逻辑
│   ├── perf/                     # 性能监控用户态程序
│   │   ├── ContextSwitch_Delay.c
│   │   ├── SysCall_Delay.c
│   │   ├── MsgQueue_Delay.c
│   │   ├── MutexLock_Delay.c
│   │   ├── Preempt_Delay.c
│   │   └── Schedule_Delay.c
│   ├── net/                      # 网络监控用户态程序
│   │   └── TcpConnect_Delay.c
│   └── main.c                    # 程序入口，按模式分发到各模块
├── vmlinux/                      # 各架构 vmlinux.h（CO-RE 支持）
│   ├── x86/
│   ├── arm64/
│   ├── arm/
│   ├── riscv/
│   ├── loongarch/
│   └── powerpc/
├── libbpf/                       # libbpf 子模块
├── bpftool/                      # bpftool 子模块
├── Makefile                      # 构建系统（自动扫描，无需手动添加文件）
└── README.md
```

### 数据流架构

```
  ┌───────────┐     ┌──────────────┐     ┌───────────┐
  │ Linux 内核 │────▶│ eBPF 程序      │────▶│ Ring/Perf │
  │ (hook点)   │     │ (采集&聚合)    │     │ Buffer    │
  └───────────┘     └──────────────┘     └─────┬─────┘
                                               │
                                        ┌──────▼──────┐
                                        │ 用户态程序    │
                                        │ (解析&展示)   │
                                        └─────────────┘
```

- **eBPF 层**：使用 `fentry`/`kprobe`/`tp_btf`/`tracepoint`/`uprobe` 等探针挂载到内核函数，采集事件和时间戳
- **传输层**：通过 ring buffer 或 perf event array 将数据从内核传到用户态（`schedule` 模块直接读取 BPF map）
- **用户态**：统一的 `main.c` 入口，命令行解析后分发到各模块，输出格式化日志

## 快速开始

### 依赖

- Linux 内核 ≥ 5.5（推荐 5.8+，`fentry`/`tp_btf` 探针需要较新内核）
- `clang`（支持 BPF target）
- `gcc`
- `libelf`、`zlib`

```bash
# Debian/Ubuntu
sudo apt install clang gcc make libelf-dev zlib1g-dev

# 初始化子模块
git submodule update --init --recursive
```

### 编译

```bash
make
```

编译产物：
- `test` — 用户态可执行程序
- `build/` — 中间产物和 BPF 骨架文件

### 运行

所有监控模块通过 `-m` 参数切换，需 `sudo` 权限加载 BPF 程序：

```bash
# 查看帮助
sudo ./test --help

# 监控进程上下文切换延迟
sudo ./test -m context     -t 100  -e 1

# 监控系统调用延迟
sudo ./test -m syscall     -t 100  -e 1

# 监控 TCP 建连延迟
sudo ./test -m tcp_connect -t 100  -e 1

# 监控消息队列延迟
sudo ./test -m msgqueue    -t 100  -e 1

# 监控互斥锁竞争（内核+用户态）
sudo ./test -m mutexlock   -t 100  -e 1

# 监控抢占延迟
sudo ./test -m preempt     -t 100  -e 1

# 监控调度延迟（建议较长轮询间隔）
sudo ./test -m schedule    -t 2000 -e 1
```

#### 参数说明

| 参数 | 短选项 | 值 | 说明 |
|------|--------|-----|------|
| `--mode` | `-m` | `context \| syscall \| tcp_connect \| msgqueue \| mutexlock \| preempt \| schedule` | 选择监控模式（必填） |
| `--timeout` | `-t` | `1-60000`（毫秒） | 轮询超时，默认 100ms（`schedule` 建议 2000ms） |
| `--enable` | `-e` | `0 \| 1` | 是否启用监控，1=启用，0=禁用 |

### 示例输出

```
# 上下文切换延迟
进程切换延迟: 1234     us | 开始: 9876543210 | 结束: 9876544444

# 系统调用延迟
PID: 1234   TID: 5678   COMM: myapp           SYSCALL: 3    DELAY: 56      us

# TCP 建连延迟
PID: 1234   COMM: curl         | LATENCY:     1234 us | SRC: 192.168.1.1:45678 DST: 93.184.216.34:443

# 消息队列延迟
SEND_PID: 1234   RCV_PID: 5678   MQDES: 3    MSG_LEN: 1024   PRIO: 0 |
SEND: 12345    ns  RCV: 6789     ns  TOTAL: 19134    ns

# 互斥锁竞争
LOCK: 0xffff888123456789 | OWNER: PID=1234   PRIO=120  NAME=myapp          | CONTENDER: PID=5678   PRIO=120  NAME=other_app

# 抢占延迟
PREV_PID: 1234   NEXT_PID: 5678   COMM: myapp           DURATION: 12345    ns

# 调度延迟
===== 系统调度统计 =====
  累计调度次数: 12345678
  平均调度延迟: 12345 ns
  最大调度延迟: 99999 ns  (进程: myapp)
  最小调度延迟: 100   ns  (进程: idle)
  最近调度: PID=1234   延迟=5678     ns  进程: myapp
========================
```

## 扩展新模块

添加新监控模块只需三步（以 `Foo` 为例）：

1. **BPF 程序**：在 `bpf/<category>/` 下编写 `Foo.bpf.c`，在 `bpf/include/` 下定义共享结构体 `Foo.h`
2. **用户态程序**：在 `src/<category>/` 下编写 `Foo.c`，实现 `foo_run(int poll_timeout_ms, bool enable)` 函数，在 `src/include/` 下声明头文件
3. **注册模块**：在 `app_common.h` 的 `enum app_mode` 中添加枚举值，在 `app_common.c` 的 `parse_opt` 和 `app_mode_to_string` 中添加对应字符串，在 `main.c` 的 `switch` 中添加 `case` 分支

Makefile 会自动扫描 `bpf/` 和 `src/` 目录下的新文件，无需手动修改构建系统。

## 待办事项

- [ ] 增加 `kprobe` 探针回退支持（低版本内核兼容）
- [ ] 增加 JSON 输出模式，方便对接日志系统
- [ ] 增加更多监控模块（文件 I/O 延迟、内存分配延迟等）
- [ ] 增加 Prometheus metrics 导出
- [ ] 增加配置文件支持，避免命令行参数过长

## 许可证

Dual BSD/GPL
