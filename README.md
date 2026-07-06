# eBPF-Toolbox

基于 eBPF 的 Linux 系统可观测性工具集，23 个监测模块，统一命令行接口。

## 架构

```
My_eBPF_Poj/
├── fs/                         # 文件系统监测
│   ├── read/                   #   bpf.c + user.c + read.h
│   ├── write/                  #   bpf.c + user.c + write.h
│   ├── open/                   #   ...
│   ├── disk_io/
│   └── block_rq/
├── mem/                        # 内存监测
│   ├── paf/ pr/ proc_stat/ sys_stat/
│   ├── oom_killer/ slab_rate/
│   ├── frag_info/ numa_frag/
│   ├── dr_snoop/ mem_leak/
├── lock/                       # 同步/调度监测
│   ├── context_switch/ syscall/
│   ├── msgqueue/ mutexlock/
│   ├── preempt/ schedule/
├── net/                        # 网络监测
│   └── tcp_connect/
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

```bash
# 编译
make

# 运行
sudo ./test -m fs_read     -t 100 -e 1
sudo ./test -m paf         -t 100 -e 1
sudo ./test -m slab_rate   -t 100 -e 1
```

## 所有模块 (23)

| 类别 | 命令 |
|------|------|
| 调度/同步 | `context` `syscall` `msgqueue` `mutexlock` `preempt` `schedule` |
| 文件系统 | `fs_open` `fs_read` `fs_write` `disk_io` `block_rq` |
| 内存 | `paf` `pr` `proc_stat` `sys_stat` `mem_leak` `frag_info` `numa_frag` `dr_snoop` `oom_killer` `slab_rate` |
| 网络 | `tcp_connect` |
