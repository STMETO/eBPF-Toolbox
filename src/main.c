#include <stdio.h>
#include "app_common.h"
#include "context_switch_delay.h"
#include "syscall_delay.h"
#include "tcp_connect_delay.h"
#include "msgqueue_delay.h"
#include "mutexlock_delay.h"
#include "preempt_delay.h"
#include "schedule_delay.h"
#include "open.h"
#include "read.h"
#include "write.h"
#include "disk_io_visit.h"
#include "block_rq_issue.h"
#include "paf.h"
#include "pr.h"
#include "proc_stat.h"
#include "sys_stat.h"
#include "mem_leak.h"
#include "frag_info.h"
#include "numa_frag_info.h"
#include "vma_snap.h"
#include "dr_snoop.h"
#include "oom_killer.h"
#include "slab_rate.h"
#include "net_watcher.h"

int main(int argc, char **argv)
{
    // 定义配置结构体，存储命令行解析后的所有参数
    struct app_options opts = {0};
    int err = 0;

    // 1. 解析命令行参数（-m、-t、-e）解析结果存入 opts 结构体
    err = app_parse_args(argc, argv, &opts);
    if (err) {
        fprintf(stderr, "命令行参数解析失败\n");
        return 1;
    }

    // 2. 注册信号处理（Ctrl+C、kill 能优雅退出）
    err = app_setup_signal_handlers();
    if (err) {
        fprintf(stderr, "信号处理初始化失败: %d\n", err);
        return 1;
    }

    // 3. 打印当前程序运行配置
    printf("启动模式: %s, 轮询超时: %d ms, enable: %d\n",
           app_mode_to_string(opts.mode),  // 枚举转字符串，方便阅读
           opts.poll_timeout_ms,            	// 轮询超时时间
           opts.enable ? 1 : 0);            	// 是否启用监控

    // 4. 根据用户指定的模式，启动对应监控模块
    switch (opts.mode) {
        // 模式1：启动【进程上下文切换延迟】监控
        case APP_MODE_CONTEXT_SWITCH:
            err = context_switch_delay_run(opts.poll_timeout_ms, opts.enable);
            break;

        // 模式2：启动【系统调用延迟】监控
        case APP_MODE_SYSCALL:
            err = syscall_delay_run(opts.poll_timeout_ms, opts.enable);
            break;

        // 模式3：启动【TCP 建连延迟】监控
        case APP_MODE_TCP_CONNECT:
            err = tcp_connect_delay_run(opts.poll_timeout_ms, opts.enable);
            break;

        // 模式4：启动【消息队列延迟】监控
        case APP_MODE_MSGQUEUE:
            err = msgqueue_delay_run(opts.poll_timeout_ms, opts.enable);
            break;

        // 模式5：启动【互斥锁延迟】监控
        case APP_MODE_MUTEXLOCK:
            err = mutexlock_delay_run(opts.poll_timeout_ms, opts.enable);
            break;

        // 模式6：启动【抢占延迟】监控
        case APP_MODE_PREEMPT:
            err = preempt_delay_run(opts.poll_timeout_ms, opts.enable);
            break;

        // 模式7：启动【调度延迟】监控
        case APP_MODE_SCHEDULE:
            err = schedule_delay_run(opts.poll_timeout_ms, opts.enable);
            break;

        // 理论上不会走到这里（参数解析已保证 mode 合法）
        default:
            fprintf(stderr, "未知模式\n");
            return 1;
    }

    // 5. 监控模块退出，检查是否异常
    if (err) {
        fprintf(stderr, "模块退出异常: %d\n", err);
        return 1;
    }

    // 正常退出
    printf("程序正常退出\n");
    return 0;
}