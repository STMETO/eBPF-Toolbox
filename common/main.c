#include <stdio.h>
#include "common/cli.h"
#include "fs/read/read.h"
#include "fs/write/write.h"
#include "fs/open/open.h"
#include "fs/disk_io/disk_io.h"
#include "fs/block_rq/block_rq.h"
#include "mem/paf/paf.h"
#include "mem/pr/pr.h"
#include "mem/proc_stat/proc_stat.h"
#include "mem/sys_stat/sys_stat.h"
#include "mem/oom_killer/oom_killer.h"
#include "mem/slab_rate/slab_rate.h"
#include "mem/frag_info/frag_info.h"
#include "mem/numa_frag/numa_frag.h"
#include "mem/dr_snoop/dr_snoop.h"
#include "mem/mem_leak/mem_leak.h"
#include "lock/context_switch/context_switch.h"
#include "lock/syscall/syscall.h"
#include "lock/msgqueue/msgqueue.h"
#include "lock/mutexlock/mutexlock.h"
#include "lock/preempt/preempt.h"
#include "lock/schedule/schedule.h"
#include "net/tcp_connect/tcp_connect.h"

int main(int argc, char **argv)
{
	struct app_options opts = {0};
	int err = 0;

	err = app_parse_args(argc, argv, &opts);
	if (err) { fprintf(stderr, "命令行参数解析失败\n"); return 1; }

	err = app_setup_signal_handlers();
	if (err) { fprintf(stderr, "信号处理初始化失败: %d\n", err); return 1; }

	printf("启动模式: %s, 轮询超时: %d ms, enable: %d\n",
	       app_mode_to_string(opts.mode), opts.poll_timeout_ms, opts.enable ? 1 : 0);

	switch (opts.mode) {
	case APP_MODE_CONTEXT_SWITCH:
		err = context_switch_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_SYSCALL:
		err = syscall_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_MSGQUEUE:
		err = msgqueue_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_MUTEXLOCK:
		err = mutexlock_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_PREEMPT:
		err = preempt_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_SCHEDULE:
		err = schedule_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_FS_OPEN:
		err = open_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_FS_READ:
		err = read_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_FS_WRITE:
		err = write_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_DISK_IO_VISIT:
		err = disk_io_visit_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_BLOCK_RQ_ISSUE:
		err = block_rq_issue_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_PAF:
		err = paf_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_PR:
		err = pr_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_PROC_STAT:
		err = proc_stat_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_SYS_STAT:
		err = sys_stat_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_MEM_LEAK:
		err = mem_leak_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_FRAG_INFO:
		err = frag_info_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_NUMA_FRAG_INFO:
		err = numa_frag_info_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_DR_SNOOP:
		err = dr_snoop_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_OOM_KILLER:
		err = oom_killer_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_SLAB_RATE:
		err = slab_rate_run(opts.poll_timeout_ms, opts.enable); break;
	case APP_MODE_TCP_CONNECT:
		err = tcp_connect_run(opts.poll_timeout_ms, opts.enable); break;
	default:
		fprintf(stderr, "未知模式\n"); return 1;
	}

	if (err) { fprintf(stderr, "模块退出异常: %d\n", err); return 1; }
	printf("程序正常退出\n");
	return 0;
}
