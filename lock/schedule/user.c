#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "common/cli.h"
#include "common/types.h"
#include "schedule.h"
#include "lock/schedule/skel.h"

// 入口函数：运行「调度延迟监控」
// poll_timeout_ms：map 轮询间隔（毫秒）
// enable：是否启用监控（true=启动，false=关闭）
//
// 注意：本模块不使用 ringbuf，而是直接读取 BPF map
// 获取系统全局调度统计 + 最近一次调度延迟信息
int schedule_run(int poll_timeout_ms, bool enable)
{
	struct schedule_bpf *skel = NULL;
	struct Schedule_Delay_ctrl ctrl = {.enable = enable};
	const int key = 0;
	int err = 0;

	skel = schedule_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "打开BPF程序失败\n");
		return 1;
	}

	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "设置控制开关失败: %s\n", strerror(-err));
		goto cleanup;
	}

	err = schedule_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载BPF程序失败\n");
		goto cleanup;
	}

	printf("=========================================\n");
	printf("  调度延迟监控已%s！\n", enable ? "启动" : "关闭");
	printf("  按 Ctrl+C 退出\n");
	printf("=========================================\n");

	while (!app_should_exit()) {
		/* 读取系统全局调度统计 */
		struct Schedule_Delay_sum_schedule sum;
		err = bpf_map__lookup_elem(skel->maps.sys_schedule,
					   &key, sizeof(key),
					   &sum, sizeof(sum), 0);
		if (err == 0 && sum.sum_count > 0) {
			bpf_u64_t avg_delay = sum.sum_delay / sum.sum_count;

			printf("\n===== 系统调度统计 =====\n");
			printf("  累计调度次数: %" PRIu64 "\n", sum.sum_count);
			printf("  平均调度延迟: %" PRIu64 " ns\n", avg_delay);
			printf("  最大调度延迟: %" PRIu64 " ns  (进程: %s)\n",
			       sum.max_delay, sum.proc_name_max);
			printf("  最小调度延迟: %" PRIu64 " ns  (进程: %s)\n",
			       sum.min_delay, sum.proc_name_min);

			/* 读取最近一次调度延迟信息 */
			struct Schedule_Delay_proc_schedule proc;
			err = bpf_map__lookup_elem(skel->maps.threshold_schedule,
						   &key, sizeof(key),
						   &proc, sizeof(proc), 0);
			if (err == 0) {
				printf("  最近调度: PID=%-6d 延迟=%-8" PRIu64 " ns 进程: %s\n",
				       proc.id.pid, proc.delay, proc.proc_name);
			}
			printf("========================\n");
		}

		/* 等待 poll_timeout_ms 后再读取 */
		usleep(poll_timeout_ms * 1000);
	}

cleanup:
	schedule_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
