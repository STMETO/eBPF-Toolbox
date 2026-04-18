#include <stdio.h>
#include "app_common.h"
#include "context_switch_delay.h"
#include "syscall_delay.h"

int main(int argc, char **argv)
{
	struct app_options opts = {0};
	int err = 0;

	err = app_parse_args(argc, argv, &opts);
	if (err) {
		fprintf(stderr, "命令行参数解析失败\n");
		return 1;
	}

	err = app_setup_signal_handlers();
	if (err) {
		fprintf(stderr, "信号处理初始化失败: %d\n", err);
		return 1;
	}

	printf("启动模式: %s, 轮询超时: %d ms, enable: %d\n",
	       app_mode_to_string(opts.mode), opts.poll_timeout_ms, opts.enable ? 1 : 0);

	switch (opts.mode) {
	case APP_MODE_CONTEXT_SWITCH:
		err = context_switch_delay_run(opts.poll_timeout_ms, opts.enable);
		break;
	case APP_MODE_SYSCALL:
		err = syscall_delay_run(opts.poll_timeout_ms, opts.enable);
		break;
	default:
		fprintf(stderr, "未知模式\n");
		return 1;
	}

	if (err) {
		fprintf(stderr, "模块退出异常: %d\n", err);
		return 1;
	}

	return 0;
}
