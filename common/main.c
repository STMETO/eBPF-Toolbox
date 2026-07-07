#include <stdio.h>
#include "common/cli.h"
#include "common/registry.h"

int main(int argc, char **argv)
{
	struct app_options opts = {0};
	int err = app_parse_args(argc, argv, &opts);
	if (err) { fprintf(stderr, "命令行参数解析失败\n"); return 1; }

	err = app_setup_signal_handlers();
	if (err) { fprintf(stderr, "信号处理初始化失败\n"); return 1; }

	printf("启动模式: %s, 轮询超时: %d ms, enable: %d\n",
	       app_mode_to_string(opts.mode), opts.poll_timeout_ms, opts.enable ? 1 : 0);

	const struct module_entry *m = NULL;
	for (int i = 0; MODULE_TABLE[i].name; i++) {
		if (MODULE_TABLE[i].mode == opts.mode) {
			m = &MODULE_TABLE[i];
			break;
		}
	}

	if (!m || !m->run) {
		fprintf(stderr, "未知模式\n");
		return 1;
	}

	err = m->run(opts.poll_timeout_ms, opts.enable, opts.target_pid, opts.min_delay_ns);
	if (err) { fprintf(stderr, "模块退出异常: %d\n", err); return 1; }
	printf("程序正常退出\n");
	return 0;
}
