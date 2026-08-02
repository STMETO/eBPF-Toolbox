#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

#include "common/cli.h"
#include "common/registry.h"

struct module_thread {
	const struct module_entry *module;
	const struct app_options *opts;
	int result;
};

/*
 * 每个模块拥有独立 skeleton、ringbuf 和 poll 循环，因此组合模式用一个
 * pthread 承载一个模块。任一模块失败都会设置公共退出标志，使其他模块
 * 在下一次 poll 返回后完成统计打印和 skeleton 销毁。
 */
static void *run_module_thread(void *arg)
{
	struct module_thread *thread = arg;
	const struct app_options *opts = thread->opts;

	thread->result = thread->module->run(opts->poll_timeout_ms, opts->enable,
					     opts->target_pid, opts->min_delay_ns);
	if (thread->result)
		app_request_exit();
	return NULL;
}

int main(int argc, char **argv)
{
	struct app_options opts = {};
	struct module_thread threads[MODULE_COUNT] = {};
	pthread_t tids[MODULE_COUNT];
	int count = 0;
	int err;

	err = app_parse_args(argc, argv, &opts);
	if (err) {
		fprintf(stderr, "命令行参数解析失败\n");
		return 1;
	}
	err = app_setup_signal_handlers();
	if (err) {
		fprintf(stderr, "信号处理初始化失败\n");
		return 1;
	}

	printf("启动模式:");
	for (int i = 0; MODULE_TABLE[i].name; i++) {
		if (!(opts.mode_mask & (1ULL << MODULE_TABLE[i].mode)))
			continue;
		printf(" %s", MODULE_TABLE[i].name);
		threads[count].module = &MODULE_TABLE[i];
		threads[count].opts = &opts;
		count++;
	}
	printf(", 轮询超时: %d ms, enable: %d\n",
	       opts.poll_timeout_ms, opts.enable ? 1 : 0);

	if (count == 1) {
		/* 单模块保留直接调用路径，避免无意义的线程创建开销。 */
		err = threads[0].module->run(opts.poll_timeout_ms, opts.enable,
					     opts.target_pid, opts.min_delay_ns);
	} else {
		err = 0;
		/* opts 在 main 返回前始终有效，所有线程只读共享该配置。 */
		for (int i = 0; i < count; i++) {
			int rc = pthread_create(&tids[i], NULL, run_module_thread, &threads[i]);
			if (rc) {
				fprintf(stderr, "启动模块 %s 失败: %d\n",
					threads[i].module->name, rc);
				app_request_exit();
				for (int j = 0; j < i; j++)
					pthread_join(tids[j], NULL);
				return 1;
			}
		}
		for (int i = 0; i < count; i++) {
			pthread_join(tids[i], NULL);
			if (!err && threads[i].result)
				err = threads[i].result;
		}
	}

	if (err) {
		fprintf(stderr, "模块退出异常: %d\n", err);
		return 1;
	}
	printf("程序正常退出\n");
	return 0;
}
