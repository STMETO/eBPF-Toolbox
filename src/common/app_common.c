#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "app_common.h"

static volatile sig_atomic_t g_exit_requested = 0;	// “需要退出” 的全局标志位。

// --help / -h 命令提供帮助信息展示
// { 长选项名, 短选项字符, 参数名, 标志位, 帮助说明 }
static const struct argp_option g_options[] = {
	{"mode", 'm', "context|syscall|tcp_connect", 0, "监控模式"},
	{"timeout", 't', "MILLISECONDS", 0, "ring buffer 轮询超时(毫秒)"},
	{"enable", 'e', "0|1", 0, "是否启用监控(1=启用, 0=禁用)"},
	{0}
};

// argp 库的参数解析回调函数
// key: 当前解析到的选项字符（如 'm', 't', 'e'）
// arg: 选项后面跟着的参数值（如 context, 100, 1）
// state: argp 库内部状态，包含输入数据、错误抛出等
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	// 从 state->input 拿到我们传入的 app_options 结构体
	// 解析后的所有参数都会存到这个结构体里
	struct app_options *opts = state->input;

	// strtol 用到的指针：标记数字解析结束位置
	char *end = NULL;

	// 存储 strtol 解析出来的长整型数值
	long parsed = 0;

	// 根据不同的选项 key 进行处理
	switch (key) {
	// 处理 -m/--mode 选项
	case 'm':
		// 判断参数是否是 "context"
		if (strcmp(arg, "context") == 0) {
			opts->mode = APP_MODE_CONTEXT_SWITCH;
		}
		// 判断参数是否是 "syscall"
		else if (strcmp(arg, "syscall") == 0) {
			opts->mode = APP_MODE_SYSCALL;
		}
		// 判断参数是否是 "tcp_connect"
		else if (strcmp(arg, "tcp_connect") == 0) {
			opts->mode = APP_MODE_TCP_CONNECT;
		}
		// 都不是 → 非法参数
		else {
			// argp_error 会自动打印错误并退出程序
			argp_error(state, "invalid mode: %s (use context|syscall|tcp_connect)", arg);
		}
		break;

	// 处理 -t/--timeout 选项
	case 't':
		errno = 0; // 先清空错误码，防止干扰判断

		// 把字符串 arg 转成十进制长整型数字
		parsed = strtol(arg, &end, 10);

		// 严格校验：
		// 1. errno != 0        → 转换出错
		// 2. end == arg         → 根本没读到数字
		// 3. *end != '\0'       → 后面还有多余字符（如 100abc）
		// 4. parsed <= 0 或 >60000 → 超出范围
		if (errno != 0 || end == arg || *end != '\0' || parsed <= 0 || parsed > 60000) {
			argp_error(state, "invalid timeout: %s (1-60000)", arg);
		}

		// 合法 → 存入超时配置
		opts->poll_timeout_ms = (int)parsed;
		break;

	// 处理 -e/--enable 选项
	case 'e':
		errno = 0;
		parsed = strtol(arg, &end, 10);

		// 校验：必须是纯数字 0 或 1
		if (errno != 0 || end == arg || *end != '\0' || (parsed != 0 && parsed != 1)) {
			argp_error(state, "invalid enable: %s (0|1)", arg);
		}

		// 1 → 启用；0 → 禁用
		opts->enable = (parsed == 1);
		break;

	// 不认识的选项，返回 argp 错误码
	default:
		return ARGP_ERR_UNKNOWN;
	}

	// 解析成功，返回 0
	return 0;
}

// argp 库的参数解析结构体
// options: 定义的选项数组
// parser: 解析回调函数
// args_doc: 无位置参数文档
// doc: 程序描述
static const struct argp g_argp = {
	.options = g_options,
	.parser = parse_opt,
	.args_doc = "",
	.doc = "cpu_watcher user space controller",
};

// 入口函数：解析命令行参数
// argc, argv：main 函数传进来的命令行原始数据
// opts：用来存储最终配置的结构体
int app_parse_args(int argc, char **argv, struct app_options *opts)
{
	// 安全检查：如果传入的结构体是空指针，直接返回错误
	if (!opts) {
		return -EINVAL;
	}

	opts->mode = APP_MODE_UNSET;   // 默认模式：上下文切换监控
	opts->poll_timeout_ms = 100;            // 默认超时：100ms
	opts->enable = true;                    // 默认启用监控

	// 调用 argp 库真正开始解析命令行参数
	// 最后一个参数 opts → 把解析结果存到这里
	if (argp_parse(&g_argp, argc, argv, 0, NULL, opts) != 0) {
		return -EINVAL; // 解析失败返回错误
	}

	// 如果用户没传 -m，自动打印帮助并退出
	if (opts->mode == APP_MODE_UNSET) {
		// 打印帮助
		argp_help(&g_argp, stdout, ARGP_HELP_STD_HELP, argv[0]);
		return -EINVAL; // 退出程序
	}

	return 0; // 解析成功
}

//////////////////////////////////////////////////////////////////

static void app_signal_handler(int sig)
{
	(void)sig;
	g_exit_requested = 1;
}

int app_setup_signal_handlers(void)
{
	struct sigaction sa = {0};

	sa.sa_handler = app_signal_handler; // 我们自己写的处理函数
	if (sigaction(SIGINT, &sa, NULL) < 0) {  // 处理 Ctrl+C
		return -errno;
	}
	if (sigaction(SIGTERM, &sa, NULL) < 0) { // 处理 kill 命令
		return -errno;
	}

	return 0;
}

// 主循环用来检查是否要退出
bool app_should_exit(void)
{
	return g_exit_requested != 0;
}

// 重置退出标记
void app_reset_exit_flag(void)
{
	g_exit_requested = 0;
}

// 功能：把枚举类型的 mode，转换成人类能看懂的字符串
// 输入：枚举值 APP_MODE_CONTEXT_SWITCH 或 APP_MODE_SYSCALL
// 输出：字符串 "context"、"syscall"、"unknown"
const char *app_mode_to_string(enum app_mode mode)
{
	switch (mode) {
		// 如果是上下文切换模式 → 返回字符串 "context"
		case APP_MODE_CONTEXT_SWITCH:
			return "context";
		
		// 如果是系统调用模式 → 返回字符串 "syscall"
		case APP_MODE_SYSCALL:
			return "syscall";

		// 如果是 TCP 建连延迟模式 → 返回字符串 "tcp_connect"
		case APP_MODE_TCP_CONNECT:
			return "tcp_connect";

		// 其他非法值 → 返回 "unknown"
		default:
			return "unknown";
	}
}
