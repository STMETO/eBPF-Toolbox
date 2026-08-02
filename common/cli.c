#include <argp.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "common/cli.h"
#include "common/registry.h"

/*
 * 信号处理器只能执行 async-signal-safe 的简单写操作，因此单独使用
 * sig_atomic_t 记录 SIGINT/SIGTERM。模块工作线程通过 C11 原子变量通知
 * 其他线程退出，避免多个 pthread 对同一普通变量读写形成数据竞争。
 */
static volatile sig_atomic_t g_signal_exit_requested = 0;
static atomic_bool g_thread_exit_requested = ATOMIC_VAR_INIT(false);

static char g_mode_str[512];
static const char *build_mode_str(void)
{
	if (g_mode_str[0]) return g_mode_str;
	int pos = 0;
	for (int i = 0; MODULE_TABLE[i].name; i++) {
		if (i > 0) g_mode_str[pos++] = '|';
		const char *s = MODULE_TABLE[i].name;
		while (*s && pos < (int)sizeof(g_mode_str) - 1) g_mode_str[pos++] = *s++;
	}
	g_mode_str[pos] = '\0';
	return g_mode_str;
}

static const struct argp_option g_options[] = {
	{"mode",    'm', "MODE", 0, "监控模式 (见下方列表)"},
	{"timeout", 't', "MS",   0, "轮询超时(毫秒)"},
	{"enable",  'e', "0|1",  0, "是否启用"},
	{"pid",     'p', "PID",  0, "目标 PID，0=全部"},
	{"delay",   'd', "NS",   0, "最小延迟阈值(纳秒)"},
	{0}
};

static const struct module_entry *find_by_name(const char *name)
{
	for (int i = 0; MODULE_TABLE[i].name; i++)
		if (strcmp(name, MODULE_TABLE[i].name) == 0) return &MODULE_TABLE[i];
	return NULL;
}

static const struct module_entry *find_by_mode(enum app_mode mode)
{
	for (int i = 0; MODULE_TABLE[i].name; i++)
		if (MODULE_TABLE[i].mode == mode) return &MODULE_TABLE[i];
	return NULL;
}

static long parse_long_arg(struct argp_state *state, const char *name,
			   const char *arg, long min, long max)
{
	char *end = NULL;
	long value;

	errno = 0;
	value = strtol(arg, &end, 10);
	if (errno == ERANGE || end == arg || *end != '\0' || value < min || value > max)
		argp_error(state, "invalid %s: %s (%ld-%ld)", name, arg, min, max);
	return value;
}

/*
 * 延迟阈值允许覆盖 uint64_t 全范围。这里不能使用 atoi/atol：它们既无法
 * 区分非法字符，也无法可靠报告溢出；同时显式拒绝负号，防止 strtoull
 * 按模转换后把 -1 误当成 UINT64_MAX。
 */
static uint64_t parse_u64_arg(struct argp_state *state, const char *name,
			      const char *arg)
{
	char *end = NULL;
	unsigned long long value;

	if (!arg || arg[0] == '-')
		argp_error(state, "invalid %s: %s (must be an unsigned integer)",
			   name, arg ? arg : "?");
	errno = 0;
	value = strtoull(arg, &end, 10);
	if (errno == ERANGE || end == arg || *end != '\0')
		argp_error(state, "invalid %s: %s (must be an unsigned integer)", name, arg);
	return (uint64_t)value;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct app_options *opts = state->input;

	switch (key) {
	case 'm': {
		char modes[512];
		char *save = NULL;
		char *name;

		if (!arg || strlen(arg) >= sizeof(modes))
			argp_error(state, "invalid mode list (已支持: %s)", build_mode_str());
		memcpy(modes, arg, strlen(arg) + 1);
		for (name = strtok_r(modes, ",", &save); name;
		     name = strtok_r(NULL, ",", &save)) {
			const struct module_entry *m = find_by_name(name);
			if (!m)
				argp_error(state, "invalid mode: %s (已支持: %s)",
					   name, build_mode_str());
			if (m->mode >= 64)
				argp_error(state, "mode id is too large: %s", name);
			opts->mode_mask |= 1ULL << m->mode;
			if (opts->mode == APP_MODE_UNSET)
				opts->mode = m->mode;
		}
		if (!opts->mode_mask)
			argp_error(state, "empty mode list");
		break;
	}
	case 't':
		opts->poll_timeout_ms = (int)parse_long_arg(state, "timeout", arg, 1, 60000);
		break;
	case 'e':
		opts->enable = parse_long_arg(state, "enable", arg, 0, 1) == 1;
		break;
	case 'p':
		opts->target_pid = (int32_t)parse_long_arg(state, "pid", arg, 0, INT32_MAX);
		break;
	case 'd':
		opts->min_delay_ns = parse_u64_arg(state, "delay", arg);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const char g_doc[] =
	"eBPF 性能监控工具集\n\n"
	"监控模式 (-m):\n"
	"  调度:    context, preempt\n"
	"  锁:      mutexlock\n"
	"  IPC:     msgqueue\n"
	"  系统调用: syscall\n"
	"  文件:    fs_open, fs_read, fs_write, block_io\n"
	"  内存:    dr_snoop, oom_killer, proc_stat, slab_rate\n"
	"  网络:    tcp_monitor, udp_monitor\n\n"
	"多个模式用逗号分隔。\n"
	"示例: sudo ./test -m context,mutexlock,fs_open -p 1234 -d 100000 -t 100";

static const struct argp g_argp = {
	.options = g_options, .parser = parse_opt,
	.args_doc = "", .doc = g_doc,
};

int app_parse_args(int argc, char **argv, struct app_options *opts)
{
	if (!opts) return -EINVAL;
	opts->mode = APP_MODE_UNSET;
	opts->mode_mask = 0;
	opts->poll_timeout_ms = 100;
	opts->enable = true;
	opts->target_pid = 0;
	opts->min_delay_ns = 0;
	if (argp_parse(&g_argp, argc, argv, 0, NULL, opts) != 0)
		return -EINVAL;
	if (opts->mode == APP_MODE_UNSET || opts->mode_mask == 0) {
		argp_help(&g_argp, stdout, ARGP_HELP_STD_HELP, argv[0]);
		return -EINVAL;
	}
	return 0;
}

const char *app_mode_to_string(enum app_mode mode)
{
	const struct module_entry *m = find_by_mode(mode);
	return m ? m->name : "unknown";
}

static void app_signal_handler(int sig)
{
	(void)sig;
	g_signal_exit_requested = 1;
}

int app_setup_signal_handlers(void)
{
	struct sigaction sa = {.sa_handler = app_signal_handler};
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGINT,  &sa, NULL) < 0) return -errno;
	if (sigaction(SIGTERM, &sa, NULL) < 0) return -errno;
	return 0;
}

bool app_should_exit(void)
{
	return g_signal_exit_requested != 0 ||
	       atomic_load_explicit(&g_thread_exit_requested, memory_order_relaxed);
}

void app_request_exit(void)
{
	atomic_store_explicit(&g_thread_exit_requested, true, memory_order_relaxed);
}

void app_reset_exit_flag(void)
{
	/* 只能在启动工作线程之前调用；运行期间复位会吞掉真实退出请求。 */
	g_signal_exit_requested = 0;
	atomic_store_explicit(&g_thread_exit_requested, false, memory_order_relaxed);
}

int app_get_pid_namespace(uint64_t *dev, uint64_t *ino)
{
	struct stat st;

	if (!dev || !ino)
		return -EINVAL;
	/*
	 * bpf_get_ns_current_pid_tgid() 要求传入 nsfs 的 st_dev/st_ino，不能
	 * 直接传 namespace 文件描述符或 /proc 中看到的 PID。
	 */
	if (stat("/proc/self/ns/pid", &st) < 0)
		return -errno;
	*dev = (uint64_t)st.st_dev;
	*ino = (uint64_t)st.st_ino;
	return 0;
}
