#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "app_common.h"

static volatile sig_atomic_t g_exit_requested = 0;

static const struct argp_option g_options[] = {
	{"mode", 'm', "context|syscall", 0, "监控模式"},
	{"timeout", 't', "MILLISECONDS", 0, "ring buffer 轮询超时(毫秒)"},
	{"enable", 'e', "0|1", 0, "是否启用监控(1=启用, 0=禁用)"},
	{0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct app_options *opts = state->input;
	char *end = NULL;
	long parsed = 0;

	switch (key) {
	case 'm':
		if (strcmp(arg, "context") == 0) {
			opts->mode = APP_MODE_CONTEXT_SWITCH;
		} else if (strcmp(arg, "syscall") == 0) {
			opts->mode = APP_MODE_SYSCALL;
		} else {
			argp_error(state, "invalid mode: %s (use context|syscall)", arg);
		}
		break;
	case 't':
		errno = 0;
		parsed = strtol(arg, &end, 10);
		if (errno != 0 || end == arg || *end != '\0' || parsed <= 0 || parsed > 60000) {
			argp_error(state, "invalid timeout: %s (1-60000)", arg);
		}
		opts->poll_timeout_ms = (int)parsed;
		break;
	case 'e':
		errno = 0;
		parsed = strtol(arg, &end, 10);
		if (errno != 0 || end == arg || *end != '\0' || (parsed != 0 && parsed != 1)) {
			argp_error(state, "invalid enable: %s (0|1)", arg);
		}
		opts->enable = (parsed == 1);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static const struct argp g_argp = {
	.options = g_options,
	.parser = parse_opt,
	.args_doc = "",
	.doc = "cpu_watcher user space controller",
};

static void app_signal_handler(int sig)
{
	(void)sig;
	g_exit_requested = 1;
}

int app_parse_args(int argc, char **argv, struct app_options *opts)
{
	if (!opts) {
		return -EINVAL;
	}

	opts->mode = APP_MODE_CONTEXT_SWITCH;
	opts->poll_timeout_ms = 100;
	opts->enable = true;

	if (argp_parse(&g_argp, argc, argv, 0, NULL, opts) != 0) {
		return -EINVAL;
	}

	return 0;
}

int app_setup_signal_handlers(void)
{
	struct sigaction sa = {0};

	sa.sa_handler = app_signal_handler;
	if (sigaction(SIGINT, &sa, NULL) < 0) {
		return -errno;
	}
	if (sigaction(SIGTERM, &sa, NULL) < 0) {
		return -errno;
	}

	return 0;
}

bool app_should_exit(void)
{
	return g_exit_requested != 0;
}

void app_reset_exit_flag(void)
{
	g_exit_requested = 0;
}

const char *app_mode_to_string(enum app_mode mode)
{
	switch (mode) {
	case APP_MODE_CONTEXT_SWITCH:
		return "context";
	case APP_MODE_SYSCALL:
		return "syscall";
	default:
		return "unknown";
	}
}
