#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/cli.h"
#include "common/registry.h"

static volatile sig_atomic_t g_exit_requested = 0;

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

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct app_options *opts = state->input;
	char *end = NULL;

	switch (key) {
	case 'm': {
		const struct module_entry *m = arg ? find_by_name(arg) : NULL;
		if (m) { opts->mode = m->mode; break; }
		argp_error(state, "invalid mode: %s (已支持: %s)", arg ? arg : "?", build_mode_str());
		break;
	}
	case 't':
		opts->poll_timeout_ms = (int)strtol(arg, &end, 10);
		if (opts->poll_timeout_ms <= 0 || opts->poll_timeout_ms > 60000)
			argp_error(state, "invalid timeout: %s (1-60000)", arg);
		break;
	case 'e':
		opts->enable = (strtol(arg, &end, 10) == 1);
		break;
	case 'p':
		opts->target_pid = (int)strtol(arg, &end, 10);
		break;
	case 'd':
		opts->min_delay_ns = (int)strtol(arg, &end, 10);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp g_argp = {
	.options = g_options, .parser = parse_opt,
	.args_doc = "", .doc = "eBPF 性能监控工具集",
};

int app_parse_args(int argc, char **argv, struct app_options *opts)
{
	if (!opts) return -EINVAL;
	opts->mode = APP_MODE_UNSET;
	opts->poll_timeout_ms = 100;
	opts->enable = true;
	opts->target_pid = 0;
	opts->min_delay_ns = 0;
	if (argp_parse(&g_argp, argc, argv, 0, NULL, opts) != 0)
		return -EINVAL;
	if (opts->mode == APP_MODE_UNSET) {
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

static void app_signal_handler(int sig) { (void)sig; g_exit_requested = 1; }

int app_setup_signal_handlers(void)
{
	struct sigaction sa = {.sa_handler = app_signal_handler};
	if (sigaction(SIGINT,  &sa, NULL) < 0) return -errno;
	if (sigaction(SIGTERM, &sa, NULL) < 0) return -errno;
	return 0;
}

bool app_should_exit(void) { return g_exit_requested != 0; }
void app_reset_exit_flag(void) { g_exit_requested = 0; }
