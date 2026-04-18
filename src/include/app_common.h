#ifndef APP_COMMON_H
#define APP_COMMON_H

#include <stdbool.h>

enum app_mode {
	APP_MODE_CONTEXT_SWITCH = 0,
	APP_MODE_SYSCALL,
};

struct app_options {
	enum app_mode mode;
	int poll_timeout_ms;
	bool enable;
};

int app_parse_args(int argc, char **argv, struct app_options *opts);
int app_setup_signal_handlers(void);
bool app_should_exit(void);
void app_reset_exit_flag(void);
const char *app_mode_to_string(enum app_mode mode);

#endif
