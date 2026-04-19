#ifndef CONTEXT_SWITCH_DELAY_APP_H
#define CONTEXT_SWITCH_DELAY_APP_H

#include <stdbool.h>

// 运行上下文切换延迟监控
int context_switch_delay_run(int poll_timeout_ms, bool enable);

#endif
