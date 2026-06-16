#ifndef PREEMPT_DELAY_APP_H
#define PREEMPT_DELAY_APP_H

#include <stdbool.h>

// 运行抢占延迟监控
int preempt_delay_run(int poll_timeout_ms, bool enable);

#endif
