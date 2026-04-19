#ifndef SYSCALL_DELAY_APP_H
#define SYSCALL_DELAY_APP_H

#include <stdbool.h>

// 运行系统调用延迟监控
int syscall_delay_run(int poll_timeout_ms, bool enable);

#endif
