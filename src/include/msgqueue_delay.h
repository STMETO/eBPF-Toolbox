#ifndef MSGQUEUE_DELAY_APP_H
#define MSGQUEUE_DELAY_APP_H

#include <stdbool.h>

// 运行消息队列延迟监控
int msgqueue_delay_run(int poll_timeout_ms, bool enable);

#endif
