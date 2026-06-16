#ifndef TCP_CONNECT_DELAY_APP_H
#define TCP_CONNECT_DELAY_APP_H

#include <stdbool.h>

// 运行 TCP 建连延迟监控
int tcp_connect_delay_run(int poll_timeout_ms, bool enable);

#endif
