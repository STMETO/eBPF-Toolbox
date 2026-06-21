#ifndef OOM_KILLER_APP_H
#define OOM_KILLER_APP_H
#include <stdbool.h>
int oom_killer_run(int poll_timeout_ms, bool enable);
#endif
