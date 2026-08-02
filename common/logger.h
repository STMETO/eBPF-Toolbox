#ifndef COMMON_LOGGER_H
#define COMMON_LOGGER_H

#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>

/* ── Colors ──────────────────────────────────────────────── */
#define C_GREEN  "\033[32m"
#define C_YELLOW "\033[33m"
#define C_RED    "\033[31m"
#define C_CYAN   "\033[36m"
#define C_BOLD   "\033[1m"
#define C_RESET  "\033[0m"

/* 组合观测时，一个模块的一整行/面板应作为不可分割的输出块。 */
static inline void log_output_lock(void) { flockfile(stdout); }
static inline void log_output_unlock(void) { funlockfile(stdout); }

/* ── Timestamp ───────────────────────────────────────────── */
static inline void log_ts(char *buf, size_t len)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	struct tm tm;
	localtime_r(&ts.tv_sec, &tm);
	snprintf(buf, len, "%02d:%02d:%02d.%03d",
		 tm.tm_hour, tm.tm_min, tm.tm_sec,
		 (int)(ts.tv_nsec / 1000000));
}

/* ── Line-oriented LOG() macro ──────────────────────────────
 *  Usage:  LOG("PID: %-6d COMM: %-16s LAT: %-8" PRIu64 " us",
 *              pid, comm, lat_us);
 *  Output: [14:05:32.123] PID: 1234   COMM: myapp       LAT: 56      us
 */
#define LOG(fmt, ...) do { \
	char _ts[16]; log_ts(_ts, sizeof(_ts)); \
	fprintf(stdout, C_BOLD "[%s]" C_RESET " " fmt, _ts, ##__VA_ARGS__); \
	fflush(stdout); \
} while(0)

/* ── Header row (no timestamp, just column titles) ───────── */
#define LOG_HDR(fmt, ...) do { \
	fprintf(stdout, "%-16s " fmt "\n", "", ##__VA_ARGS__); \
} while(0)
#define LOG_SEP() fprintf(stdout, "%s\n", \
	"----------------------------------------------------------------")

/* ── Banner ──────────────────────────────────────────────── */
static inline void log_banner(const char *name, bool enable)
{
	printf(C_CYAN C_BOLD "═════════════════════════════════════════\n" C_RESET);
	printf(C_CYAN "  %s — 已%s\n" C_RESET, name, enable ? "启动" : "关闭");
	printf(C_CYAN "  Ctrl+C 退出\n" C_RESET);
	printf(C_CYAN C_BOLD "═════════════════════════════════════════\n" C_RESET);
}

/* ── Colored duration (inline, no newline) ───────────────── */
static inline void log_col_ns(uint64_t ns, uint64_t warn, uint64_t crit)
{
	if      (ns >= crit) fprintf(stdout, C_RED    "%8" PRIu64 " ns" C_RESET, ns);
	else if (ns >= warn) fprintf(stdout, C_YELLOW "%8" PRIu64 " ns" C_RESET, ns);
	else                 fprintf(stdout, C_GREEN  "%8" PRIu64 " ns" C_RESET, ns);
}

static inline void log_col_us(uint64_t us, uint64_t warn, uint64_t crit)
{
	if      (us >= crit) fprintf(stdout, C_RED    "%8" PRIu64 " us" C_RESET, us);
	else if (us >= warn) fprintf(stdout, C_YELLOW "%8" PRIu64 " us" C_RESET, us);
	else                 fprintf(stdout, C_GREEN  "%8" PRIu64 " us" C_RESET, us);
}

#endif
