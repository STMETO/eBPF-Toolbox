#ifndef APP_COMMON_H
#define APP_COMMON_H

#include <stdbool.h>

/**
 * 程序运行模式枚举
 * 用来指定当前监控的类型：未设置 / 上下文切换 / 系统调用
 */
enum app_mode {
	APP_MODE_UNSET = 0,    	// 初始状态：未选择任何模式（必须用户指定）
	APP_MODE_CONTEXT_SWITCH, // 模式1：监控进程上下文切换
	APP_MODE_SYSCALL,      	// 模式2：监控系统调用
	APP_MODE_TCP_CONNECT,  	// 模式3：监控 TCP 建连延迟
	APP_MODE_MSGQUEUE,     	// 模式4：监控消息队列延迟
	APP_MODE_MUTEXLOCK,    	// 模式5：监控互斥锁延迟
	APP_MODE_PREEMPT,      	// 模式6：监控抢占延迟
	APP_MODE_SCHEDULE,     	// 模式7：监控调度延迟
};

/**
 * 程序全局配置结构体
 * 存储命令行解析后的所有配置参数
 */
struct app_options {
	enum app_mode mode;         // 运行模式（必须指定）
	int poll_timeout_ms;        // ring buffer 轮询超时时间（毫秒）
	bool enable;                // 是否启用监控功能
};

/**
 * 解析命令行参数
 * @argc: main函数的参数个数
 * @argv: main函数的参数列表
 * @opts: 存储解析结果的配置结构体
 * 返回：0成功，负数失败
 */
int app_parse_args(int argc, char **argv, struct app_options *opts);

/**
 * 注册信号处理函数（捕获Ctrl+C、kill等退出信号）
 * 返回：0成功，负数失败
 */
int app_setup_signal_handlers(void);

/**
 * 查询程序是否需要退出
 * 返回：true=需要退出，false=继续运行
 */
bool app_should_exit(void);

/**
 * 重置退出标志位
 * 让程序恢复到“不需要退出”的状态
 */
void app_reset_exit_flag(void);

/**
 * 将模式枚举转换为可读字符串（用于日志、打印）
 * @mode: 枚举类型的模式
 * 返回：字符串 "context" / "syscall" / "unknown"
 */
const char *app_mode_to_string(enum app_mode mode);

#endif
