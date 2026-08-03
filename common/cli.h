#ifndef COMMON_CLI_H
#define COMMON_CLI_H

#include <stdbool.h>
#include <stdint.h>

/**
 * 程序运行模式枚举
 * 用来指定当前监控的类型：未设置 / 上下文切换 / 系统调用
 */
enum app_mode {
	APP_MODE_UNSET = 0,    	// 初始状态：未选择任何模式（必须用户指定）
	APP_MODE_CONTEXT_SWITCH, // 模式1：监控进程上下文切换
    APP_MODE_PREEMPT,         // 抢占延迟
	APP_MODE_SYSCALL,      	// 系统调用延迟监控
	APP_MODE_TCP_MONITOR,  	// 模式3：监控 TCP 建连延迟
	APP_MODE_MSGQUEUE,     	// IPC：POSIX 消息队列驻留时间
	APP_MODE_MUTEXLOCK,    	// 锁：内核 mutex 慢路径等待

	// 文件系统监控 (5)
	APP_MODE_FS_OPEN,          // 模式8：监控 open 系统调用
	APP_MODE_FS_READ,          // 模式9：监控 read 系统调用
	APP_MODE_FS_WRITE,         // 模式10：监控 write 系统调用
    APP_MODE_BLOCK_IO,       // 磁盘 IO 延迟监控

	// 内存监控 (10)
	APP_MODE_DR_SNOOP,         // 模式20：直接回收追踪
	APP_MODE_OOM_KILLER,       // 模式21：OOM Killer 事件
	APP_MODE_SLAB_RATE,        // 模式22：Slab 分配速率
    APP_MODE_PROC_STAT,       // 进程内存状态

	// 网络监控 (2)
    APP_MODE_UDP_MONITOR,     // UDP 发送监控
};

/**
 * 程序全局配置结构体
 * 存储命令行解析后的所有配置参数
 */
struct app_options {
	enum app_mode mode;         // 首个运行模式（兼容单模块调用）
	uint64_t mode_mask;         // 逗号分隔的模块组合位图
	int poll_timeout_ms;        // ring buffer 轮询超时时间（毫秒）
	bool enable;
	int32_t target_pid;
	uint64_t min_delay_ns;
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
 * 由普通工作线程请求全局退出。
 * 与信号处理器使用的 sig_atomic_t 分离，内部通过 C11 原子变量同步。
 */
void app_request_exit(void);

/**
 * 重置退出标志位
 * 让程序恢复到“不需要退出”的状态
 */
void app_reset_exit_flag(void);

/**
 * 获取当前进程所在 PID namespace 的 nsfs 设备号和 inode。
 * 这两个值用于 bpf_get_ns_current_pid_tgid()，保证 -p 使用用户可见 PID。
 */
int app_get_pid_namespace(uint64_t *dev, uint64_t *ino);

/**
 * 将模式枚举转换为可读字符串（用于日志、打印）
 * @mode: 枚举类型的模式
 * 返回：字符串 "context" / "syscall" / "unknown"
 */
const char *app_mode_to_string(enum app_mode mode);

#endif
