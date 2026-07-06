#ifndef COMMON_CLI_H
#define COMMON_CLI_H

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
	APP_MODE_SCHEDULE,         // 模式7：监控调度延迟

	// 文件系统监控 (5)
	APP_MODE_FS_OPEN,          // 模式8：监控 open 系统调用
	APP_MODE_FS_READ,          // 模式9：监控 read 系统调用
	APP_MODE_FS_WRITE,         // 模式10：监控 write 系统调用
	APP_MODE_DISK_IO_VISIT,    // 模式11：监控磁盘 I/O 访问
	APP_MODE_BLOCK_RQ_ISSUE,   // 模式12：监控块设备 I/O 请求

	// 内存监控 (10)
	APP_MODE_PAF,              // 模式13：页面分配失败分析
	APP_MODE_PR,               // 模式14：页面回收报告
	APP_MODE_PROC_STAT,        // 模式15：进程内存状态
	APP_MODE_SYS_STAT,         // 模式16：系统内存状态
	APP_MODE_MEM_LEAK,         // 模式17：内存泄漏检测
	APP_MODE_FRAG_INFO,        // 模式18：内存碎片分析
	APP_MODE_NUMA_FRAG_INFO,   // 模式19：NUMA 碎片信息
	APP_MODE_DR_SNOOP,         // 模式20：直接回收追踪
	APP_MODE_OOM_KILLER,       // 模式21：OOM Killer 事件
	APP_MODE_SLAB_RATE,        // 模式22：Slab 分配速率
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
