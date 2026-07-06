#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "common/cli.h"
#include "common/types.h"
#include "proc_stat.h"
#include "proc_stat.h"
#include "mem/proc_stat/skel.h"
#include "common/logger.h"

/**
 * ringbuf 事件回调处理函数
 * 内核推送ProcStat_event事件后，libbpf自动调用此函数
 * @param ctx 自定义上下文，本程序未使用
 * @param data 内核下发的事件数据指针，对应 struct ProcStat_event
 * @param data_sz 事件数据长度，校验用，本程序忽略
 * @return 返回0代表正常消费事件
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	// 强制转换为我们定义的进程统计事件结构体
	const struct ProcStat_event *e = data;
	// 标记未使用参数，消除编译警告
	(void)ctx;
	(void)data_sz;

	struct tm *tm;
	char ts[32];  // 存放格式化后的时分秒时间字符串
	time_t t;

	// 获取当前系统时间戳
	time(&t);
	// 转换为本地时区时间结构
	tm = localtime(&t);
	// 格式化为 HH:MM:SS 存入ts缓冲区
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	// 格式化打印一行监控数据
	// 字段：时间 | PID | 总RSS物理页 | 匿名内存页 | 文件映射页 | 共享内存页
	printf("%-8s %-8d %-8ld %-8lld %-8lld %-8lld\n",
	       ts, e->pid, e->size, e->rssanon, e->rssfile, e->rssshmem);
	return 0;
}

/**
 * 进程内存统计采集主入口函数
 * @param poll_timeout_ms ringbuf阻塞轮询超时时间(ms)，超时无事件返回继续循环
 * @param enable true=开启内核采集；false=关闭内核采集
 * @return 0正常退出；正数/负数代表错误码
 */
int proc_stat_run(int poll_timeout_ms, bool enable)
{
	// BPF骨架对象，管理整个BPF程序、maps、挂载点生命周期
	struct proc_stat_bpf *skel = NULL;
	// ringbuf环形缓冲区管理句柄，用于接收内核事件
	struct ring_buffer *rb = NULL;
	// 下发到内核ctrl_map的控制开关结构体
	struct ProcStat_ctrl ctrl = { .enable = enable };
	// ctrl_map数组MAP固定key=0
	const int key = 0;
	// 统一错误码接收变量
	int err = 0;

	// 1. 打开并加载BPF字节码到内核，完成maps创建、程序校验
	skel = proc_stat_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed ProcStat BPF skeleton open&load\n");
		return 1;
	}

	// 2. 更新控制MAP，下发采集开关给内核BPF程序
	// BPF_ANY：key不存在则创建，存在则覆盖
	err = bpf_map__update_elem(skel->maps.ctrl_map,
							   &key, sizeof(key),
							   &ctrl, sizeof(ctrl),
							   BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Update ctrl_map fail: %d\n", err);
		goto cleanup; // 出错跳转到统一资源释放逻辑
	}

	// 3. 创建ringbuf读取器，绑定内核rb map与事件回调函数handle_event
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		goto cleanup;
	}

	// 4. 挂载kprobe到内核函数finish_task_switch，开始捕获进程切换事件
	err = proc_stat_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "BPF kprobe attach fail: %d\n", err);
		goto cleanup;
	}

	// 打印表头，对齐输出列
	printf("%-8s %-8s %-8s %-8s %-8s %-8s\n",
		   "TIME", "PID", "SIZE", "RSSANON", "RSSFILE", "RSSSHMEM");

	// 主循环：持续拉取内核事件，直到收到退出信号
	while (!app_should_exit()) {
		// 阻塞poll环形缓冲区，超时时间poll_timeout_ms
		err = ring_buffer__poll(rb, poll_timeout_ms);

		// 被信号中断(如Ctrl+C)，正常退出循环
		if (err == -EINTR) {
			err = 0;
			break;
		}
		// 其他负错误码，终止采集循环
		if (err < 0)
			break;
	}

cleanup:
	// 统一释放资源，防止内存泄漏
	ring_buffer__free(rb);        // 销毁ringbuf读取器
	proc_stat_bpf__destroy(skel); // 卸载BPF程序、销毁MAP、解除kprobe挂载

	// 错误码转正后返回，上层统一判断
	return err < 0 ? -err : 0;
}
