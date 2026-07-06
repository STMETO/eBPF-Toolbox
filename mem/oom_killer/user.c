#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "common/cli.h"       
#include "common/types.h"     
#include "oom_killer.h"        
#include "oom_killer.h"      
#include "mem/oom_killer/skel.h" 
#include "common/logger.h"

/**
 * @brief RingBuffer事件回调函数，内核推送OOM事件后由libbpf自动调用
 * @param ctx 自定义上下文，本代码未使用
 * @param data 内核传递过来的OomKiller_event事件数据指针
 * @param data_sz 事件数据长度，本代码未做长度校验
 * @return int 回调返回值，0代表正常处理
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	// 转换数据为OOM事件结构体，屏蔽未使用参数警告
	const struct OomKiller_event *e = data;
	(void)ctx;
	(void)data_sz;

	struct tm *tm;
	char ts[32];
	time_t t;
	// 获取当前系统时间，格式化输出时分秒
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	// 格式化打印OOM告警信息：时间、触发OOM扫描PID、被杀死PID、触发进程虚拟内存页数、被杀进程名
	printf("%-8s TriggerPID=%-8u KillPID=%-8u Pages=%-8u Comm=%-16s\n",
	       ts, e->triggered_pid, e->oomkill_pid, e->mem_pages, e->comm);
	return 0;
}

/**
 * @brief OOM杀手监控主入口函数
 * @param poll_timeout_ms RingBuffer阻塞读取超时时间，单位ms
 * @param enable 采集总开关，true开启OOM监控，false关闭探针采集
 * @return int 0正常退出，正数为错误码
 */
int oom_killer_run(int poll_timeout_ms, bool enable)
{
	struct oom_killer_bpf *skel = NULL;   // BPF骨架句柄，管理所有BPF程序与Map
	struct ring_buffer *rb = NULL;        // libbpf环形缓冲区管理句柄
	struct OomKiller_ctrl ctrl = { .enable = enable }; // 下发给内核的开关配置
	const int key = 0;                    // ctrl_map数组map固定下标key
	int err = 0;

	// 1. 打开BPF字节码并加载到内核，自动初始化所有BPF Map
	skel = oom_killer_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed OomKiller\n");
		return 1;
	}

	// 2. 将启停开关写入内核ctrl_map，控制探针是否采集事件
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key), &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Control fail\n");
		goto cleanup; // 写入失败，跳转统一释放资源
	}

	// 3. 创建RingBuffer实例，绑定内核rb环形缓冲区fd，注册事件回调函数
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM; // 环形缓冲区创建失败，内存不足
		goto cleanup;
	}

	// 4. 将kprobe探针挂载到内核oom_kill_process函数
	err = oom_killer_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Attach fail\n");
		goto cleanup;
	}

	printf("Waiting for OOM events...\n");
	// 主循环：持续阻塞等待OOM事件，直到收到退出信号(Ctrl+C)
	while (!app_should_exit()) {
		// 阻塞读取环形缓冲区，超时时间poll_timeout_ms
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { // 被信号中断（如Ctrl+C），正常退出循环
			err = 0;
			break;
		}
		if (err < 0) // 发生其他读取错误，终止监控
			break;
	}

cleanup:
	// 资源逆序释放：先销毁环形缓冲区，再销毁BPF骨架
	ring_buffer__free(rb);
	oom_killer_bpf__destroy(skel);
	// 负数错误码转正后返回，无错误返回0
	return err < 0 ? -err : 0;
}
