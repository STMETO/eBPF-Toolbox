/*
本eBPF内核程序基于tracepoint埋点监控Linux内核vmscan直接内存回收事件：
1. 挂载`mm_vmscan_direct_reclaim_begin`回收开始钩子，抓取线程PID/TID、进程名、起始时间戳，读取整机vm_stat内存快照存入哈希表临时缓存；
2. 挂载`mm_vmscan_direct_reclaim_end`回收结束钩子，匹配同线程起始记录，计算回收阻塞耗时、读取本次回收页面数；
3. 组装完整监控事件写入环形缓冲区，下发给用户态程序消费打印；
4. 依靠BPF CO-RE实现多内核版本兼容，精准捕获业务进程因同步内存回收产生的延迟毛刺，用于内存压力与性能抖动排查。
*/

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "common/cli.h"
#include "common/types.h"
#include "dr_snoop.h"
#include "mem/dr_snoop/skel.h"
#include "common/logger.h"

#define KALLSYMS_PATH "/proc/kallsyms"		// /proc/kallsyms：内核符号表文件，用于读取全局变量虚拟地址
#define VM_STAT_SYMBOL "vm_stat"			// 要查找的内核全局变量名：整机内存统计结构体 vm_stat
#define VM_ZONE_STAT_SYMBOL "vm_zone_stat"	// 备用内核符号（分区内存统计，本程序未使用）
#define PAGE_SHIFT 12						// Linux 默认页大小 4KB = 2^12 Byte
#define K(x) ((x) << (PAGE_SHIFT - 10))		// 页数转 KB：page <<12 转字节 /1024 = page << (12-10)

/**
 * @brief 读取 /proc/kallsyms 获取内核全局符号的虚拟地址
 * @param addr 出参，存放找到的 vm_stat 内核虚拟地址
 * @return 成功返回0，找不到/打开文件失败返回-1
 */
static int get_vm_stat_addr(__u64 *addr)
{
    // 打开内核符号文件
	FILE *file = fopen(KALLSYMS_PATH, "r");
	if (!file) 
        return -1;

	char line[256];
    // 逐行遍历符号表
	while (fgets(line, sizeof(line), file)) {
		unsigned long address; 
        char symbol[256];
        // 解析行格式：地址 权限 符号名，忽略中间权限字段
		if (sscanf(line, "%lx %*s %s", &address, symbol) == 2) {
            // 匹配目标符号 vm_stat
			if (strcmp(symbol, VM_STAT_SYMBOL) == 0 ||
			    strcmp(symbol, VM_ZONE_STAT_SYMBOL) == 0) {
				*addr = address; 
                fclose(file); 
                return 0;
			}
		}
	}
    // 遍历完毕未找到符号，释放文件
	fclose(file);
	return -1;
}

/**
 * @brief RingBuf 事件回调函数，内核推送事件后触发打印输出
 * @param ctx 自定义上下文（本程序未使用）
 * @param data 内核下发的 data_t 完整事件结构体指针
 * @param data_sz 事件数据长度
 * @return 0 正常处理完成
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    // 强制转换为我们定义的事件结构体
	const struct data_t *e = data; 
    // 消除未使用参数告警
    (void)ctx; 
    (void)data_sz;

	struct tm *tm; 
    char ts[32]; 
    time_t t;
    // 获取当前系统本地时间，格式化打印
	time(&t); 
    tm = localtime(&t); 
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    // e->delta：纳秒级延迟，转微秒、毫秒，保留小数微秒
	__u64 delta_us = e->delta / 1000;
    __u64 delta_ms = delta_us / 1000;
    __u64 fractional_us = delta_us % 1000;

    // 格式化输出一行监控日志：时间、进程名、PID、空闲内存KB、回收阻塞延迟ms.xxx
	printf("%-8s %-16s %-7llu %-9llu %llu.%02llu\n",
	       ts, e->name, e->id >> 32, K(e->vm_stat[NR_FREE_PAGES]), delta_ms, fractional_us);
	return 0;
}

/**
 * @brief dr_snoop 主业务入口函数
 * 完整流程：获取vm_stat地址 -> 加载BPF骨架 -> 写入内核地址到BPF map -> 创建ringbuf -> 挂载tracepoint -> 循环消费事件
 * @param poll_timeout_ms ringbuf轮询超时时间(ms)，无事件时阻塞等待时长
 * @param enable 全局监控开关（当前骨架暂未使用ctrl结构体）
 * @return 0正常退出，非0异常错误码
 */
int dr_snoop_run(int poll_timeout_ms, bool enable)
{
    // BPF骨架对象，自动生成的dr_snoop_bpf结构体，管理maps、progs、挂载点
	struct dr_snoop_bpf *skel = NULL;
    // 环形缓冲区管理句柄，用于接收内核上报事件
	struct ring_buffer *rb = NULL;
    // BPF控制结构体（预留，当前代码未写入map使用）
	struct DrSnoop_ctrl ctrl = { .enable = enable };
    // vm_stat_map数组map唯一下标key固定为0
	const int key = 0; 
    int err = 0;

    // 存储内核全局vm_stat虚拟地址
	__u64 vm_stat_addr; 
    __u32 map_key = 0;

	// 步骤1：读取内核符号，拿到 vm_stat 全局结构体地址
	if (get_vm_stat_addr(&vm_stat_addr) != 0) {
		fprintf(stderr, "Failed to get vm_stat address\n"); 
        return 1;
	}

	// 步骤2：打开并加载编译好的BPF字节码（CO-RE骨架）
	skel = dr_snoop_bpf__open_and_load();
	if (!skel) { 
        fprintf(stderr, "Failed DrSnoop\n"); 
        return 1; 
    }

	// 步骤3：把vm_stat内核地址写入BPF侧 vm_stat_map，供tracepoint钩子读取
	err = bpf_map_update_elem(bpf_map__fd(skel->maps.vm_stat_map), &map_key, &vm_stat_addr, BPF_ANY);
	if (err) { 
        fprintf(stderr, "Failed to update vm_stat_map: %s\n", strerror(errno)); 
        goto cleanup; 
    }

	// 步骤4：初始化RingBuf，绑定事件回调handle_event
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { 
        err = -ENOMEM; 
        goto cleanup; 
    }

	// 步骤5：挂载所有tracepoint钩子（begin / end 两个vmscan埋点）
	err = dr_snoop_bpf__attach(skel);
	if (err) { 
        fprintf(stderr, "Attach fail\n"); 
        goto cleanup; 
    }

	// 打印表头，日志字段说明
	printf("%-8s %-16s %-7s %-9s %-7s\n", "TIME", "COMM", "PID", "FREE(KB)", "LAT(ms)");

	// 步骤6：事件循环，持续拉取内核上报的direct reclaim事件
	while (!app_should_exit()) {
        // 阻塞poll环形缓冲区，超时poll_timeout_ms后返回
		err = ring_buffer__poll(rb, poll_timeout_ms);
        // 收到中断信号(Ctrl+C)，正常退出循环
		if (err == -EINTR) { 
            err = 0; 
            break; 
        }
        // poll返回负数代表底层错误，跳出循环
		if (err < 0) 
            break;
	}

// 统一资源释放出口，防止内存泄漏
cleanup:
    // 销毁环形缓冲区
	ring_buffer__free(rb);
    // 销毁BPF骨架，卸载eBPF程序、释放所有BPF map
	dr_snoop_bpf__destroy(skel);
    // 标准化错误码输出
	return err < 0 ? -err : 0;
}
