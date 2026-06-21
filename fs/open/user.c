// 系统标准库
#include <errno.h>       // 错误码定义
#include <stdio.h>       // 打印输出
#include <string.h>      // strcmp、mem 操作
#include <unistd.h>      // readlink 等系统调用

// libbpf 核心库：操作 BPF 程序、Map、RingBuffer
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// 项目内部公共头
#include "common/cli.h"  // 通用命令行工具、app_should_exit() 退出信号判断
#include "common/types.h"// 公共类型、宏定义（FS_OPEN_PATH_SIZE 等）
#include "open.h"        // 和内核态共用：Open_event、Open_ctrl 结构体
#include "fs/open/skel.h"// bpftool 自动生成的骨架头：struct open_bpf、map/程序访问接口

/**
 * @brief RingBuffer 事件回调函数，内核每推送一条 Open_event 就触发一次
 * @param ctx       自定义上下文，这里传递 comm_cache map 的 fd
 * @param data      内核下发的事件数据指针，强转为 Open_event
 * @param data_sz   事件字节长度，用于校验
 * @return int      固定返回0，无特殊含义
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	// 把 ringbuf 二进制数据转换成业务事件结构体
	const struct Open_event *e = data;
	// 取出上下文里存的 comm_cache map 文件描述符，用于查表进程名
	int map_fd = *(int *)ctx;

	// 临时缓冲区：/proc/pid/fd/x 路径、readlink 读出的真实文件路径、进程名
	char fd_path[FS_OPEN_PATH_SIZE];
	char actual_path[FS_OPEN_PATH_SIZE];
	char comm[TASK_COMM_LEN];

	/*
	 * 逻辑说明：
	 * e->n_ = max_fds，进程最大允许FD编号；
	 * 循环遍历 0 ~ max_fds-1 所有可能文件描述符
	 * 通过 /proc/[pid]/fd/[fdnum] 软链接比对，找出本次 openat 分配的 fd
	 */
	for (int i = 0; i < e->n_; ++i) {
		// 拼接 /proc/pid/fd/i 路径，用于读取软链接
		snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", e->pid_, i);
		// readlink 读取软链接指向的真实文件路径，不自动追加'\0'
		ssize_t len = readlink(fd_path, actual_path, sizeof(actual_path) - 1);
		if (len != -1) {
			// 手动补字符串结束符
			actual_path[len] = '\0';
			// 软链接真实路径 == 本次 openat 打开的文件路径，匹配成功
			if (strcmp(e->path_name_, actual_path) == 0) {
				// 去内核 comm_cache map 根据 PID 查询进程名
				if (bpf_map_lookup_elem(map_fd, &e->pid_, &comm) == 0) {
					// 查询成功：打印 文件路径 | fd号 | PID | 进程名
					printf("%-8s  %-8d  %-8d  %-8s\n",
					       e->path_name_, i, e->pid_, comm);
				} else {
					// map 中无该PID缓存，进程名显示?
					printf("%-8s  %-8d  %-8d  %-8s\n",
					       e->path_name_, i, e->pid_, "?");
				}
			}
		}
	}
	return 0;
}

/**
 * @brief 采集主逻辑入口
 * @param poll_timeout_ms ringbuffer 轮询超时时间(ms)
 * @param enable 下发给内核的采集总开关
 * @return 0成功，非0失败码
 */
int open_run(int poll_timeout_ms, bool enable)
{
	struct open_bpf *skel = NULL;  // libbpf 自动生成的 BPF 骨架，管理所有map+程序
	struct ring_buffer *rb = NULL;  // ringbuffer 管理句柄
	struct Open_ctrl ctrl = { .enable = enable }; // 下发内核的控制配置
	const int key = 0;             // ctrl_map 数组map固定key=0
	int err = 0;

	// 1. 打开并加载 BPF 字节码到内核（CO-RE 骨架标准接口）
	skel = open_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load Open BPF skeleton\n");
		return 1;
	}

	// 2. 向 ctrl_map 写入采集开关 enable，内核程序会读取该配置
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Failed to set control switch: %d\n", err);
		goto cleanup; // 写入失败，直接走资源释放流程
	}

	// 3. 获取 comm_cache 哈希map的fd，后续回调中用来查表进程名
	int map_fd = bpf_map__fd(skel->maps.comm_cache);
	if (map_fd < 0) {
		fprintf(stderr, "Failed to get comm_cache map fd\n");
		err = -1;
		goto cleanup;
	}

	// 4. 创建 RingBuffer 实例，绑定内核rb map、事件回调、自定义上下文(map_fd)
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &map_fd, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	// 5. 将 BPF tracepoint 程序挂载到内核埋点 tracepoint/syscalls/sys_enter_openat
	err = open_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	// 打印表头
	printf("%-8s  %-8s  %-8s  %-8s\n",
	       "FILENAME", "FD", "PID", "COMM");

	// 6. 循环轮询 ringbuffer，持续接收内核上报事件
	while (!app_should_exit()) {
		// 阻塞poll，超时时间 poll_timeout_ms，有事件立刻触发 handle_event
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) {
			// 被信号中断(Ctrl+C)，正常退出循环
			err = 0;
			break;
		}
		if (err < 0) {
			// 轮询发生未知错误，跳出循环终止采集
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	// 资源逆序释放：先销毁ringbuffer，再销毁整个BPF骨架
	ring_buffer__free(rb);
	open_bpf__destroy(skel);
	// 统一转换错误码为正数返回
	return err < 0 ? -err : 0;
}
