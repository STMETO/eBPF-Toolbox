#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <linux/types.h>

#include "common/cli.h"
#include "common/types.h"
#include "tcp_connect.h"
#include "net/tcp_connect/skel.h"
#include "common/logger.h"

/*
 * 解析并打印事件
 */
static void handle_event(void *data, size_t data_sz)
{
	char saddr[INET6_ADDRSTRLEN];
	char daddr[INET6_ADDRSTRLEN];
	const struct event *e = data;

	/* 转换 IP 地址 */
	if (e->af == AF_INET) {
		inet_ntop(AF_INET, &e->saddr_v4, saddr, sizeof(saddr));
		inet_ntop(AF_INET, &e->daddr_v4, daddr, sizeof(daddr));
	} else if (e->af == AF_INET6) {
		inet_ntop(AF_INET6, &e->saddr_v6, saddr, sizeof(saddr));
		inet_ntop(AF_INET6, &e->daddr_v6, daddr, sizeof(daddr));
	} else {
		strcpy(saddr, "unknown");
		strcpy(daddr, "unknown");
	}

	/* 打印 TCP 建连延迟 */
	printf("PID: %-6d COMM: %-12s | LATENCY: %8llu us | "
		   "SRC: %-16s:%-5d DST: %-16s:%-5d\n",
		   e->tgid,
		   e->comm,
		   (unsigned long long)e->delta_us,
		   saddr,
		   ntohs(e->lport),
		   daddr,
		   ntohs(e->dport));
}

/*
 * perf buffer 回调
 */
static void perf_buf_cb(void *ctx, int cpu, void *data, __u32 data_sz)
{
	(void)ctx;
	(void)cpu;
	handle_event(data, data_sz);
}

/*
 * 入口函数：运行「TCP 建连延迟监控」
 * poll_timeout_ms：perf buffer 轮询超时（毫秒）
 * enable：是否启用监控（true=启动，false=关闭）
 */
int tcp_connect_run(int poll_timeout_ms, bool enable)
{
	struct tcp_connect_bpf *skel;
	struct perf_buffer *pb = NULL;
	struct TcpConnect_Delay_ctrl ctrl;
	int err;

	/* 1. 加载 BPF 程序 */
	skel = tcp_connect_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* 2. 开启/关闭监控 */
	memset(&ctrl, 0, sizeof(ctrl));
	ctrl.enable = enable;
	err = bpf_map__update_elem(skel->maps.ctrl_map,
							   &(const int){0}, sizeof(int),
							   &ctrl, sizeof(ctrl),
							   BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Failed to set ctrl: %s\n", strerror(-err));
		goto cleanup;
	}

	/* 3. 附加探针 */
	err = tcp_connect_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF program\n");
	log_banner("TCP 建连延迟监控", enable);
		goto cleanup;
	}

	/* 4. 创建 perf buffer 监听事件 */
	pb = perf_buffer__new(bpf_map__fd(skel->maps.events),
						  8, perf_buf_cb, NULL, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "Failed to create perf buffer\n");
		goto cleanup;
	}

	/* 开始监听 */
	while (!app_should_exit()) {
		err = perf_buffer__poll(pb, poll_timeout_ms);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "perf buffer poll failed: %s\n", strerror(-err));
			break;
		}
	}

cleanup:
	/* 清理 */
	perf_buffer__free(pb);
	tcp_connect_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
