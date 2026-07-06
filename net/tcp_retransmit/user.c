#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <bpf/libbpf.h>

#include "common/cli.h"
#include "common/types.h"
#include "tcp_retransmit.h"
#include "net/tcp_retransmit/skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	char saddr[INET6_ADDRSTRLEN] = {};
	char daddr[INET6_ADDRSTRLEN] = {};
	const struct TcpRetransmit_event *e = data;
	(void)ctx;
	(void)data_sz;

	if (e->af == AF_INET) {
		inet_ntop(AF_INET,  &e->saddr_v4, saddr, sizeof(saddr));
		inet_ntop(AF_INET,  &e->daddr_v4, daddr, sizeof(daddr));
	} else if (e->af == AF_INET6) {
		inet_ntop(AF_INET6, &e->saddr_v6, saddr, sizeof(saddr));
		inet_ntop(AF_INET6, &e->daddr_v6, daddr, sizeof(daddr));
	}

	printf("PID: %-6d COMM: %-16s | %-16s:%-5d -> %-16s:%-5d | STATE: %d\n",
	       e->pid, e->comm,
	       saddr, ntohs(e->sport),
	       daddr, ntohs(e->dport),
	       e->state);

	return 0;
}

int tcp_retransmit_run(int poll_timeout_ms, bool enable)
{
	struct tcp_retransmit_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct TcpRetransmit_ctrl ctrl = {.enable = enable};
	const int key = 0;
	int err = 0;

	skel = tcp_retransmit_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "打开BPF程序失败\n");
		return 1;
	}

	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "设置控制开关失败: %s\n", strerror(-err));
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "创建RingBuffer失败\n");
		goto cleanup;
	}

	err = tcp_retransmit_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载BPF程序失败\n");
		goto cleanup;
	}

	printf("=========================================\n");
	printf("  TCP 重传监控已%s！\n", enable ? "启动" : "关闭");
	printf("  按 Ctrl+C 退出\n");
	printf("=========================================\n");
	printf("PID    COMM             SRC:PORT          -> DST:PORT           STATE\n");
	printf("-------------------------------------------------------------------\n");

	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "轮询事件失败: %s\n", strerror(-err));
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	tcp_retransmit_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
