/*
 * NetWatcher - eBPF network subsystem monitoring (libbpf CO-RE)
 *
 * Minimal wrapper that loads and attaches the default TCP monitoring probes.
 * The original net_watcher had ~1800 lines of detailed output formatting;
 * this wrapper provides basic connection/packet event printing.
 */
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "app_common.h"
#include "NetWatcher.h"
#include "net_watcher.h"
#include "net/NetWatcher.skel.h"

static int handle_conn(void *ctx, void *data, size_t sz)
{
	(void)ctx; (void)sz;
	const struct conn_t *e = data;
	struct tm *tm; char ts[32]; time_t t;
	time(&t); tm = localtime(&t); strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	char src[64], dst[64];
	if (e->family == 10) /* AF_INET6 */
		snprintf(src, sizeof(src), "[v6]:%u", e->sport);
	else
		snprintf(src, sizeof(src), "%u.%u.%u.%u:%u",
			 (e->saddr >> 24) & 0xff, (e->saddr >> 16) & 0xff,
			 (e->saddr >> 8) & 0xff, e->saddr & 0xff, e->sport);
	printf("%-8s %-6d %-32s %-4s backlog=%u/%u\n",
	       ts, e->pid, src, e->is_server ? "SRV" : "CLI",
	       e->tcp_backlog, e->max_tcp_backlog);
	return 0;
}

int net_watcher_run(int poll_timeout_ms, bool enable)
{
	struct NetWatcher_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	int err = 0;
	(void)enable;

	skel = NetWatcher_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "Failed to open/load NetWatcher\n"); return 1; }

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_conn, NULL, NULL);
	if (!rb) { err = -ENOMEM; fprintf(stderr, "Ring buffer fail\n"); goto cleanup; }

	err = NetWatcher_bpf__attach(skel);
	if (err) { fprintf(stderr, "Attach fail: %d\n", err); goto cleanup; }

	printf("NetWatcher running. Ctrl-C to stop.\n");
	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) break;
	}

cleanup:
	ring_buffer__free(rb);
	NetWatcher_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
