#include <errno.h>
#include <stdio.h>

#include <bpf/libbpf.h>

#include "app_common.h"
#include "common.h"
#include "Paf.h"
#include "paf.h"
#include "mem/Paf.skel.h"

static void print_flag_modifiers(int flag);

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Paf_event *e = data;
	(void)ctx;
	(void)data_sz;

	printf("%-8lu %-8lu %-8lu %-8lu %-8x ",
	       e->min, e->low, e->high, e->present, e->flag);
	print_flag_modifiers(e->flag);
	printf("\n");
	return 0;
}

int paf_run(int poll_timeout_ms, bool enable)
{
	struct Paf_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct Paf_ctrl ctrl = { .enable = enable };
	const int key = 0;
	int err = 0;

	skel = Paf_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load Paf BPF skeleton\n");
		return 1;
	}

	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Failed to set control: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	err = Paf_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach: %d\n", err);
		goto cleanup;
	}

	printf("%-8s %-8s %-8s %-8s %-8s\n", "MIN", "LOW", "HIGH", "PRESENT", "FLAG");

	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) { fprintf(stderr, "Poll error: %d\n", err); break; }
	}

cleanup:
	ring_buffer__free(rb);
	Paf_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}

/* GFP flag 解析辅助函数 */
typedef struct { int flag; const char *name; } Flag;

static Flag gfp_list[] = {
	{0x01u, "___GFP_DMA"}, {0x02u, "___GFP_HIGHMEM"}, {0x04u, "___GFP_DMA32"},
	{0x08u, "___GFP_MOVABLE"}, {0x10u, "___GFP_RECLAIMABLE"}, {0x20u, "___GFP_HIGH"},
	{0x40u, "___GFP_IO"}, {0x80u, "___GFP_FS"}, {0x100u, "___GFP_ZERO"},
	{0x200u, "___GFP_ATOMIC"}, {0x400u, "___GFP_DIRECT_RECLAIM"},
	{0x800u, "___GFP_KSWAPD_RECLAIM"}, {0x1000u, "___GFP_WRITE"},
	{0x2000u, "___GFP_NOWARN"}, {0x4000u, "___GFP_RETRY_MAYFAIL"},
	{0x8000u, "___GFP_NOFAIL"}, {0x10000u, "___GFP_NORETRY"},
	{0x20000u, "___GFP_MEMALLOC"}, {0x40000u, "___GFP_COMP"},
	{0x80000u, "___GFP_NOMEMALLOC"}, {0x100000u, "___GFP_HARDWALL"},
	{0x200000u, "___GFP_THISNODE"}, {0x400000u, "___GFP_ACCOUNT"},
	{0x800000u, "___GFP_ZEROTAGS"}, {0x1000000u, "___GFP_SKIP_KASAN_POISON"},
	{0, NULL}
};

static void print_flag_modifiers(int flag)
{
	char buf[512] = {0};
	for (int i = 0; gfp_list[i].name; i++) {
		if (flag & gfp_list[i].flag) {
			if (buf[0]) strcat(buf, " | ");
			strcat(buf, gfp_list[i].name);
		}
	}
	printf("%s", buf[0] ? buf : "none");
}
