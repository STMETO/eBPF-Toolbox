#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "app_common.h"
#include "common.h"
#include "DrSnoop.h"
#include "dr_snoop.h"
#include "mem/DrSnoop.skel.h"

#define KALLSYMS_PATH "/proc/kallsyms"
#define VM_STAT_SYMBOL "vm_stat"
#define VM_ZONE_STAT_SYMBOL "vm_zone_stat"
#define PAGE_SHIFT 12
#define K(x) ((x) << (PAGE_SHIFT - 10))

static int get_vm_stat_addr(__u64 *addr)
{
	FILE *file = fopen(KALLSYMS_PATH, "r");
	if (!file) return -1;
	char line[256];
	while (fgets(line, sizeof(line), file)) {
		unsigned long address; char symbol[256];
		if (sscanf(line, "%lx %*s %s", &address, symbol) == 2) {
			if (strcmp(symbol, VM_STAT_SYMBOL) == 0 ||
			    strcmp(symbol, VM_ZONE_STAT_SYMBOL) == 0) {
				*addr = address; fclose(file); return 0;
			}
		}
	}
	fclose(file);
	return -1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct data_t *e = data; (void)ctx; (void)data_sz;
	struct tm *tm; char ts[32]; time_t t;
	time(&t); tm = localtime(&t); strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	__u64 delta_us = e->delta / 1000, delta_ms = delta_us / 1000, fractional_us = delta_us % 1000;
	printf("%-8s %-16s %-7llu %-9llu %llu.%02llu\n",
	       ts, e->name, e->id >> 32, K(e->vm_stat[NR_FREE_PAGES]), delta_ms, fractional_us);
	return 0;
}

int dr_snoop_run(int poll_timeout_ms, bool enable)
{
	struct DrSnoop_bpf *skel = NULL; struct ring_buffer *rb = NULL;
	struct DrSnoop_ctrl ctrl = { .enable = enable }; const int key = 0; int err = 0;
	__u64 vm_stat_addr; __u32 map_key = 0;

	if (get_vm_stat_addr(&vm_stat_addr) != 0) {
		fprintf(stderr, "Failed to get vm_stat address\n"); return 1;
	}

	skel = DrSnoop_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "Failed DrSnoop\n"); return 1; }

	err = bpf_map_update_elem(bpf_map__fd(skel->maps.vm_stat_map), &map_key, &vm_stat_addr, BPF_ANY);
	if (err) { fprintf(stderr, "Failed to update vm_stat_map: %s\n", strerror(errno)); goto cleanup; }

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -ENOMEM; goto cleanup; }

	err = DrSnoop_bpf__attach(skel);
	if (err) { fprintf(stderr, "Attach fail\n"); goto cleanup; }

	printf("%-8s %-16s %-7s %-9s %-7s\n", "TIME", "COMM", "PID", "FREE(KB)", "LAT(ms)");
	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) break;
	}

cleanup:
	ring_buffer__free(rb); DrSnoop_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
