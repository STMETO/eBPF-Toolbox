#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "app_common.h"
#include "common.h"
#include "SlabRate.h"
#include "slab_rate.h"
#include "mem/SlabRate.skel.h"

#define OUTPUT_ROWS 20

static int sort_by_size(const void *a, const void *b)
{
	struct SlabRate_info *sa = (struct SlabRate_info *)a;
	struct SlabRate_info *sb = (struct SlabRate_info *)b;
	return (sb->size > sa->size) ? 1 : ((sb->size < sa->size) ? -1 : 0);
}

static int print_stat(struct SlabRate_bpf *skel)
{
	static struct SlabRate_info values[10240];
	char *key = NULL, **prev_key = NULL;
	int fd = bpf_map__fd(skel->maps.slab_entries);
	int rows = 0, err = 0;

	printf("%-32s %8s %12s\n", "CACHE", "ALLOCS", "BYTES");
	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, &key);
		if (err) { if (errno == ENOENT) { err = 0; break; } return err; }
		err = bpf_map_lookup_elem(fd, &key, &values[rows++]);
		if (err) return err;
		prev_key = &key;
		if (rows >= 10240) break;
	}
	qsort(values, rows, sizeof(struct SlabRate_info), sort_by_size);
	int show = rows < OUTPUT_ROWS ? rows : OUTPUT_ROWS;
	for (int i = 0; i < show; i++)
		printf("%-32s %8llu %12llu\n", values[i].name, values[i].count, values[i].size);
	printf("\n");

	/* 删除已读条目以便下一轮增量统计 */
	prev_key = NULL;
	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, &key);
		if (err) break;
		err = bpf_map_delete_elem(fd, &key);
		if (err) return err;
		prev_key = &key;
	}
	return 0;
}

int slab_rate_run(int poll_timeout_ms, bool enable)
{
	struct SlabRate_bpf *skel = NULL;
	struct SlabRate_ctrl ctrl = { .enable = enable };
	const int key = 0;
	int err = 0;

	skel = SlabRate_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "Failed SlabRate\n"); return 1; }

	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) { fprintf(stderr, "Control fail\n"); goto cleanup; }

	err = SlabRate_bpf__attach(skel);
	if (err) { fprintf(stderr, "Attach fail\n"); goto cleanup; }

	while (!app_should_exit()) {
		sleep(poll_timeout_ms > 1000 ? poll_timeout_ms / 1000 : 1);
		system("clear");
		err = print_stat(skel);
		if (err) break;
	}

cleanup:
	SlabRate_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
