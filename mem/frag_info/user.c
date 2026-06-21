#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common/cli.h"
#include "common/types.h"
#include "frag_info.h"
#include "frag_info.h"
#include "mem/frag_info/skel.h"

static int compare_entries(const void *a, const void *b);
static int __fragmentation_index(unsigned int order, unsigned long total,
				 unsigned long suitable, unsigned long free);
static int unusable_free_index(unsigned int order, unsigned long total,
			       unsigned long suitable, unsigned long free);

struct order_entry {
	struct order_zone okey;
	struct ctg_info oinfo;
};

static void print_nodes(int fd)
{
	struct pgdat_info pinfo;
	__u64 key = 0, next_key;
	printf(" Node ID          PGDAT_PTR       NR_ZONES \n");
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &pinfo);
		printf(" %5d       0x%llx  %5d\n", pinfo.node_id, pinfo.pgdat_ptr, pinfo.nr_zones);
		key = next_key;
	}
}

static void print_zones(int fd)
{
	struct zone_info zinfo;
	__u64 key = 0, next_key;
	printf("%-20s %-20s %-25s %-20s %-20s\n", " COMM", "ZONE_PTR", "ZONE_PFN", "SUM_PAGES", "FACT_PAGES");
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &zinfo);
		printf(" %-15s 0x%-25llx %-25llu %-20llu %-15llu\n",
		       zinfo.comm, zinfo.zone_ptr, zinfo.zone_start_pfn,
		       zinfo.spanned_pages, zinfo.present_pages);
		key = next_key;
	}
}

static void print_orders(int fd)
{
	struct order_zone okey = {};
	struct ctg_info oinfo;
	struct order_entry entries[256];
	int entry_count = 0;

	while (bpf_map_get_next_key(fd, &okey, &okey) == 0) {
		if (bpf_map_lookup_elem(fd, &okey, &oinfo) == 0) {
			entries[entry_count].okey = okey;
			entries[entry_count].oinfo = oinfo;
			entry_count++;
		}
	}

	qsort(entries, entry_count, sizeof(struct order_entry), compare_entries);
	printf(" Order     Zone_PTR                Free Pages         Free Blocks Total    Free Blocks Suitable      SCOREA     SCOREB\n");
	for (int i = 0; i < entry_count; i++) {
		int res = __fragmentation_index(entries[i].okey.order,
			entries[i].oinfo.free_blocks_total, entries[i].oinfo.free_blocks_suitable,
			entries[i].oinfo.free_pages);
		int tmp = unusable_free_index(entries[i].okey.order,
			entries[i].oinfo.free_blocks_total, entries[i].oinfo.free_blocks_suitable,
			entries[i].oinfo.free_pages);
		int part2 = tmp / 1000, dec2 = tmp % 1000;
		printf(" %-8u 0x%-25llx %-20lu %-20lu %-20lu %d   %d.%03d\n",
		       entries[i].okey.order, entries[i].okey.zone_ptr, entries[i].oinfo.free_pages,
		       entries[i].oinfo.free_blocks_total, entries[i].oinfo.free_blocks_suitable,
		       res, part2, dec2);
	}
}

int frag_info_run(int poll_timeout_ms, bool enable)
{
	struct frag_info_bpf *skel = NULL;
	int err = 0;

	(void)poll_timeout_ms;
	(void)enable;

	skel = frag_info_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "Failed FragInfo\n"); return 1; }

	err = frag_info_bpf__attach(skel);
	if (err) { fprintf(stderr, "Attach fail\n"); goto cleanup; }

	while (!app_should_exit()) {
		sleep(1);
		print_nodes(bpf_map__fd(skel->maps.nodes));
		printf("\n");
		print_zones(bpf_map__fd(skel->maps.zones));
		printf("\n");
		print_orders(bpf_map__fd(skel->maps.orders));
		printf("\n");
	}

cleanup:
	frag_info_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}

static int compare_entries(const void *a, const void *b)
{
	struct order_entry *ea = (struct order_entry *)a, *eb = (struct order_entry *)b;
	if (ea->okey.zone_ptr != eb->okey.zone_ptr)
		return (ea->okey.zone_ptr < eb->okey.zone_ptr) ? -1 : 1;
	return (ea->okey.order < eb->okey.order) ? -1 : 1;
}

static int __fragmentation_index(unsigned int order, unsigned long total,
				 unsigned long suitable, unsigned long free)
{
	if (order > MAX_ORDER || !total) return 0;
	if (suitable) return -1000;
	unsigned long requested = 1UL << order;
	double res1 = (double)(free * 1000ULL) / requested;
	return (int)(res1 / total);
}

static int unusable_free_index(unsigned int order, unsigned long total,
			       unsigned long suitable, unsigned long free)
{
	if (free == 0) return 1000;
	long unsigned int res1 = free - (suitable << order);
	return (int)((res1 * 1000ULL) / free);
}
