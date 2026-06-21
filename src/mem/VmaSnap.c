#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "app_common.h"
#include "common.h"
#include "VmaSnap.h"
#include "vma_snap.h"
#include "mem/VmaSnap.skel.h"

static void print_find_events(int map_fd)
{
	__u64 key = 0, next_key;
	struct find_event_t event;
	printf("%-10s %-20s %-15s %-20s %-20s %-20s %-20s\n",
	       "PID", "Address", "Duration", "VMACache Hit", "RB Subtree Last", "VM Start", "VM End");
	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &next_key, &event) == 0) {
			printf("%-10llu %-20lu %-15llu %-20d %-20llu %-20llu %-20llu\n",
			       next_key, event.addr, event.duration, event.vmacache_hit,
			       event.rb_subtree_last, event.vm_start, event.vm_end);
			bpf_map_delete_elem(map_fd, &next_key);
		}
		key = next_key;
	}
}

static void print_insert_events(int map_fd)
{
	__u64 key = 0, next_key;
	struct insert_event_t event;
	printf("%-10s %-15s %-15s %-20s %-20s %-20s %-20s\n",
	       "PID", "Duration", "List", "RB", "Interval Tree", "List Time", "RB Time", "Interval Tree Time");
	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &next_key, &event) == 0) {
			printf("%-10llu %-15llu %-15d %-20d %-20d %-20llu %-20llu %-20llu\n",
			       next_key, event.duration, event.inserted_to_list,
			       event.inserted_to_rb, event.inserted_to_interval_tree,
			       event.link_list_duration, event.link_rb_duration, event.interval_tree_duration);
			bpf_map_delete_elem(map_fd, &next_key);
		}
		key = next_key;
	}
}

int vma_snap_run(int poll_timeout_ms, bool enable)
{
	struct VmaSnap_bpf *skel = NULL;
	int err = 0;
	(void)enable;

	skel = VmaSnap_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "Failed VmaSnap\n"); return 1; }
	err = VmaSnap_bpf__attach(skel);
	if (err) { fprintf(stderr, "Attach fail\n"); goto cleanup; }

	printf("Successfully started! Press Ctrl-C to exit.\n");
	int ffd = bpf_map__fd(skel->maps.find_events);
	int ifd = bpf_map__fd(skel->maps.insert_events);

	while (!app_should_exit()) {
		print_find_events(ffd);
		print_insert_events(ifd);
		usleep(poll_timeout_ms * 1000);
	}

cleanup:
	VmaSnap_bpf__destroy(skel);
	return 0;
}
