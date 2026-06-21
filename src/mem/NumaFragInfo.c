#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "app_common.h"
#include "common.h"
#include "FragInfo.h"
#include "numa_frag_info.h"
#include "mem/NumaFragInfo.skel.h"

int numa_frag_info_run(int poll_timeout_ms, bool enable)
{
	struct NumaFragInfo_bpf *skel = NULL;
	int err = 0;
	(void)poll_timeout_ms; (void)enable;

	skel = NumaFragInfo_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "Failed NumaFragInfo\n"); return 1; }
	err = NumaFragInfo_bpf__attach(skel);
	if (err) { fprintf(stderr, "Attach fail\n"); goto cleanup; }

	while (!app_should_exit()) {
		sleep(1);
		struct pgdat_info pinfo;
		__u64 key = 0, next_key;
		int fd = bpf_map__fd(skel->maps.nodes);
		printf(" Node ID          PGDAT_PTR       NR_ZONES \n");
		while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
			bpf_map_lookup_elem(fd, &next_key, &pinfo);
			printf(" %5d       0x%llx  %5d\n", pinfo.node_id, pinfo.pgdat_ptr, pinfo.nr_zones);
			key = next_key;
		}
		printf("\n");
	}
cleanup:
	NumaFragInfo_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
