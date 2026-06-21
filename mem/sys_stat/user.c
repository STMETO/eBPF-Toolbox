#include <errno.h>
#include <stdio.h>
#include <bpf/libbpf.h>
#include "common/cli.h"
#include "common/types.h"
#include "sys_stat.h"
#include "sys_stat.h"
#include "mem/sys_stat/skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct SysStat_event *e = data; (void)ctx; (void)data_sz;
	printf("%-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu\n",
	       e->anon_active + e->file_active, e->file_inactive + e->anon_inactive,
	       e->anon_active, e->anon_inactive, e->file_active, e->file_inactive,
	       e->unevictable, e->file_dirty, e->writeback, e->anon_mapped, e->file_mapped, e->shmem);
	return 0;
}

int sys_stat_run(int poll_timeout_ms, bool enable)
{
	struct sys_stat_bpf *skel = NULL; struct ring_buffer *rb = NULL;
	struct SysStat_ctrl ctrl = { .enable = enable }; const int key = 0; int err = 0;
	skel = sys_stat_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "Failed SysStat\n"); return 1; }
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key), &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) { fprintf(stderr, "Control fail\n"); goto cleanup; }
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -ENOMEM; goto cleanup; }
	err = sys_stat_bpf__attach(skel);
	if (err) { fprintf(stderr, "Attach fail\n"); goto cleanup; }
	printf("%-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s\n",
	       "ACTIVE", "INACTVE", "ANON_ACT", "ANON_INA", "FILE_ACT", "FILE_INA",
	       "UNEVICT", "DIRTY", "WRITEBK", "ANONPAG", "MAP", "SHMEM");
	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) break;
	}
cleanup: ring_buffer__free(rb); sys_stat_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
