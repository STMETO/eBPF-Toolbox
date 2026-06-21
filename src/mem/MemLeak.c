#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "blazesym.h"
#include "app_common.h"
#include "common.h"
#include "MemLeak.h"
#include "mem_leak.h"
#include "mem/MemLeak.skel.h"

#define PERF_MAX_STACK_DEPTH 127
#define STACK_MAP_MAX_ENTRIES 10240

static struct blaze_symbolizer *symbolizer = NULL;

static void print_frame(const char *name, uintptr_t input_addr, uintptr_t addr,
			uint64_t offset, const blaze_symbolize_code_info *code_info)
{
	if (input_addr != 0) {
		printf("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
		if (code_info && code_info->file)
			printf(" %s:%u\n", code_info->file, code_info->line);
		else
			printf("\n");
	}
}

static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid)
{
	const struct blaze_syms *result;
	const struct blaze_sym *sym;
	int i;

	if (pid) {
		struct blaze_symbolize_src_process src = { .type_size = sizeof(src), .pid = pid };
		result = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	} else {
		struct blaze_symbolize_src_kernel src = { .type_size = sizeof(src) };
		result = blaze_symbolize_kernel_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	}

	for (i = 0; i < stack_sz; i++) {
		if (!result || result->cnt <= i || result->syms[i].name == NULL) {
			printf("%016llx: <no-symbol>\n", stack[i]);
			continue;
		}
		sym = &result->syms[i];
		print_frame(sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);
	}
	blaze_syms_free(result);
}

static int print_outstanding_allocs(struct MemLeak_bpf *skel, __u64 *stacks, size_t stacks_size)
{
	const size_t key_size = bpf_map__key_size(skel->maps.allocs);
	time_t t = time(NULL); struct tm *tm = localtime(&t);
	size_t nr_allocs = 0;
	struct { int stack_id; __u64 size; size_t count; } *allocs;
	allocs = calloc(ALLOCS_MAX_ENTRIES, sizeof(*allocs));
	if (!allocs) return -ENOMEM;

	for (__u64 prev = 0, curr = 0;; prev = curr) {
		struct alloc_info info = {};
		if (bpf_map__get_next_key(skel->maps.allocs, &prev, &curr, key_size)) {
			if (errno == ENOENT) break;
			perror("map get next key");
			free(allocs); return -errno;
		}
		if (bpf_map__lookup_elem(skel->maps.allocs, &curr, key_size, &info, sizeof(info), 0)) {
			if (errno == ENOENT) continue;
			perror("map lookup"); free(allocs); return -errno;
		}
		if (info.stack_id < 0) continue;
		int found = 0;
		for (size_t i = 0; i < nr_allocs; i++) {
			if (allocs[i].stack_id == info.stack_id) {
				allocs[i].size += info.size;
				allocs[i].count++;
				found = 1;
				break;
			}
		}
		if (!found && nr_allocs < ALLOCS_MAX_ENTRIES) {
			allocs[nr_allocs].stack_id = info.stack_id;
			allocs[nr_allocs].size = info.size;
			allocs[nr_allocs].count = 1;
			nr_allocs++;
		}
	}

	printf("[%d:%d:%d] Top %zu stacks with outstanding allocations:\n",
	       tm->tm_hour, tm->tm_min, tm->tm_sec, nr_allocs < 10 ? nr_allocs : (size_t)10);

	for (size_t i = 0; i < (nr_allocs < 10 ? nr_allocs : (size_t)10); i++) {
		printf("stack_id=0x%x total_size=%llu nr_allocs=%zu\n",
		       allocs[i].stack_id, allocs[i].size, allocs[i].count);
		if (bpf_map__lookup_elem(skel->maps.stack_traces, &allocs[i].stack_id,
					 sizeof(allocs[i].stack_id), stacks, stacks_size, 0)) {
			perror("failed to lookup stack traces");
		} else {
			int sz = 0;
			for (int j = 0; j < PERF_MAX_STACK_DEPTH && stacks[j]; j++) sz++;
			show_stack_trace(stacks, sz, 0);
		}
	}
	free(allocs);
	return 0;
}

int mem_leak_run(int poll_timeout_ms, bool enable)
{
	struct MemLeak_bpf *skel = NULL;
	int err = 0;

	symbolizer = blaze_symbolizer_new();
	if (!symbolizer) { fprintf(stderr, "Failed to create symbolizer\n"); return 1; }

	skel = MemLeak_bpf__open();
	if (!skel) { fprintf(stderr, "Failed MemLeak open\n"); goto cleanup; }

	bpf_map__set_value_size(skel->maps.stack_traces, PERF_MAX_STACK_DEPTH * sizeof(__u64));
	bpf_map__set_max_entries(skel->maps.stack_traces, STACK_MAP_MAX_ENTRIES);

	err = MemLeak_bpf__load(skel);
	if (err) { fprintf(stderr, "Failed MemLeak load\n"); goto cleanup; }

	err = MemLeak_bpf__attach(skel);
	if (err) { fprintf(stderr, "Failed MemLeak attach\n"); goto cleanup; }

	(void)enable;

	{
		size_t stacks_size = PERF_MAX_STACK_DEPTH * sizeof(__u64);
		__u64 *stacks = malloc(stacks_size);
		if (!stacks) { err = -ENOMEM; goto cleanup; }
		memset(stacks, 0, stacks_size);

		while (!app_should_exit()) {
			print_outstanding_allocs(skel, stacks, stacks_size);
			sleep(1);
		}
		free(stacks);
	}

cleanup:
	if (symbolizer) blaze_symbolizer_free(symbolizer);
	MemLeak_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
