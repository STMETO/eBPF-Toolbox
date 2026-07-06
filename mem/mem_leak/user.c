#include "blazesym.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common/cli.h"
#include "common/types.h"
#include "mem_leak.h"
#include "mem_leak.h"
#include "mem/mem_leak/skel.h"

#define PERF_MAX_STACK_DEPTH 127
#define STACK_MAP_MAX_ENTRIES 10240

// 全局符号解析器句柄，用于将内核/用户态虚拟地址翻译成函数名、行号
static struct blaze_symbolizer *symbolizer = NULL;

/**
 * @brief 打印单条栈帧详细符号信息
 * @param name 解析得到的函数符号名
 * @param input_addr 原始采集到的虚拟地址（栈帧原始地址）
 * @param addr 符号对应的函数起始地址
 * @param offset 地址相对于函数开头的偏移量
 * @param code_info 源码文件、行号信息，可为NULL
 */
static void print_frame(const char *name, uintptr_t input_addr, uintptr_t addr,
			uint64_t offset, const blaze_symbolize_code_info *code_info)
{
	// 原始栈地址不为0时才打印有效栈帧
	if (input_addr != 0) {
		// 打印原始地址、函数名、函数基地址+偏移
		printf("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
		// 如果解析出源码文件和行号，追加打印
		if (code_info && code_info->file)
			printf(" %s:%u\n", code_info->file, code_info->line);
		else
			printf("\n");
	}
}

/**
 * @brief 解析并打印一整条完整调用栈
 * @param stack 栈帧地址数组，存储一串虚拟地址
 * @param stack_sz 当前栈实际有效帧数量
 * @param pid 进程PID：0代表内核栈，非0代表指定用户进程栈
 */
static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid)
{
	const struct blaze_syms *result;
	const struct blaze_sym *sym;
	int i;

	if (pid) {
		// 用户态栈：指定进程PID，解析进程虚拟地址
		struct blaze_symbolize_src_process src = {
			.type_size = sizeof(src),
			.pid = pid
		};
		// 批量解析一组用户态绝对虚拟地址
		result = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	} else {
		// 内核栈：解析内核全局虚拟地址
		struct blaze_symbolize_src_kernel src = {
			.type_size = sizeof(src)
		};
		result = blaze_symbolize_kernel_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	}

	// 逐帧遍历打印符号
	for (i = 0; i < stack_sz; i++) {
		// 解析失败/无符号信息，打印原始地址占位
		if (!result || result->cnt <= i || result->syms[i].name == NULL) {
			printf("%016llx: <no-symbol>\n", stack[i]);
			continue;
		}
		sym = &result->syms[i];
		// 格式化输出单帧符号
		print_frame(sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);
	}
	// 释放符号解析结果内存，避免内存泄漏
	blaze_syms_free(result);
}

/**
 * @brief 遍历BPF allocs表，按stack_id聚合未释放内存，打印泄漏热点栈
 * @param skel BPF骨架对象，持有所有BPF map引用
 * @param stacks 缓冲区，用于从stack_traces读取完整栈帧数据
 * @param stacks_size 缓冲区总字节大小
 * @return 成功返回0，失败返回负错误码
 * @logic
 * 1. 遍历allocs所有存活内存条目，按stack_id累加总占用size、内存块数量
 * 2. 取占用最高的前10个调用栈作为泄漏热点
 * 3. 根据stack_id读取stack_traces栈数据，调用符号解析打印完整调用链
 */
static int print_outstanding_allocs(struct mem_leak_bpf *skel, __u64 *stacks, size_t stacks_size)
{
	// 获取allocs map中key的字节宽度（key是u64内存地址）
	const size_t key_size = bpf_map__key_size(skel->maps.allocs);
	// 获取当前本地时间，用于打印日志时间戳
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	// nr_allocs：聚合后不同调用栈的总数
	size_t nr_allocs = 0;

	// 自定义聚合数组：每个元素对应一条stack_id的汇总统计
	struct {
		int stack_id;
		__u64 size;       // 该栈所有未释放内存总字节
		size_t count;     // 该栈未释放内存块总数
	} *allocs;

	// 分配聚合存储缓冲区，最大支持ALLOCS_MAX_ENTRIES种不同调用栈
	allocs = calloc(ALLOCS_MAX_ENTRIES, sizeof(*allocs));
	if (!allocs)
		return -ENOMEM;

	// BPF map迭代器：遍历allocs哈希表所有key
	// prev：上一条key，curr：当前遍历key
	for (__u64 prev = 0, curr = 0;; prev = curr) {
		struct alloc_info info = {};
		// 获取下一个map key，遍历终止条件：errno == ENOENT 无更多key
		if (bpf_map__get_next_key(skel->maps.allocs, &prev, &curr, key_size)) {
			if (errno == ENOENT)
				break;
			perror("map get next key");
			free(allocs);
			return -errno;
		}
		// 根据当前内存地址key，读取分配详情size+stack_id
		if (bpf_map__lookup_elem(skel->maps.allocs, &curr, key_size, &info, sizeof(info), 0)) {
			if (errno == ENOENT)
				continue;
			perror("map lookup");
			free(allocs);
			return -errno;
		}
		// 非法stack_id跳过
		if (info.stack_id < 0)
			continue;

		// 查找当前stack_id是否已存在于聚合数组，存在则累加size与计数
		int found = 0;
		for (size_t i = 0; i < nr_allocs; i++) {
			if (allocs[i].stack_id == info.stack_id) {
				allocs[i].size += info.size;
				allocs[i].count++;
				found = 1;
				break;
			}
		}
		// 未找到该栈，新增一条聚合记录
		if (!found && nr_allocs < ALLOCS_MAX_ENTRIES) {
			allocs[nr_allocs].stack_id = info.stack_id;
			allocs[nr_allocs].size = info.size;
			allocs[nr_allocs].count = 1;
			nr_allocs++;
		}
	}

	// 打印头部日志，展示当前时间与待输出热点栈数量
	printf("[%d:%d:%d] Top %zu stacks with outstanding allocations:\n",
	       tm->tm_hour, tm->tm_min, tm->tm_sec, nr_allocs < 10 ? nr_allocs : (size_t)10);

	// 输出前10个泄漏最严重的调用栈
	for (size_t i = 0; i < (nr_allocs < 10 ? nr_allocs : (size_t)10); i++) {
		printf("stack_id=0x%x total_size=%llu nr_allocs=%zu\n",
		       allocs[i].stack_id, allocs[i].size, allocs[i].count);

		// 根据stack_id读取stack_traces映射，获取完整栈帧数组
		if (bpf_map__lookup_elem(skel->maps.stack_traces, &allocs[i].stack_id,
					 sizeof(allocs[i].stack_id), stacks, stacks_size, 0)) {
			perror("failed to lookup stack traces");
		} else {
			// 统计当前栈有效帧数量（以0地址作为栈结束标记）
			int sz = 0;
			for (int j = 0; j < PERF_MAX_STACK_DEPTH && stacks[j]; j++)
				sz++;
			// 解析并打印该栈完整符号调用链
			show_stack_trace(stacks, sz, 0);
		}
	}

	// 释放聚合数组内存
	free(allocs);
	return 0;
}

/**
 * @brief 内存泄漏检测主运行函数
 * @param poll_timeout_ms 预留参数，本次代码未使用
 * @param enable 开关标记，预留扩展，当前未做逻辑处理
 * @return 0正常退出，非0为异常错误码
 * @flow
 * 1. 创建符号解析器
 * 2. 打开、配置、加载、挂载BPF程序
 * 3. 循环每秒读取一次泄漏统计并打印
 * 4. 程序退出时释放所有资源
 */
int mem_leak_run(int poll_timeout_ms, bool enable)
{
	struct mem_leak_bpf *skel = NULL;
	int err = 0;

	// 初始化符号解析器，用于地址转函数名/源码行
	symbolizer = blaze_symbolizer_new();
	if (!symbolizer) {
		fprintf(stderr, "Failed to create symbolizer\n");
		return 1;
	}

	// 1. 打开BPF骨架，加载BPF程序元数据
	skel = mem_leak_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed MemLeak open\n");
		goto cleanup;
	}

	// 配置stack_traces MAP：单条栈最大深度、总存储条数
	// value_size = 最大栈深度 × 单帧地址8字节
	bpf_map__set_value_size(skel->maps.stack_traces, PERF_MAX_STACK_DEPTH * sizeof(__u64));
	bpf_map__set_max_entries(skel->maps.stack_traces, STACK_MAP_MAX_ENTRIES);

	// 2. 将BPF字节码加载进内核
	err = mem_leak_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed MemLeak load\n");
		goto cleanup;
	}

	// 3. 挂载所有uprobe/tracepoint探针到内核
	err = mem_leak_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed MemLeak attach\n");
		goto cleanup;
	}

	// enable参数预留，暂无业务逻辑
	(void)enable;

	{
		// 分配栈帧读取缓冲区，用于临时存放stack_traces取出的地址数组
		size_t stacks_size = PERF_MAX_STACK_DEPTH * sizeof(__u64);
		__u64 *stacks = malloc(stacks_size);
		if (!stacks) {
			err = -ENOMEM;
			goto cleanup;
		}
		memset(stacks, 0, stacks_size);

		// 主循环：未收到退出信号则每秒打印一次泄漏汇总
		while (!app_should_exit()) {
			print_outstanding_allocs(skel, stacks, stacks_size);
			sleep(1);
		}
		free(stacks);
	}

cleanup:
	// 资源释放统一出口
	if (symbolizer)
		blaze_symbolizer_free(symbolizer);
	// 销毁BPF骨架，自动卸载探针、释放BPF map
	mem_leak_bpf__destroy(skel);
	// 统一转成正数错误码返回
	return err < 0 ? -err : 0;
}

