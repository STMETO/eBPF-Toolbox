#include <errno.h>
#include <stdio.h>

#include <bpf/libbpf.h>

#include "common/cli.h"       
#include "common/types.h"      
#include "paf.h"              
#include "paf.h"              
#include "mem/paf/skel.h"      
#include "common/logger.h"

// 前置函数声明：解析并打印GFP分配掩码标识
static void print_flag_modifiers(int flag);

/**
 * @brief RingBuffer事件回调函数，内核推送水位事件时自动触发
 * @param ctx 自定义上下文，本程序未使用
 * @param data 内核下发的Paf_event水位事件数据
 * @param data_sz 事件数据长度，本程序未做长度校验
 * @return int 回调返回值，0代表处理正常
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct Paf_event *e = data;
	// 消除未使用参数编译警告
	(void)ctx;
	(void)data_sz;

	// 格式化打印水位原始数值：min/low/high有效水位、zone总有效页数、原始GFP掩码十六进制
	printf("%-8lu %-8lu %-8lu %-8lu %-8x ",
	       e->min, e->low, e->high, e->present, e->flag);
	// 解析GFP掩码，打印对应的内存分配属性字符串
	print_flag_modifiers(e->flag);
	printf("\n");
	return 0;
}

/**
 * @brief PAF内存水位监控用户态主入口函数
 * @param poll_timeout_ms 环形缓冲区阻塞读取超时时间(ms)
 * @param enable 采集总开关，true启用BPF探针采集水位事件，false关闭
 * @return int 0正常退出，正数为错误码
 */
int paf_run(int poll_timeout_ms, bool enable)
{
	struct paf_bpf *skel = NULL;         // BPF骨架句柄，管理BPF程序、所有Map
	struct ring_buffer *rb = NULL;      // libbpf环形缓冲区管理句柄
	struct Paf_ctrl ctrl = { .enable = enable }; // 下发至内核的采集开关配置
	const int key = 0;                   // ctrl_map数组MAP固定下标key
	int err = 0;

	// 1. 打开BPF字节码并加载到内核，自动初始化所有BPF Map
	skel = paf_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load Paf BPF skeleton\n");
		return 1;
	}

	// 2. 将启停开关写入内核ctrl_map，控制探针是否采集水位事件
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Failed to set control: %d\n", err);
		goto cleanup;
	}

	// 3. 绑定内核rb环形缓冲区fd，创建RingBuffer实例并注册事件回调
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	// 4. 将kprobe探针挂载到内核get_page_from_freelist函数
	err = paf_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach: %d\n", err);
		goto cleanup;
	}

	// 打印输出表头，对应水位字段含义
	printf("%-8s %-8s %-8s %-8s %-8s\n", "MIN", "LOW", "HIGH", "PRESENT", "FLAG");

	// 主循环：阻塞等待内核水位事件，直到收到退出信号(Ctrl+C)
	while (!app_should_exit()) {
		// 阻塞读取环形缓冲区，超时时间poll_timeout_ms
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { // 被系统信号中断（Ctrl+C），视为正常退出
			err = 0;
			break;
		}
		if (err < 0) { // 缓冲区读取发生异常，终止监控
			fprintf(stderr, "Poll error: %d\n", err);
			break;
		}
	}

cleanup:
	// 逆序释放资源：先销毁环形缓冲区，再销毁BPF骨架
	ring_buffer__free(rb);
	paf_bpf__destroy(skel);
	// 负数错误码转正后返回，无错误返回0
	return err < 0 ? -err : 0;
}

/**
 * @brief GFP掩码解析映射表结构体
 * @param flag GFP掩码二进制位值
 * @param name 对应掩码的文本名称
 */
typedef struct { int flag; const char *name; } Flag;

/**
 * @brief 完整GFP分配掩码对照表，覆盖内核常用内存分配标识
 * 每一项对应内核__GFP_系列宏，用于解析分配行为属性
 */
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
	{0, NULL} // 数组结束标记
};

/**
 * @brief 根据GFP掩码数值，拼接并打印所有生效的分配属性名称
 * @param flag 内核下发的gfp_mask原始数值
 */
static void print_flag_modifiers(int flag)
{
	char buf[512] = {0};
	// 遍历掩码对照表，匹配所有置位的flag
	for (int i = 0; gfp_list[i].name; i++) {
		if (flag & gfp_list[i].flag) {
			if (buf[0]) strcat(buf, " | ");
			strcat(buf, gfp_list[i].name);
		}
	}
	// 存在标识则打印拼接字符串，无任何标识则打印none
	printf("%s", buf[0] ? buf : "none");
}
