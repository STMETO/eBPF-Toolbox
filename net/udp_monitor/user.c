#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "common/cli.h"
#include "common/types.h"
#include "common/logger.h"
#include "udp_monitor.h"
#include "net/udp_monitor/skel.h"

static struct udp_monitor_bpf *g_skel = NULL;
static int g_ncpus;

/**
 * @brief 将IPv4/IPv6地址转为人类可读字符串
 * @param buf 输出缓冲区
 * @param len 缓冲区最大长度
 * @param af 地址族 AF_INET / AF_INET6
 * @param v4 网络序32位IPv4地址
 * @param v6 16字节IPv6地址数组
 */
static void ip_str(char *buf, size_t len, int af, uint32_t v4, uint8_t *v6)
{
	/*
	 * 全零地址在本模块中表示入口回退未能得到路由后的地址，不把它伪装成
	 * 实际发送地址0.0.0.0/::，直接输出问号更符合五元组语义。
	 */
	if (af == AF_INET && v4 == 0)
		snprintf(buf, len, "?");
	else if (af == AF_INET)
		inet_ntop(AF_INET, &v4, buf, len);
	else if (af == AF_INET6) {
		static const uint8_t zero_v6[16];

		if (memcmp(v6, zero_v6, sizeof(zero_v6)) == 0)
			snprintf(buf, len, "?");
		else
			inet_ntop(AF_INET6, v6, buf, len);
	}
	else
		snprintf(buf, len, "?"); // 未知地址族占位
}

/** 将内核事件中的五元组来源转换为简短、稳定的输出标签。 */
static const char *tuple_source_str(bpf_u8_t source)
{
	switch (source) {
	case UDP_TUPLE_FLOW:
		return "FLOW";   // 路由完成后的flowi4/flowi6，代表真实发包五元组
	case UDP_TUPLE_MSG:
		return "MSG";    // 目的地址来自内核msghdr，源地址可能仍是回退值
	default:
		return "SOCKET"; // connect socket缓存；主要用于未经过send_skb的边界场景
	}
}

/**
 * @brief 程序退出时读取内核stats_map，打印UDP全局汇总统计
 */
static void print_stats(void)
{
	// BPF骨架未初始化直接返回
	if (!g_skel)
		return;

	struct UdpMonitor_stats s = {};
	size_t stride = (sizeof(struct UdpMonitor_stats) + 7U) & ~7U;
	void *values;
	int key = 0;
	// 读取全局统计数组唯一条目；读取失败或无任何发包事件直接不输出
	/*
	 * 【现实现修正】stats_map已经改为PERCPU_ARRAY，必须按8字节对齐后的
	 * value大小为所有possible CPU分配缓冲区，再逐CPU合并，不能继续按
	 * 普通ARRAY只读取一个结构体。
	 */
	if (g_ncpus <= 0)
		return;
	values = calloc((size_t)g_ncpus, stride);
	if (!values)
		return;
	if (bpf_map_lookup_elem(bpf_map__fd(g_skel->maps.stats_map), &key, values)) {
		free(values);
		return;
	}
	for (int cpu = 0; cpu < g_ncpus; cpu++) {
		const struct UdpMonitor_stats *v =
			(const void *)((char *)values + (size_t)cpu * stride);

		s.attempted += v->attempted;
		s.count += v->count;
		s.failed += v->failed;
		s.total_ns += v->total_ns;
		s.total_bytes += v->total_bytes;
		s.filtered_pid += v->filtered_pid;
		s.filtered_latency += v->filtered_latency;
		s.ringbuf_dropped += v->ringbuf_dropped;
		s.map_update_failed += v->map_update_failed;
		s.lookup_missed += v->lookup_missed;
		s.nested_calls += v->nested_calls;
		s.flow_tuple += v->flow_tuple;
		s.fallback_tuple += v->fallback_tuple;
		if (v->max_ns > s.max_ns) {
			s.max_ns = v->max_ns;
			s.max_pid = v->max_pid;
			s.max_tid = v->max_tid;
			memcpy(s.max_comm, v->max_comm, sizeof(s.max_comm));
		}
	}
	free(values);
	if (!s.attempted && !s.count && !s.failed)
		return;

	// 彩色打印统计面板
	log_output_lock();
	printf(C_CYAN C_BOLD "\n══════ UDP 监控统计 ══════\n" C_RESET);
	printf("  尝试: %" PRIu64 "  成功: %" PRIu64 "  失败: %" PRIu64
	       "  字节: %" PRIu64 "\n",
	       s.attempted, s.count, s.failed, s.total_bytes);
	if (s.count)
		printf("  平均: %" PRIu64 " ns  最大: %" PRIu64
		       " ns (PID=%u TID=%u %s)\n",
		       s.total_ns / s.count, s.max_ns, s.max_pid, s.max_tid,
		       s.max_comm);
	printf("  五元组: flow=%" PRIu64 " fallback=%" PRIu64
	       "  过滤: PID=%" PRIu64 " 延迟=%" PRIu64 "\n",
	       s.flow_tuple, s.fallback_tuple, s.filtered_pid,
	       s.filtered_latency);
	printf("  健康: ringbuf_drop=%" PRIu64 " map_fail=%" PRIu64
	       " lookup_miss=%" PRIu64 " nested=%" PRIu64 "\n",
	       s.ringbuf_dropped, s.map_update_failed, s.lookup_missed,
	       s.nested_calls);
	printf(C_CYAN C_BOLD "════════════════════════════\n" C_RESET);
	log_output_unlock();
}

/**
 * @brief SIGINT(Ctrl+C)/SIGTERM信号回调，捕获中断后打印统计并安全退出
 * @param sig 触发的信号值，未使用
 */
/**
 * @brief RingBuffer事件回调函数，内核推送UDP发包事件后自动执行
 * @param ctx 回调自定义上下文，未使用
 * @param data 内核下发的UdpMonitor_event事件数据指针
 * @param data_sz 事件结构体字节大小，未使用
 * @return int 固定返回0
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct UdpMonitor_event *e = data;
	(void)ctx;
	char src[64], dst[64];

	/* ABI防御：旧对象或损坏记录尺寸不足时不越界解释事件。 */
	if (data_sz < sizeof(*e))
		return 0;

	// 格式化源、目的IP字符串
	ip_str(src, sizeof(src), e->af, e->saddr_v4, (uint8_t*)e->saddr_v6);
	ip_str(dst, sizeof(dst), e->af, e->daddr_v4, (uint8_t*)e->daddr_v6);

	// 打印基础信息：PID、进程名、IP端口、发送字节
	log_output_lock();
	LOG("PID=%-6u TID=%-6d (%-16s) %s:%-5u → %s:%-5u | %-6" PRIu64
	    " B | %-6s | ",
	    e->tgid, e->pid, e->comm, src, e->sport, dst, e->dport, e->len,
	    tuple_source_str(e->tuple_source));
	// 彩色打印系统调用延迟，区分低/高延迟
	log_col_ns(e->latency_ns, 10000, 100000);
	printf("\n");
	log_output_unlock();
	return 0;
}

/**
 * @brief UDP发包监控主业务入口函数，完整管理BPF生命周期
 * @param poll_timeout_ms ringbuf阻塞轮询超时时间(毫秒)
 * @param enable 下发内核的监控总开关
 * @param target_pid PID过滤，0=监控全部进程，非0仅采集对应TGID进程
 * @param min_latency_ns 延迟过滤阈值，系统调用耗时低于该值不上报事件
 * @return int 0正常退出，非0代表异常错误码
 */
int udp_monitor_run(int poll_timeout_ms, bool enable,
		    bpf_s32_t target_pid, bpf_u64_t min_latency_ns)
{
	struct udp_monitor_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	const int key = 0;
	int err = 0;

	g_ncpus = libbpf_num_possible_cpus();
	if (g_ncpus <= 0) {
		fprintf(stderr, "获取possible CPU数量失败\n");
		return 1;
	}

	// 1. 打开并加载BPF骨架ELF，执行内核verifier校验
	skel = udp_monitor_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "打开BPF程序失败\n");
		return 1;
	}
	g_skel = skel;

	// 2. 组装监控控制参数，写入ctrl_map下发给内核BPF程序
	struct UdpMonitor_ctrl ctrl = {
		.enable = enable,
		.min_latency_ns = min_latency_ns,
		.target_pid = target_pid
	};
	err = app_get_pid_namespace(&ctrl.pid_ns_dev, &ctrl.pid_ns_ino);
	if (err) {
		fprintf(stderr, "读取PID namespace失败: %s\n", strerror(-err));
		goto cleanup;
	}
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key),
				   &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "设置控制开关失败: %s\n", strerror(-err));
		goto cleanup;
	}

	// 3. 注册中断信号捕获，实现Ctrl+C优雅退出
	// 4. 创建RingBuffer，绑定内核rb环形缓冲区与事件回调handle_event
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "创建RingBuffer失败\n");
		goto cleanup;
	}

	// 5. 挂载所有kprobe/kretprobe探针到内核udp_sendmsg函数
	err = udp_monitor_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载BPF程序失败\n");
		goto cleanup;
	}

	// 打印启动横幅、当前过滤规则
	log_output_lock();
	log_banner("UDP 发送监控", enable);
	if (target_pid)
		LOG("过滤 PID=%d  阈值=%" PRIu64 " ns\n", target_pid, min_latency_ns);
	else if (min_latency_ns)
		LOG("过滤 ALL PID  阈值=%" PRIu64 " ns\n", min_latency_ns);
	else
		LOG("过滤 ALL PID  阈值=无\n");

	// 打印输出表头分隔线
	LOG_HDR("%-7s %-7s %-16s %-22s %-22s %-10s %-7s %s",
		"PID", "TID", "COMM", "SRC:PORT", "DST:PORT", "BYTES",
		"TUPLE", "DELAY");
	LOG_SEP();
	log_output_unlock();

	// 6. 主循环：阻塞轮询ringbuf，持续消费内核UDP事件
	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) { // 被信号中断，正常退出循环
			err = 0;
			break;
		}
		if (err < 0) { // 轮询发生错误，打印后跳出循环
			fprintf(stderr, "轮询事件失败: %s\n", strerror(-err));
			break;
		}
	}

	// 循环退出，打印最终全局统计
	print_stats();

cleanup:
	// 统一资源释放流程，防止句柄泄漏
	g_skel = NULL;
	ring_buffer__free(rb);                // 销毁ringbuf事件通道
	udp_monitor_bpf__destroy(skel);       // 卸载探针、销毁BPF骨架
	return err < 0 ? -err : 0;
}
