#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "common/cli.h"
#include "common/types.h"
#include "common/logger.h"
#include "udp_monitor.h"
#include "net/udp_monitor/skel.h"

static struct udp_monitor_bpf *g_skel = NULL;

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
	if (af == AF_INET)
		inet_ntop(AF_INET, &v4, buf, len);
	else if (af == AF_INET6)
		inet_ntop(AF_INET6, v6, buf, len);
	else
		snprintf(buf, len, "?"); // 未知地址族占位
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
	int key = 0;
	// 读取全局统计数组唯一条目；读取失败或无任何发包事件直接不输出
	if (bpf_map__lookup_elem(g_skel->maps.stats_map, &key, sizeof(key),
				 &s, sizeof(s), 0) || s.count == 0)
		return;

	// 彩色打印统计面板
	printf(C_CYAN C_BOLD "\n══════ UDP 监控统计 ══════\n" C_RESET);
	printf("  发送: %" PRIu64 " 次  %" PRIu64 " 字节\n", s.count, s.total_bytes);
	printf("  平均: %" PRIu64 " ns  最大: %" PRIu64 " ns (PID=%d %s)\n",
	       s.total_ns / s.count, s.max_ns, s.max_pid, s.max_comm);
	printf(C_CYAN C_BOLD "════════════════════════════\n" C_RESET);
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
	(void)data_sz;
	char src[64], dst[64];

	// 格式化源、目的IP字符串
	ip_str(src, sizeof(src), e->af, e->saddr_v4, (uint8_t*)e->saddr_v6);
	ip_str(dst, sizeof(dst), e->af, e->daddr_v4, (uint8_t*)e->daddr_v6);

	// 打印基础信息：PID、进程名、IP端口、发送字节
	LOG("PID=%-6d(%-16s) %s:%-5d → %s:%-5d | %-6" PRIu64 " B | ",
	    e->pid, e->comm, src, e->sport, dst, e->dport, e->len);
	// 彩色打印系统调用延迟，区分低/高延迟
	log_col_ns(e->latency_ns, 10000, 100000);
	printf("\n");
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
	log_banner("UDP 发送监控", enable);
	if (target_pid)
		LOG("过滤 PID=%d  阈值=%" PRIu64 " ns\n", target_pid, min_latency_ns);
	else if (min_latency_ns)
		LOG("过滤 ALL PID  阈值=%" PRIu64 " ns\n", min_latency_ns);
	else
		LOG("过滤 ALL PID  阈值=无\n");

	// 打印输出表头分隔线
	LOG_HDR("%-7s %-16s %-22s %-22s %-10s %s",
		"PID", "COMM", "SRC:PORT", "DST:PORT", "BYTES", "DELAY");
	LOG_SEP();

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
