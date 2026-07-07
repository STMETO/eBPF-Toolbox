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
#include "tcp_monitor.h"
#include "net/tcp_monitor/skel.h"

static struct tcp_monitor_bpf *g_skel = NULL;

/**
 * @brief 格式化IP+端口为可读字符串，支持IPv4/IPv6
 * @param buf 输出缓冲区
 * @param len 缓冲区长度
 * @param af 地址族 AF_INET / AF_INET6
 * @param v4 IPv4 网络序32位地址
 * @param v6 IPv6 16字节地址数组
 * @param port 网络序端口号
 * @note IPv6映射IPv4地址(::ffff:a.b.c.d)简化输出为a.b.c.d，纯IPv6用[]包裹区分端口
 */
static void fmt_addr(char *buf, size_t len, int af, uint32_t v4, uint8_t *v6, uint16_t port)
{
	char ip[INET6_ADDRSTRLEN];
	if (af == AF_INET) {
		// IPv4 转换点分十进制
		inet_ntop(AF_INET, &v4, ip, sizeof(ip));
	} else if (af == AF_INET6) {
		inet_ntop(AF_INET6, v6, ip, sizeof(ip));
		// 处理IPv4映射IPv6地址，精简显示
		if (strncmp(ip, "::ffff:", 7) == 0) {
			snprintf(buf, len, "%s:%-5d", ip + 7, ntohs(port));
		} else {
			// 标准IPv6加方括号区分端口
			snprintf(buf, len, "[%s]:%-5d", ip, ntohs(port));
		}
		return;
	} else {
		// 未知地址族占位输出
		snprintf(buf, len, "?:%-5d", ntohs(port));
		return;
	}
	// IPv4 格式化输出 IP:端口
	snprintf(buf, len, "%s:%-5d", ip, ntohs(port));
}

/**
 * @brief 程序退出时打印全局TCP汇总统计信息
 * 从stats_map读取累计握手、重传、关闭计数、最大握手延迟等指标
 */
static void print_stats(void)
{
	// BPF骨架未初始化直接返回
	if (!g_skel)
		return;

	struct TcpMonitor_stats s = {};
	int key = 0;
	// 读取数组map唯一条目key=0；读取失败或无任何事件直接不打印
	if (bpf_map__lookup_elem(g_skel->maps.stats_map, &key, sizeof(key),
			&s, sizeof(s), 0) || s.hs_count + s.rt_count + s.cl_count == 0)
		return;

	char src[64], dst[64];
	fprintf(stderr, "\n");
	// 彩色表头打印
	printf(C_CYAN C_BOLD "══════ TCP 监控统计 ══════\n" C_RESET);
	// 打印握手汇总：总次数、平均延迟、最大延迟及对应连接四元组
	if (s.hs_count) {
		fmt_addr(src, sizeof(src), AF_INET, s.hs_max_saddr, NULL, s.hs_max_sport);
		fmt_addr(dst, sizeof(dst), AF_INET, s.hs_max_daddr, NULL, s.hs_max_dport);
		printf("  握手: %" PRIu64 " 次  avg=%" PRIu64 " us  max=%" PRIu64 " us"
		       "  (%s → %s)\n",
		       s.hs_count, s.hs_total_ns / (s.hs_count * 1000),
		       s.hs_max_ns / 1000, src, dst);
	}
	// 全局总重传次数
	if (s.rt_count)
		printf("  重传: %" PRIu64 " 次\n", s.rt_count);
	// 总关闭连接次数
	if (s.cl_count)
		printf("  关闭: %" PRIu64 " 次\n", s.cl_count);
	printf(C_CYAN C_BOLD "════════════════════════════\n" C_RESET);
}

/**
 * @brief SIGINT/SIGTERM信号回调：捕获Ctrl+C，打印统计并退出
 */
static void sig_handler(int sig)
{
	(void)sig;
	print_stats();
	_exit(0);
}

/**
 * @brief TCP内核状态数字转可读字符串
 * @param state sk->__sk_common.skc_state 数值
 * @return 简短状态名
 */
static const char *tcp_state_str(uint32_t state)
{
	switch (state) {
	case 1: return "ESTAB";    // 连接建立
	case 2: return "SYN_SENT"; // 客户端发SYN等待应答
	case 3: return "SYN_RECV"; // 服务端收到SYN
	case 4: return "FIN_W1";   // FIN_WAIT_1
	case 5: return "CLOSE_W";  // CLOSE_WAIT
	case 6: return "LAST_ACK";
	case 7: return "TIME_W";  // TIME_WAIT
	case 8: return "CLOSED";
	default: return "???";
	}
}

/**
 * @brief RingBuf事件回调，内核推送事件后触发解析打印
 * @param ctx 回调上下文（未使用）
 * @param data 内核下发的TcpMonitor_event事件指针
 * @param data_sz 事件结构体大小
 * @return 固定返回0
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct TcpMonitor_event *e = data;
	(void)ctx;
	(void)data_sz;
	char src[48], dst[48];

	// 格式化源、目的IP端口字符串
	fmt_addr(src, sizeof(src), e->af, e->saddr_v4, (uint8_t*)e->saddr_v6, e->sport);
	fmt_addr(dst, sizeof(dst), e->af, e->daddr_v4, (uint8_t*)e->daddr_v6, e->dport);

	// 按事件类型区分打印格式
	switch (e->type) {
		case TCP_EV_HANDSHAKE:
			// 绿色握手事件，打印建连耗时(微秒)
			LOG("%-10s | PID=%-6d %-16s %-25s → %-25s | ",
				C_GREEN "HANDSHAKE" C_RESET, e->pid, e->comm, src, dst);
			log_col_us(e->latency_ns / 1000, 1000, 10000);
			printf("\n");
			break;
		case TCP_EV_RETRANSMIT:
			// 黄色重传事件，打印当前累计重传数、TCP状态
			LOG("%-10s | PID=%-6d %-16s %-25s ← %-25s | R#%-3u %s\n",
				C_YELLOW "RETRANSMIT" C_RESET, e->pid, e->comm, src, dst,
				e->retrans_cnt, tcp_state_str(e->state));
			break;
		case TCP_EV_CLOSE:
			// 青色关闭事件，打印整条连接总重传数、关闭时TCP状态
			LOG("%-10s | PID=%-6d %-16s %-25s → %-25s | R#%-3u %s\n",
				C_CYAN "CLOSE" C_RESET, e->pid, e->comm, src, dst,
				e->retrans_cnt, tcp_state_str(e->state));
			break;
	}
	return 0;
}

/**
 * @brief TCP监控主业务入口函数
 * @param poll_timeout_ms ringbuf阻塞读取超时时间(ms)
 * @param enable 下发给内核的总开关
 * @param target_pid 过滤指定进程TGID，0=全量采集
 * @param min_latency_ns 握手延迟过滤阈值(当前内核未使用预留)
 * @return 0正常退出，非0异常错误码
 */
int tcp_monitor_run(int poll_timeout_ms, bool enable,
		    bpf_s32_t target_pid, bpf_u64_t min_latency_ns)
{
	struct tcp_monitor_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	const int key = 0;
	int err = 0;

	// 1. 打开并加载BPF骨架（ELF加载、map创建、校验verifier）
	skel = tcp_monitor_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "打开BPF程序失败\n");
		return 1;
	}
	g_skel = skel;

	// 2. 填充控制参数，写入ctrl_map下发给内核BPF程序
	struct TcpMonitor_ctrl ctrl = {
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

	// 3. 注册信号捕获，Ctrl+C/程序终止触发统计打印
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 4. 创建RingBuffer，绑定内核rb map与事件回调handle_event
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		fprintf(stderr, "创建RingBuffer失败\n");
		goto cleanup;
	}

	// 5. 挂载所有fentry/kprobe探针到内核
	err = tcp_monitor_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "挂载BPF程序失败\n");
		goto cleanup;
	}

	// 打印启动横幅、过滤提示、表头分隔线
	log_banner("TCP 网络监控", enable);
	if (target_pid)
		LOG("过滤 PID=%d\n", target_pid);
	LOG_HDR("%-12s %-7s %-16s %-26s %-26s %s",
		"EVENT", "PID", "COMM", "SRC:PORT", "DST:PORT", "DETAIL");
	LOG_SEP();

	// 6. 主循环：阻塞轮询ringbuf等待内核事件
	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "轮询事件失败: %s\n", strerror(-err));
			break;
		}
	}

	// 循环退出，打印最终汇总统计
	print_stats();

cleanup:
	// 资源释放流程
	g_skel = NULL;
	ring_buffer__free(rb);                // 销毁ringbuf
	tcp_monitor_bpf__destroy(skel);       // 卸载BPF、销毁骨架
	return err < 0 ? -err : 0;
}
