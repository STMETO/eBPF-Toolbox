#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <mqueue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void usage(void) {
	fprintf(stderr, "用法: ./trigger <命令>\n\n"
		"  tcp       发起 TCP 连接 (127.0.0.1:19999) → 触发 HANDSHAKE\n"
		"  udp       发送 UDP 包 → 触发 udp_monitor\n"
		"  mq        POSIX 消息队列 send+receive → 触发 msgqueue\n"
		"  mutex     双线程互斥锁竞争 → 触发 mutexlock\n"
		"  fs        open/read/write 临时文件 → 触发 fs_*\n"
		"  syscall   getpid() 循环 → 触发 syscall\n"
		"  sched     sched_yield 循环 → 触发 context_switch/preempt\n"
		"  slab      malloc/free 循环 → 触发 slab_rate\n"
		"  all       依次执行以上全部\n");
}

/* ── tcp: 发起连接 → SYN 握手 ────────────────────────────── */
static int do_tcp(void) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) { perror("socket"); return 1; }
	struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(19999)};
	inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
	printf("[tcp] connecting to 127.0.0.1:19999 ...\n");
	connect(fd, (struct sockaddr *)&addr, sizeof(addr)); /* expected ECONNREFUSED */
	close(fd);
	printf("[tcp] done (SYN sent, HANDSHAKE event triggered)\n");
	return 0;
}

/* ── udp: sendto → 触发 udp_sendmsg ───────────────────────── */
static int do_udp(void) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) { perror("socket"); return 1; }
	struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(9)};
	inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
	const char *msg = "hello";
	sendto(fd, msg, strlen(msg), 0, (struct sockaddr *)&addr, sizeof(addr));
	close(fd);
	printf("[udp] sent 5 bytes to 127.0.0.1:9\n");
	return 0;
}

/* ── mq: POSIX 消息队列 send + receive ───────────────────── */
static int do_mq(void) {
	struct mq_attr attr = {.mq_flags = 0, .mq_maxmsg = 10, .mq_msgsize = 64, .mq_curmsgs = 0};
	mqd_t mq = mq_open("/ebpf_test_mq", O_CREAT | O_RDWR, 0644, &attr);
	if (mq == (mqd_t)-1) { perror("mq_open"); return 1; }
	const char *msg = "ebpf test message";
	if (mq_send(mq, msg, strlen(msg) + 1, 0) < 0) { perror("mq_send"); mq_close(mq); return 1; }
	char buf[64];
	if (mq_receive(mq, buf, sizeof(buf), NULL) < 0) { perror("mq_receive"); }
	mq_close(mq);
	mq_unlink("/ebpf_test_mq");
	printf("[mq] send+receive done\n");
	return 0;
}

/* ── mutex: 双线程竞争 ────────────────────────────────────── */
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
static void *mutex_worker(void *arg) {
	(void)arg;
	pthread_mutex_lock(&g_mtx);
	usleep(10000); /* hold 10ms */
	pthread_mutex_unlock(&g_mtx);
	return NULL;
}
static int do_mutex(void) {
	pthread_t t1, t2;
	pthread_mutex_lock(&g_mtx);
	pthread_create(&t1, NULL, mutex_worker, NULL);
	pthread_create(&t2, NULL, mutex_worker, NULL);
	usleep(5000);
	pthread_mutex_unlock(&g_mtx); /* both workers will contend */
	pthread_join(t1, NULL);
	pthread_join(t2, NULL);
	printf("[mutex] 2 threads contended, done\n");
	return 0;
}

/* ── fs: open/read/write 临时文件 ──────────────────────────── */
static int do_fs(void) {
	const char *path = "/tmp/ebpf_trigger_test";
	int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd < 0) { perror("open"); return 1; }
	const char *data = "ebpf fs trigger test\n";
	write(fd, data, strlen(data));
	lseek(fd, 0, SEEK_SET);
	char buf[64];
	read(fd, buf, sizeof(buf));
	close(fd);
	unlink(path);
	printf("[fs] open/write/read/unlink on %s\n", path);
	return 0;
}

/* ── syscall: getpid() 循环 ───────────────────────────────── */
static int do_syscall(void) {
	for (int i = 0; i < 100; i++) getpid();
	printf("[syscall] getpid() x100\n");
	return 0;
}

/* ── sched: yield 循环 ────────────────────────────────────── */
static int do_sched(void) {
	for (int i = 0; i < 1000; i++) sched_yield();
	printf("[sched] sched_yield() x1000\n");
	return 0;
}

/* ── slab: malloc/free ────────────────────────────────────── */
static int do_slab(void) {
	void *ptrs[100];
	for (int i = 0; i < 100; i++) ptrs[i] = malloc(1024);
	for (int i = 0; i < 100; i++) free(ptrs[i]);
	printf("[slab] malloc(1024)/free x100\n");
	return 0;
}

/* ── main ─────────────────────────────────────────────────── */
int main(int argc, char **argv) {
	if (argc < 2) { usage(); return 1; }
	const char *cmd = argv[1];

	if      (!strcmp(cmd, "tcp"))     return do_tcp();
	else if (!strcmp(cmd, "udp"))     return do_udp();
	else if (!strcmp(cmd, "mq"))      return do_mq();
	else if (!strcmp(cmd, "mutex"))   return do_mutex();
	else if (!strcmp(cmd, "fs"))      return do_fs();
	else if (!strcmp(cmd, "syscall")) return do_syscall();
	else if (!strcmp(cmd, "sched"))   return do_sched();
	else if (!strcmp(cmd, "slab"))    return do_slab();
	else if (!strcmp(cmd, "all")) {
		return do_tcp() | do_udp() | do_mq() | do_mutex() |
		       do_fs() | do_syscall() | do_sched() | do_slab();
	}
	usage();
	return 1;
}
