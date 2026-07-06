/*
 * sys_stat 用户态采集程序
 * 配套内核eBPF探针，接收整机全局内存vm_stat指标，实时打印系统内存LRU、脏页、共享内存等大盘数据
 * 数据通路：内核ringbuf推送SysStat_event事件 → libbpf回调格式化输出
 * 观测维度：整机系统全局内存，区别于proc_stat进程内存、slab_rate内核slab分配统计
 */
#include <errno.h>
#include <stdio.h>
#include <bpf/libbpf.h>
#include "common/cli.h"
#include "common/types.h"
#include "sys_stat.h"
#include "sys_stat.h"
#include "mem/sys_stat/skel.h"
#include "common/logger.h"

/**
 * ringbuf事件回调函数
 * 内核每次采样整机内存数据推送ringbuf后，libbpf自动触发此函数
 * @param ctx 自定义上下文，本程序未使用
 * @param data 内核下发的SysStat_event内存指标结构体
 * @param data_sz 事件数据长度，校验字段，本程序忽略
 * @return 0 正常消费事件
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	// 强制转换为整机内存事件结构体
	const struct SysStat_event *e = data;
	// 消除未使用参数编译警告
	(void)ctx;
	(void)data_sz;

	// 格式化打印内存指标，单位KB（内核已预先完成页×4换算）
	// 打印字段：总活跃页 | 总非活跃页 | 匿名活跃 | 匿名非活跃 | 文件活跃 | 文件非活跃 | 不可回收页 | 脏页 | 回写页 | 匿名映射 | 文件映射 | 共享内存shmem
	printf("%-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu\n",
	       e->anon_active + e->file_active,    // ACTIVE：全部冷热活跃页面总和
	       e->file_inactive + e->anon_inactive,// INACTVE：全部冷热非活跃页面总和
	       e->anon_active,                     // ANON_ACT：活跃匿名内存
	       e->anon_inactive,                   // ANON_INA：非活跃匿名内存
	       e->file_active,                     // FILE_ACT：活跃文件缓存
	       e->file_inactive,                   // FILE_INA：非活跃文件缓存
	       e->unevictable,                     // UNEVICT：锁定不可回收内存
	       e->file_dirty,                      // DIRTY：待刷盘脏页
	       e->writeback,                       // WRITEBK：正在回写磁盘页面
	       e->anon_mapped,                     // ANONPAG：进程私有匿名映射页
	       e->file_mapped,                     // MAP：文件mmap映射页
	       e->shmem);                          // SHMEM：shmem/tmpfs共享内存
	return 0;
}

/**
 * 整机内存统计采集主入口函数
 * @param poll_timeout_ms ringbuf阻塞轮询超时时间(ms)，无新数据超时返回
 * @param enable true开启内核内存采样探针，false关闭
 * @return 0 正常退出；负数/正数为错误码
 */
int sys_stat_run(int poll_timeout_ms, bool enable)
{
	// BPF骨架对象，管理内核程序、两张MAP生命周期
	struct sys_stat_bpf *skel = NULL;
	// ringbuf句柄，用于阻塞读取内核推送的内存采样事件
	struct ring_buffer *rb = NULL;
	// 下发至ctrl_map的采集开关配置
	struct SysStat_ctrl ctrl = { .enable = enable };
	// 控制数组MAP固定查询key=0
	const int key = 0;
	int err = 0;

	// 1. 打开BPF字节码并加载至内核，自动创建ctrl_map、rb环形缓冲区
	skel = sys_stat_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed SysStat BPF skeleton open&load\n");
		return 1;
	}

	// 2. 更新控制MAP，下发采集启停开关给内核BPF探针
	// BPF_ANY：key不存在新建，存在则覆盖
	err = bpf_map__update_elem(skel->maps.ctrl_map, &key, sizeof(key), &ctrl, sizeof(ctrl), BPF_ANY);
	if (err < 0) {
		fprintf(stderr, "Update ctrl_map fail\n");
		goto cleanup; // 出错统一跳转资源释放
	}

	// 3. 绑定内核ringbuf fd与事件回调函数handle_event
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -ENOMEM;
		goto cleanup;
	}

	// 4. 将kprobe挂载到内核get_page_from_freelist，开始采样整机内存
	err = sys_stat_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "BPF kprobe attach fail\n");
		goto cleanup;
	}

	// 打印输出表头，与下方打印字段一一对应
	printf("%-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s\n",
	       "ACTIVE", "INACTVE", "ANON_ACT", "ANON_INA", "FILE_ACT", "FILE_INA",
	       "UNEVICT", "DIRTY", "WRITEBK", "ANONPAG", "MAP", "SHMEM");

	// 主事件循环：持续阻塞读取ringbuf，直到捕获Ctrl+C退出信号
	while (!app_should_exit()) {
		err = ring_buffer__poll(rb, poll_timeout_ms);
		// 被外部信号中断（Ctrl+C），正常退出循环
		if (err == -EINTR) {
			err = 0;
			break;
		}
		// 其他负错误码，终止采集
		if (err < 0)
			break;
	}

cleanup:
	// 统一释放资源，防止内核探针、MAP、内存句柄残留
	ring_buffer__free(rb);        // 销毁ringbuf读取器
	sys_stat_bpf__destroy(skel);  // 卸载kprobe、销毁内核MAP、释放骨架内存

	// 错误码转正后返回上层调用
	return err < 0 ? -err : 0;
}
