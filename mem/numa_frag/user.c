#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>      
#include <bpf/bpf.h>         
#include "common/cli.h"      
#include "common/types.h"   
#include "numa_frag.h"      
#include "mem/numa_frag/skel.h"

/**
 * @brief NUMA节点信息采集主运行入口函数
 * @param poll_timeout_ms 预留参数：数据轮询超时毫秒（当前代码未使用）
 * @param enable 预留开关参数：采集总使能开关（当前代码未做启停控制逻辑）
 * @return int 执行状态码：0 正常退出，非0 代表加载/挂载BPF失败
 * @desc 功能：加载并挂载numa_frag eBPF探针，循环读取BPF哈希map中缓存的NUMA pgdat节点信息并打印
 */
int numa_frag_info_run(int poll_timeout_ms, bool enable)
{
    // BPF程序骨架句柄，libbpf自动生成的结构体，管理所有程序、map、探针
	struct numa_frag_bpf *skel = NULL;
	int err = 0;
    // 强制消除未使用参数编译警告，当前代码未实现开关控制与超时逻辑
	(void)poll_timeout_ms; (void)enable;

    // 1. 打开BPF字节码、加载到内核，完成map初始化、变量分配
	skel = numa_frag_bpf__open_and_load();
	if (!skel) {
        // 骨架加载失败：字节码错误、内核不支持BPF、权限不足、vmlinux缺失等
		fprintf(stderr, "Failed NumaFragInfo\n");
		return 1;
	}

    // 2. 将kprobe探针挂载到内核函数 get_page_from_freelist
	err = numa_frag_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Attach fail\n");
		goto cleanup; // 挂载失败，直接跳转释放资源
	}

    // 主循环：持续打印NUMA节点信息，直到程序收到退出信号(Ctrl+C等)
	while (!app_should_exit()) {
		sleep(1); // 1秒刷新一次输出，降低CPU占用

		struct pgdat_info pinfo; // 存储从nodes map读取的单条NUMA节点信息
		__u64 key = 0, next_key; // map遍历迭代器：key为当前游标，next_key存下一条key
        // 获取 nodes 哈希map对应的fd文件描述符
		int fd = bpf_map__fd(skel->maps.nodes);

        // 打印表头：节点ID、pgdat内核虚拟地址、该NUMA节点下zone数量
		printf(" Node ID          PGDAT_PTR       NR_ZONES \n");

        // 遍历整个哈希map：bpf_map_get_next_key 迭代读取所有key
		while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
            // 根据key读取对应pgdat节点完整信息
			bpf_map_lookup_elem(fd, &next_key, &pinfo);
            // 格式化打印节点数据：节点ID、pgdat指针十六进制、zone总数
			printf(" %5d       0x%llx  %5d\n", pinfo.node_id, pinfo.pgdat_ptr, pinfo.nr_zones);
            // 更新游标，下一轮迭代从当前next_key开始查找下一条
			key = next_key;
		}
		printf("\n"); // 单次刷新输出空行分隔
	}

cleanup:
    // 资源释放：卸载探针、销毁BPF骨架、释放内核map与程序资源
	numa_frag_bpf__destroy(skel);
    // 标准化错误码返回：负数错误转正数，无错返回0
	return err < 0 ? -err : 0;
}
