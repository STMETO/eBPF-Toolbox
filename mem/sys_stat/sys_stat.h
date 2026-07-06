/*
 * sys_stat.h 全局整机内存水位统计头文件
 * 定义控制开关结构体、整机内存事件结构体，内核BPF与用户态共用
 * 采集内核 vm_stat 页面统计指标，反映整机全局内存分类型占用
 */
 #ifndef __SYS_STAT_H
 #define __SYS_STAT_H
 
 // 统一跨平台BPF基础无符号64位类型 bpf_u64_t
 #include "common/types.h"
 
 /**
  * 控制结构体：用户态下发至ctrl_map，控制整机内存采集开关
  */
 struct SysStat_ctrl {
	 bpf_bool_t enable; // true开启采集，false关闭探针
 };
 
 /**
  * 环形缓冲区事件结构体
  * 存储内核zone vm_stat 全局内存页面统计数据
  * 所有数值单位：内核页（内核中一页默认4KB，代码内统一×4转为KB）
  * 字段对应内核 enum vm_stat_item 各项页面计数
  */
 struct SysStat_event {
	 // 总内存页预留字段，当前内核代码未填充
	 bpf_u64_t present;
	 // LRU匿名页
	 bpf_u64_t anon_inactive;    // 非活跃匿名页
	 bpf_u64_t anon_active;      // 活跃匿名页
	 // LRU文件页
	 bpf_u64_t file_inactive;    // 非活跃文件缓存页
	 bpf_u64_t file_active;      // 活跃文件缓存页
	 bpf_u64_t unevictable;      // 不可回收锁定页（mlock、设备内存等）
 
	 // Slab缓存内存
	 bpf_u64_t slab_reclaimable; // 可回收slab（dentry、inode缓存）
	 bpf_u64_t slab_unreclaimable;// 不可回收slab内核对象
 
	 // 隔离页（vmscan回收流程中临时隔离页面）
	 bpf_u64_t anon_isolated;
	 bpf_u64_t file_isolated;
 
	 // 工作集内存相关统计（页面冷热、refault重复载入）
	 bpf_u64_t working_nodes, working_refault, working_activate, working_restore, working_nodereclaim;
 
	 // 映射页
	 bpf_u64_t anon_mapped;      // 进程私有匿名映射页
	 bpf_u64_t file_mapped;      // 文件mmap映射页
	 bpf_u64_t file_pages;       // 文件缓存总页
	 bpf_u64_t file_dirty;       // 脏页（待刷盘文件缓存）
	 bpf_u64_t writeback;        // 正在回写到磁盘的页面
	 bpf_u64_t writeback_temp;   // 临时回写缓存页
 
	 // 共享内存、大页、NFS相关
	 bpf_u64_t shmem;            // shmem/tmpfs共享内存页
	 bpf_u64_t shmem_thps;       // shmem透明大页
	 bpf_u64_t pmdmapped;        // 设备pmd映射页
	 bpf_u64_t anon_thps;        // 匿名透明大页
	 bpf_u64_t unstable_nfs;     // NFS不稳定脏页
 
	 // 内存回收统计
	 bpf_u64_t vmscan_write;     // vmscan回收时写出页面数
	 bpf_u64_t vmscan_immediate; // 紧急直接回收页面
 
	 bpf_u64_t diried;           // 历史脏页计数预留
	 bpf_u64_t written;          // 刷盘总页数预留
	 bpf_u64_t kernel_misc_reclaimable; // 其他可回收内核杂项内存
 };
 
 /* 用户态API声明，仅用户态编译生效，BPF内核程序跳过 */
 #ifndef __BPF__
 #include <stdbool.h>
 /**
  * 整机内存统计采集主入口
  * @param poll_timeout_ms ringbuf阻塞读取超时毫秒
  * @param enable true启动采集，false关闭
  * @return 0正常，负数错误码
  */
 int sys_stat_run(int poll_timeout_ms, bool enable);
 #endif
 
 #endif
 