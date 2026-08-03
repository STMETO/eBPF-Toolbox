#ifndef COMMON_PID_NAMESPACE_BPF_H
#define COMMON_PID_NAMESPACE_BPF_H

/*
 * 文件用途总述：
 * 这是一套 BPF 辅助函数库，专门解决【PID Namespace 容器场景下 PID 转换问题】
 * 原生bpf助手函数拿到的PID是内核全局PID（初始pidns），容器内进程看到的PID是容器ns内局部PID。
 * 本头文件提供4个核心inline函数：
 * 1. 获取当前线程在指定pidns下的 pid_tgid（TID+TGID）
 * 2. 根据 struct pid 对象，查找目标pidns内对应的PID号
 * 3. 根据task_struct，获取该任务在目标ns中的TID（线程id）
 * 4. 根据task_struct，获取该任务在目标ns中的TGID（进程组id/主线程pid）
 *
 * 使用方式：传入目标PID Namespace的inode号(ino)，即可查询任意task在该容器内可见PID；
 * 如果任务不在该namespace层级内，返回0，上层BPF程序直接丢弃事件，实现容器过滤。
 */

/*
 * Linux 内核定义 MAX_PID_NS_LEVEL = 32
 * pid namespace 支持嵌套最多32层（根ns level=0，逐层递增）
 * 循环需要覆盖 0~32，一共33层upid结构。
 * 固定常量上界非常关键：BPF verifier需要证明循环有边界、不会无限循环，否则加载失败。
 */
#define APP_PIDNS_LEVEL_COUNT 33

/**
 * @brief 获取当前线程在指定PID Namespace内的 pid_tgid
 * @param dev 目标pidns所在文件系统设备号（部分内核接口需要，兼容bpf_get_ns_current_pid_tgid）
 * @param ino 目标PID Namespace的inode号（唯一标识一个pid ns）
 * @return bpf_u64_t
 *      高32bit = TGID(进程ID)，低32bit = TID(线程ID)
 *      返回0：当前任务不在该namespace中，上层需要过滤丢弃事件
 * @note 如果传入ino=0，代表不做namespace转换，直接返回全局初始ns的pid_tgid
 */
static __always_inline bpf_u64_t
app_current_pid_tgid_ns(bpf_u64_t dev, bpf_u64_t ino)
{
	struct bpf_pidns_info info = {};

	/* ino=0 代表不指定容器ns，直接使用内核默认全局pidns */
	if (!ino)
		return bpf_get_current_pid_tgid();

	/*
	 * bpf_get_ns_current_pid_tgid：BPF helper
	 * 根据ns设备号+inode，查询current任务在该pidns下的tgid/pid
	 * 调用失败（任务不在该ns）返回负数
	 */
	if (bpf_get_ns_current_pid_tgid(dev, ino, &info, sizeof(info)) < 0)
		return 0;

	/* 拼接格式：高32位TGID，低32位TID，和bpf_get_current_pid_tgid格式保持一致 */
	return ((bpf_u64_t)info.tgid << 32) | info.pid;
}

/**
 * @brief 遍历struct pid层级upid数组，查找指定pidns内对应的PID号
 * @param pid task->thread_pid 指针，内核struct pid对象
 * @param ino 目标PID namespace inode
 * @return bpf_s32_t 容器内局部PID；找不到返回0
 *
 * 内核原理：
 * struct pid 内嵌 struct upid numbers[] 数组；
 * 每一层嵌套pid namespace对应一个upid；
 * upid.ns 指向对应pid_namespace实例，upid.nr 是该ns内可见PID；
 * numbers[0] = 根初始pidns；numbers[level] = 当前任务所在最内层ns。
 */
static __always_inline bpf_s32_t
app_pid_nr_in_ns(struct pid *pid, bpf_u64_t ino)
{
	bpf_u32_t level;

	/* 空指针或者未指定ns，直接返回0 */
	if (!pid || !ino)
		return 0;

	/* 获取当前pid对象所处的namespace嵌套层级 */
	level = BPF_CORE_READ(pid, level);
	/* 防御：内核最大层级32，超出直接返回，防止越界访问numbers数组 */
	if (level >= APP_PIDNS_LEVEL_COUNT)
		return 0;

/*
 * #pragma unroll：强制编译器循环展开
 * BPF verifier对可变循环限制严格，循环展开消除动态循环，更容易通过校验
 */
#pragma unroll
	for (int i = 0; i < APP_PIDNS_LEVEL_COUNT; i++) {
		struct upid upid = {};
		bpf_u32_t inum;

		/* i超过pid实际层级，后面没有有效upid，终止循环 */
		if (i > level)
			break;

		/* 读取第i层namespace对应的upid结构 */
		bpf_core_read(&upid, sizeof(upid), &pid->numbers[i]);
		if (!upid.ns)
			continue;

		/* 获取该upid归属pid namespace的inode号 */
		inum = BPF_CORE_READ(upid.ns, ns.inum);

		/* 和目标ns ino匹配，说明找到对应容器内PID */
		if ((bpf_u64_t)inum == ino)
			return upid.nr;
	}
	/* 遍历所有层级仍未匹配，该进程不在目标namespace内 */
	return 0;
}

/**
 * @brief 获取task_struct对应的【线程TID】在目标pidns中的PID号
 * @param task 目标任务task_struct指针
 * @param ino 目标pidns inode
 * @return 容器内TID，找不到返回0
 *
 * 原理：每个线程拥有独立 thread_pid，代表线程id（TID）
 */
static __always_inline bpf_s32_t
app_task_tid_ns(struct task_struct *task, bpf_u64_t ino)
{
	struct pid *pid;

	if (!task)
		return 0;
	/* thread_pid 代表线程自身pid（TID） */
	pid = BPF_CORE_READ(task, thread_pid);
	return app_pid_nr_in_ns(pid, ino);
}

/**
 * @brief 获取task_struct所属线程组【TGID（进程ID）】在目标pidns中的PID号
 * @param task 任意线程task_struct指针
 * @param ino 目标pidns inode
 * @return 容器内进程TGID，找不到返回0
 *
 * 重要知识点：
 * Linux线程组内所有线程共享同一个TGID，TGID等于线程组leader主线程的PID。
 * 不能直接读取当前task的thread_pid，必须找到group_leader主线程再获取pid。
 */
static __always_inline bpf_s32_t
app_task_tgid_ns(struct task_struct *task, bpf_u64_t ino)
{
	struct task_struct *leader;
	struct pid *pid;

	if (!task)
		return 0;
	/* 获取线程组主线程task_struct */
	leader = BPF_CORE_READ(task, group_leader);
	if (!leader)
		return 0;
	/* 主线程thread_pid就是进程TGID */
	pid = BPF_CORE_READ(leader, thread_pid);
	return app_pid_nr_in_ns(pid, ino);
}

#endif
