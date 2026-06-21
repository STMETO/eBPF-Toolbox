#ifndef __READ_H
#define __READ_H

#include "common/types.h"

// 文件类型掩码，统一放到头文件
#define S_IFMT  0170000
#define S_IFREG 0100000
#define S_IFCHR 0020000
#define S_IFDIR 0040000
#define S_IFLNK 0120000
#define S_IFBLK 0060000
#define S_IFIFO 0010000
#define S_IFSOCK 0140000

struct Read_ctrl {
	bpf_bool_t enable;
};

struct Read_event {
	bpf_s32_t pid;
	bpf_u64_t duration_ns;
};

#endif /* __READ_H */
