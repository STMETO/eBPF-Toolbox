#ifndef __BPF_COMMON_H
#define __BPF_COMMON_H

#define TASK_COMM_LEN 16

#if defined(__BPF__) && defined(__VMLINUX_H__)
typedef __u8 bpf_bool_t;
typedef __u8 bpf_u8_t;
typedef __u16 bpf_u16_t;
typedef __u32 bpf_u32_t;
typedef __u64 bpf_u64_t;
typedef __s8 bpf_s8_t;
typedef __s16 bpf_s16_t;
typedef __s32 bpf_s32_t;
typedef __s64 bpf_s64_t;
#else
#include <stdbool.h>
#include <stdint.h>
typedef bool bpf_bool_t;
typedef uint8_t bpf_u8_t;
typedef uint16_t bpf_u16_t;
typedef uint32_t bpf_u32_t;
typedef uint64_t bpf_u64_t;
typedef int8_t bpf_s8_t;
typedef int16_t bpf_s16_t;
typedef int32_t bpf_s32_t;
typedef int64_t bpf_s64_t;
#endif

#endif

/*
// 类型对应速查表
bpf_bool_t  →  bool
bpf_u8_t    →  unsigned char  (uint8_t)
bpf_u16_t   →  unsigned short (uint16_t)
bpf_u32_t   →  unsigned int   (uint32_t)
bpf_u64_t   →  unsigned long long (uint64_t)

bpf_s8_t    →  char    (int8_t)
bpf_s16_t   →  short   (int16_t)
bpf_s32_t   →  int     (int32_t)
bpf_s64_t   →  long long (int64_t)

*/