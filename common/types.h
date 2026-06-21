#ifndef __COMMON_TYPES_H
#define __COMMON_TYPES_H

#define TASK_COMM_LEN 16

/*
 * BPF context: vmlinux.h provides __u8/__u16/__u32/__u64 etc.
 * User-space context: these typedefs provide compatible types.
 */
#ifndef __BPF__
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
#else
/* In BPF context, use __u8/__u16/etc directly from vmlinux.h */
typedef __u8 bpf_u8_t;
typedef __u16 bpf_u16_t;
typedef __u32 bpf_u32_t;
typedef __u64 bpf_u64_t;
typedef __s8 bpf_s8_t;
typedef __s16 bpf_s16_t;
typedef __s32 bpf_s32_t;
typedef __s64 bpf_s64_t;
typedef _Bool bpf_bool_t;
#endif

#endif
