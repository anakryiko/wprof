/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __WPROF_TYPES_H_
#define __WPROF_TYPES_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

typedef unsigned long long u64;
typedef signed long long s64;
typedef unsigned int u32;
typedef signed int s32;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned char u8;
typedef signed char s8;

/* wraparound-safe comparison of two monotonic (ktime) timestamps */
static inline int ts_cmp(u64 a, u64 b)
{
	s64 d = (s64)(a - b);

	return (d > 0) - (d < 0);
}

static inline bool ts_before(u64 a, u64 b)
{
	return ts_cmp(a, b) < 0;
}

static inline bool ts_after(u64 a, u64 b)
{
	return ts_cmp(a, b) > 0;
}

static inline bool ts_before_or_at(u64 a, u64 b)
{
	return ts_cmp(a, b) <= 0;
}

static inline bool ts_after_or_at(u64 a, u64 b)
{
	return ts_cmp(a, b) >= 0;
}

#endif /* __WPROF_TYPES_H_ */
