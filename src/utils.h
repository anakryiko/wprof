/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __UTILS_H_
#define __UTILS_H_

#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include "../libbpf/src/hashmap.h" /* internal to libbpf, yep */

typedef unsigned long long u64;
typedef unsigned int u32;

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#endif
#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif
#ifndef max
#define max(x, y) ((x) > (y) ? (x) : (y))
#endif
#define __unused __attribute__((unused))
#define __cleanup(fn) __attribute__((cleanup(fn)))

#ifndef offsetofend
#define offsetofend(TYPE, MEMBER) (offsetof(TYPE, MEMBER) + sizeof((((TYPE *)0)->MEMBER)))
#endif

/*
 * This function is from libbpf, but it is not a public API and can only be
 * used for demonstration. We can use this here because we statically link
 * against the libbpf built from submodule during build.
 */
extern int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz);

static inline long perf_event_open(struct perf_event_attr *hw_event,
				   pid_t pid, int cpu, int group_fd,
				   unsigned long flags)
{
	return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

ssize_t file_size(FILE *f);

static inline bool is_pow_of_2(long x)
{
        return x && (x & (x - 1)) == 0;
}

static inline int round_pow_of_2(int n)
{
        int tmp_n;

        if (is_pow_of_2(n))
                return n;

        for (tmp_n = 1; tmp_n <= INT_MAX / 4; tmp_n *= 2) {
                if (tmp_n >= n)
                        break;
        }

        if (tmp_n >= INT_MAX / 2)
                return -E2BIG;

        return tmp_n;
}

/* Copy up to sz - 1 bytes from zero-terminated src string and ensure that dst
 * is zero-terminated string no matter what (unless sz == 0, in which case
 * it's a no-op). It's conceptually close to FreeBSD's strlcpy(), but differs
 * in what is returned. Given this is internal helper, it's trivial to extend
 * this, when necessary. Use this instead of strncpy inside libbpf source code.
 */
static inline void strlcpy(char *dst, const char *src, size_t sz)
{
	size_t i;

	if (sz == 0)
		return;

	sz--;
	for (i = 0; i < sz && src[i]; i++)
		dst[i] = src[i];
	dst[i] = '\0';
}

const char *sfmt(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
const char *vsfmt(const char *fmt, va_list ap);

/* HASHMAP HELPERS */
static inline size_t str_hash_fn(long key, void *ctx)
{
	return str_hash((void *)key);
}

static inline bool str_equal_fn(long a, long b, void *ctx)
{
	return strcmp((void *)a, (void *)b) == 0;
}

static inline size_t hash_identity_fn(long key, void *ctx)
{
	return key;
}

static inline bool hash_equal_fn(long k1, long k2, void *ctx)
{
	return k1 == k2;
}

/* TIME ROUTINES */
static inline uint64_t timespec_to_ns(struct timespec *ts)
{
	return ts->tv_sec * 1000000000ULL + ts->tv_nsec;
}

static inline u64 ktime_now_ns()
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);

	return timespec_to_ns(&t);
}

void calibrate_ktime(void);

/* ARGS PARSING HELPERS */
int append_str(char ***strs, int *cnt, const char *str);
int append_str_file(char ***strs, int *cnt, const char *file);
int append_num(int **nums, int *cnt, const char *arg);

#endif /* __UTILS_H_ */
