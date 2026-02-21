/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __UTILS_H_
#define __UTILS_H_

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "hashmap.h" /* internal to libbpf, yep */
#include "wprof_types.h"

enum tristate { UNSET = -1, TRUE = 1, FALSE = 0 };

static inline bool is_true_or_unset(enum tristate tri)
{
	return tri == UNSET || tri == TRUE;
}

static inline bool is_false_or_unset(enum tristate tri)
{
	return tri == UNSET || tri == TRUE;
}

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
#define __weak __attribute__((weak))
#define __cleanup(fn) __attribute__((cleanup(fn)))
#define __printf(a, b) __attribute__((format(printf, a, b)))
#define __aligned(N) __attribute__((aligned(N)))

#define zclose(fd) do { if (fd >= 0) { close(fd); fd = -1; } } while (0)

#ifndef offsetofend
#define offsetofend(TYPE, MEMBER) (offsetof(TYPE, MEMBER) + sizeof((((TYPE *)0)->MEMBER)))
#endif

#define __str(X) __str_(X)
#define __str_(X) #X

#define wprof_for_each(type, cur, args...) for (						\
	/* initialize and define destructor */							\
	struct type##_iter ___it __attribute__((cleanup(type##_iter_destroy))),			\
			       *___p __attribute__((unused)) = (				\
					type##_iter_new(&___it, ##args),			\
					(void *)0);						\
	(((cur) = type##_iter_next(&___it)));							\
)

enum log_subset {
	LOG_LIBBPF = 0x01,
	LOG_USDT = 0x02,
	LOG_TOPOLOGY = 0x04,
	LOG_INJECTION = 0x08,
	LOG_TRACEE = 0x10,
};

extern bool env_verbose;
extern int env_debug_level;
extern enum log_subset env_log_set;

__printf(2, 3) void log_printf(int verbosity, const char *fmt, ...);

#define eprintf(fmt, ...) log_printf(-1, fmt, ##__VA_ARGS__)
#define wprintf(fmt, ...) log_printf(0, fmt, ##__VA_ARGS__)
#define vprintf(fmt, ...) log_printf(1, fmt, ##__VA_ARGS__)
#define dprintf(_level, fmt, ...) log_printf(1 + _level, fmt, ##__VA_ARGS__)
#define dlogf(_set, _level, fmt, ...) do {							\
	if (env_log_set & LOG_##_set)								\
		log_printf(1 + _level, fmt, ##__VA_ARGS__);						\
} while (0);

ssize_t file_size(FILE *f);
FILE *fopen_buffered(const char *path, const char *mode);
int file_splice_into(FILE *src_file, FILE *dst_file, off_t *off, size_t *sz);
void file_pad(FILE *f, size_t align);

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
static inline void wprof_strlcpy(char *dst, const char *src, size_t sz)
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
int parse_int_from_file(const char *file, const char *fmt, void *val);
int parse_str_from_file(const char *file, char *buf, size_t buf_sz);
int parse_cpu_mask(const char *fcpu, bool **mask, int *mask_sz);

bool wprof_glob_match(const char *pat, const char *str);

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

static inline unsigned long hash_combine(unsigned long h, unsigned long value)
{
	return h * 31 + value;
}

/* TIME ROUTINES */
static inline uint64_t timespec_to_ns(struct timespec *ts)
{
	return ts->tv_sec * 1000000000ULL + ts->tv_nsec;
}

s64 parse_time_units(const char *arg);

static inline u64 ktime_now_ns()
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);

	return timespec_to_ns(&t);
}

void calibrate_ktime(void);
void set_ktime_off(u64 ktime_ns, u64 realtime_ns);
u64 ktime_to_realtime_ns(u64 ts_ns);

/* ARGS PARSING HELPERS */
int append_str(char ***strs, int *cnt, const char *str);
int append_str_file(char ***strs, int *cnt, const char *file);
int append_num(int **nums, int *cnt, const char *arg);

#endif /* __UTILS_H_ */
