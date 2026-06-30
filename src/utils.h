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
	LOG_DISCOVERY = 0x20,
};

extern bool env_verbose;
extern int env_debug_level;
extern enum log_subset env_log_set;

__printf(2, 3) void log_printf(int verbosity, const char *fmt, ...);

#define eprintf(fmt, ...) log_printf(-1, fmt, ##__VA_ARGS__)
#define BUG(fmt, ...) do { eprintf("BUG (%s:%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__); exit(1); } while (0)
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

const char *libbpf_errstr(int err); /* from libbpf */
static inline const char *errstr(int err)  { return libbpf_errstr(err); }

struct btf;
/* Lazily parse and cache the running kernel's BTF; exits on failure. */
struct btf *load_vmlinux_btf(void);

static inline const char *fmt_timestamp_ns(u64 realtime_ns)
{
	time_t t = realtime_ns / 1000000000ULL;
	struct tm *tm = gmtime(&t);
	static char buf[64];
	int n = strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", tm);
	snprintf(buf + n, sizeof(buf) - n, ".%03dZ", (int)((realtime_ns % 1000000000ULL) / 1000000));
	return buf;
}
const char *vsfmt(const char *fmt, va_list ap);
int parse_int_from_file(const char *file, const char *fmt, void *val);
int parse_str_from_file(const char *file, char *buf, size_t buf_sz);
int parse_cpu_mask(const char *fcpu, bool **mask, int *mask_sz);

bool wprof_glob_match(const char *pat, const char *str);

static inline bool str_has_suffix(const char *str, const char *suffix)
{
	size_t str_len = strlen(str);
	size_t sfx_len = strlen(suffix);

	return str_len >= sfx_len && strcmp(str + str_len - sfx_len, suffix) == 0;
}

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
const char *fmt_time_units(u64 ns);

enum size_unit { SZ_NONE = 0, SZ_B, SZ_KB, SZ_MB, SZ_GB, SZ_TB };

int parse_size(const char *s, enum size_unit def_unit, u64 *out);
const char *fmt_size_units(u64 bytes);

static inline u64 ktime_now_ns()
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);

	return timespec_to_ns(&t);
}


void calibrate_ktime(void);
void set_ktime_off(u64 ktime_ns, u64 realtime_ns);
u64 ktime_to_realtime_ns(u64 ts_ns);
u64 realtime_to_ktime_ns(u64 ts_ns);

/*
 * A --prepare/--activate time spec, parsed from the CLI and later resolved to an
 * absolute ktime (CLOCK_MONOTONIC) instant via resolve_timespec().
 */
enum timespec_kind {
	TS_UNSET = 0,	/* option not given */
	TS_NOW,		/* @now */
	TS_ABS,		/* @<ISO time>: val = wall-clock (realtime) ns */
	TS_REL,		/* +<dur>: val = ns offset from wprof start */
	TS_ALIGN,	/* /<dur>: val = period ns, align to next epoch boundary */
};

struct timespec_spec {
	enum timespec_kind kind;
	u64 val;
};

int parse_timespec(const char *arg, struct timespec_spec *out);
u64 resolve_timespec(const struct timespec_spec *spec, u64 start_ktime_ns);

/* RFC 4122 UUID string: 36 chars (8-4-4-4-12 hex with dashes) + NUL. */
#define UUID_STR_LEN 37
void gen_uuid(char out[UUID_STR_LEN]);

/* ARGS PARSING HELPERS */
int append_str(char ***strs, int *cnt, const char *str);
int append_str_file(char ***strs, int *cnt, const char *file);
int append_num(int **nums, int *cnt, const char *arg);

#endif /* __UTILS_H_ */
