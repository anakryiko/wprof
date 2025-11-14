/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __INJ_H_
#define __INJ_H_

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include "inj_common.h"

#define zclose(fd) do { if (fd >= 0) { close(fd); fd = -1; } } while (0)
#define __printf(a, b) __attribute__((format(printf, a, b)))
#define __weak __attribute__((weak))
#define __aligned(N) __attribute__((aligned(N)))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#define elog(fmt, ...) do { log_printf(0, fmt, ##__VA_ARGS__); } while (0)
#define log(fmt, ...) do { log_printf(1, fmt, ##__VA_ARGS__); } while (0)
#define vlog(fmt, ...) do { log_printf(2, fmt, ##__VA_ARGS__); } while (0)
#define dlog(fmt, ...) do { log_printf(3, fmt, ##__VA_ARGS__); } while (0)

extern struct inj_setup_ctx *setup_ctx;
extern struct inj_run_ctx *run_ctx;
extern struct strset *cuda_dump_strs;

__printf(2, 3)
void log_printf(int verbosity, const char *fmt, ...);

void *dyn_resolve_sym(const char *sym_name, void *dlopen_handle);

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

#define atomic_add(p, v) __atomic_add_fetch((p), (v), __ATOMIC_RELAXED)
#define atomic_store(p, v) __atomic_store_n((p), (v), __ATOMIC_SEQ_CST)
#define atomic_load(p) __atomic_load_n((p), __ATOMIC_SEQ_CST)
#define atomic_xchg(p, v) __atomic_exchange_n((p), v, __ATOMIC_SEQ_CST)

int cuda_dump_event(struct wcuda_event *e);
int cuda_dump_finalize(void);

#endif /* __INJ_H_ */
