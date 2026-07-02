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
#include <pthread.h>
#include <sys/syscall.h>

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

/* Record a human-readable reason into a fixed-size run_ctx hint buffer. */
#define inj_set_feat_hint(hint, fmt, ...) snprintf(hint, sizeof(hint), fmt, ##__VA_ARGS__)

extern struct inj_setup_ctx *setup_ctx;
extern struct inj_run_ctx *run_ctx;
extern struct strset *cuda_respool_strs;

__printf(2, 3)
void log_printf(int verbosity, const char *fmt, ...);

void *dyn_resolve_sym(const char *sym_name, void *dlopen_handle);

/*
 * Register/unregister a dump fd while its session is live. On fork(), an atfork
 * child handler redirects every tracked fd to /dev/null (see libwprofinj_init),
 * so a forked child -- which we never capture in -- can neither write new events
 * nor flush its inherited stdio buffers into the parent's capture files.
 */
void inj_track_dump_fd(int fd);
void inj_untrack_dump_fd(int fd);

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

/*
 * gettid() is not cached by glibc, so each call is a real syscall. The hot
 * tracing paths call it per event, so cache it per-thread. New threads start
 * with freshly zeroed TLS, so the cache re-reads correctly (a real tid is never
 * 0). We don't support tracing from forked children (they'd inherit and corrupt
 * the parent's dump fd/stdio buffer regardless), so the post-fork stale-tid case
 * is moot.
 */
static inline u32 inj_gettid(void)
{
	static __thread u32 cached_tid;

	if (cached_tid == 0)
		cached_tid = (u32)syscall(SYS_gettid);
	return cached_tid;
}

#define atomic_add(p, v) __atomic_add_fetch((p), (v), __ATOMIC_RELAXED)
#define atomic_store(p, v) __atomic_store_n((p), (v), __ATOMIC_SEQ_CST)
#define atomic_load(p) __atomic_load_n((p), __ATOMIC_SEQ_CST)
#define atomic_xchg(p, v) __atomic_exchange_n((p), v, __ATOMIC_SEQ_CST)

/*
 * Per-feature data-stream writer: wraps the current chunk FILE* with a lock
 * and per-chunk accounting. With chunk_size == 0 it is a plain single file; a
 * later change rotates into a spare chunk once chunk_size bytes have been
 * written. The event write path runs on many tracee threads, so the lock
 * serializes writes + accounting (fwrite already serialized per FILE).
 */
struct chunker {
	pthread_mutex_t lock;
	enum inj_feature feature;
	u64 chunk_size;		/* rotate every N bytes; 0 = never (single file) */
	FILE *cur;		/* current chunk being written */
	u64 total_event_cnt;	/* cumulative across chunks, for run_ctx stats */
	int seq;		/* current chunk sequence number */

	u64 bytes;		/* current chunk: bytes written */
	u64 event_cnt;		/* current chunk: events written */
	u64 end_ts;		/* current chunk: max event ts */
} __aligned(64);

int chunker_init(struct chunker *chunker, int events_fd, enum inj_feature feature, size_t buf_sz);
int chunker_write(struct chunker *chunker, const void *rec, size_t sz, u64 ts);
int chunker_finalize(struct chunker *chunker);

int cuda_dump_event(struct wcuda_event *e);
int cuda_dump_finalize(void);

int init_cupti_activities(void);
int start_cupti_activities(void);
void finalize_cupti_activities(void);

int pytrace_session_setup(int events_fd, int respool_fd, int version_minor,
			  unsigned long *sym_addrs, int sym_addr_cnt);
int pytrace_session_finalize(void);

int pytorch_session_setup(int events_fd, int respool_fd, unsigned long *sym_addrs, int sym_addr_cnt);
int pytorch_session_finalize(void);

#endif /* __INJ_H_ */
