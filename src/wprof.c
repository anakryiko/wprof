// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <argp.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <time.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <pthread.h>
#include <limits.h>
#include <linux/fs.h>
#include <sched.h>

#include "utils.h"
#include "wprof.h"
#include "data.h"
#include "wprof.skel.h"

#include "env.h"
#include "wprof_build_info.h"
#include "protobuf.h"
#include "emit.h"
#include "stacktrace.h"
#include "topology.h"
#include "wrust.h"
#include "proc.h"
#include "requests.h"
#include "cuda_data.h"
#include "pytrace.h"
#include "pytrace_data.h"
#include "injmgr.h"
#include "bpf_utils.h"
#include "elf_utils.h"
#include "sys.h"
#include "inject.h"
#include "inj_common.h"
#include "merge.h"
#include "../libbpf/src/strset.h"
#include "pystacks.h"
#include "pysym.h"
#include "utrace.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !(env.log_set & LOG_LIBBPF))
		return 0;
	return vfprintf(stderr, format, args);
}

const struct capture_feature capture_features[] = {
	{"IPIs", "IPIs:", "capture_ipis", DEFAULT_CAPTURE_IPIS,
	 offsetof(struct env, capture_ipis), CFG_CAPTURE_IPIS},
	{"requests", "Requests:", "capture_requests", DEFAULT_CAPTURE_REQUESTS,
	 offsetof(struct env, capture_requests), CFG_CAPTURE_REQUESTS},
	{"sched-ext info", "SCX info:", "capture_scx", DEFAULT_CAPTURE_SCX,
	 offsetof(struct env, capture_scx), CFG_CAPTURE_SCX},
	{"CUDA", "CUDA:", "capture_cuda", DEFAULT_CAPTURE_CUDA,
	 offsetof(struct env, capture_cuda), CFG_CAPTURE_CUDA},
	{"Python stacks", "PyStacks:", "capture_pystacks", DEFAULT_CAPTURE_PYSTACKS,
	 offsetof(struct env, capture_pystacks), CFG_CAPTURE_PYSTACKS},
	{"Python function tracing", "PyTrace:", "capture_pytrace", DEFAULT_CAPTURE_PYTRACE,
	 offsetof(struct env, capture_pytrace), CFG_CAPTURE_PYTRACE},
	{"PyTorch RecordFunction", "PyTorch:", "capture_pytorch", DEFAULT_CAPTURE_TORCH_PROFILER,
	 offsetof(struct env, capture_pytorch), CFG_CAPTURE_PYTORCH},
	{"user-defined tracing", "Utrace:", "capture_utrace", DEFAULT_CAPTURE_UTRACE,
	 offsetof(struct env, capture_utrace), CFG_CAPTURE_UTRACE},
	{"softirqs", "Softirqs:", "capture_softirq", DEFAULT_CAPTURE_SOFTIRQ,
	 offsetof(struct env, capture_softirq), CFG_CAPTURE_SOFTIRQ},
	{"hardirqs", "Hardirqs:", "capture_hardirq", DEFAULT_CAPTURE_HARDIRQ,
	 offsetof(struct env, capture_hardirq), CFG_CAPTURE_HARDIRQ},
	{"context switches", "Context switches:", "capture_sched", DEFAULT_CAPTURE_SCHED,
	 offsetof(struct env, capture_sched), CFG_NO_SCHED, true},
	{"wakeups", "Wakeups:", "capture_wakeup", DEFAULT_CAPTURE_WAKEUP,
	 offsetof(struct env, capture_wakeup), CFG_NO_WAKEUP, true},
	{"task lifetime", "Task lifetime:", "capture_task_life", DEFAULT_CAPTURE_TASK_LIFE,
	 offsetof(struct env, capture_task_life), CFG_NO_TASK_LIFE, true},
	{"workqueues", "Workqueues:", "capture_wq", DEFAULT_CAPTURE_WQ,
	 offsetof(struct env, capture_wq), CFG_NO_WQ, true},
};

const int capture_feature_cnt = ARRAY_SIZE(capture_features);

const struct emit_feature emit_features[] = {
	{WEXTRA_EMIT_NUMA, offsetof(struct env, emit_numa), DEFAULT_EMIT_NUMA},
	{WEXTRA_EMIT_TIDPID, offsetof(struct env, emit_tidpid), DEFAULT_EMIT_TIDPID},
	{WEXTRA_EMIT_TIMER_TICKS, offsetof(struct env, emit_timer_ticks), DEFAULT_EMIT_TIMER_TICKS},
	{WEXTRA_EMIT_SCHED, offsetof(struct env, emit_sched_view), DEFAULT_EMIT_SCHED},
	{WEXTRA_EMIT_SCHED_EXTRAS, offsetof(struct env, emit_sched_extras), DEFAULT_EMIT_SCHED_EXTRAS},
	{WEXTRA_EMIT_PYSTACKS_ONLY, offsetof(struct env, emit_pystacks_only), DEFAULT_EMIT_PYSTACKS_ONLY},
	{WEXTRA_EMIT_REQ_SPLIT, offsetof(struct env, emit_req_split), DEFAULT_EMIT_REQ_SPLIT},
	{WEXTRA_EMIT_REQ_EMBED, offsetof(struct env, emit_req_embed), DEFAULT_EMIT_REQ_EMBED},
	{WEXTRA_EMIT_EMBED_STACKS, offsetof(struct env, emit_embed_stacks), DEFAULT_EMIT_EMBED_STACKS},
};

const int emit_feature_cnt = ARRAY_SIZE(emit_features);

/*
 * Render an extra param as the CLI option that produced it. -e options carry
 * their on/off value in the union; everything else carries an optional string
 * argument in stroff.
 */
const char *extra_param_str(struct wprof_data_hdr *hdr, const struct wprof_extra_param *e)
{
	switch (e->kind) {
	case WEXTRA_FILTER_PID_ALLOW:		return sfmt("--pid %s", wevent_str(hdr, e->stroff));
	case WEXTRA_FILTER_PID_DENY:		return sfmt("--no-pid %s", wevent_str(hdr, e->stroff));
	case WEXTRA_FILTER_TID_ALLOW:		return sfmt("--tid %s", wevent_str(hdr, e->stroff));
	case WEXTRA_FILTER_TID_DENY:		return sfmt("--no-tid %s", wevent_str(hdr, e->stroff));
	case WEXTRA_FILTER_PNAME_ALLOW:		return sfmt("--process-name %s", wevent_str(hdr, e->stroff));
	case WEXTRA_FILTER_PNAME_DENY:		return sfmt("--no-process-name %s", wevent_str(hdr, e->stroff));
	case WEXTRA_FILTER_TNAME_ALLOW:		return sfmt("--thread-name %s", wevent_str(hdr, e->stroff));
	case WEXTRA_FILTER_TNAME_DENY:		return sfmt("--no-thread-name %s", wevent_str(hdr, e->stroff));
	case WEXTRA_FILTER_IDLE_ALLOW:		return "--idle";
	case WEXTRA_FILTER_IDLE_DENY:		return "--no-idle";
	case WEXTRA_FILTER_KTHREAD_ALLOW:	return "--kthread";
	case WEXTRA_FILTER_KTHREAD_DENY:	return "--no-kthread";
	case WEXTRA_UTRACE_DEF:			return sfmt("--utrace %s", wevent_str(hdr, e->stroff));
	case WEXTRA_METADATA:			return sfmt("--metadata %s", wevent_str(hdr, e->stroff));
	case WEXTRA_STATS:			return "--stats";
	case WEXTRA_PMU:			return sfmt("--pmu %s", wevent_str(hdr, e->stroff));
	case WEXTRA_EMIT_NUMA:			return e->value ? "-e numa" : "-e no-numa";
	case WEXTRA_EMIT_TIDPID:		return e->value ? "-e tidpid" : "-e no-tidpid";
	case WEXTRA_EMIT_TIMER_TICKS:		return e->value ? "-e timer-ticks" : "-e no-timer-ticks";
	case WEXTRA_EMIT_SCHED:			return e->value ? "-e sched" : "-e no-sched";
	case WEXTRA_EMIT_SCHED_EXTRAS:		return e->value ? "-e sched-extras" : "-e no-sched-extras";
	case WEXTRA_EMIT_PYSTACKS_ONLY:		return e->value ? "-e py-stacks-only" : "-e no-py-stacks-only";
	case WEXTRA_EMIT_REQ_SPLIT:		return e->value ? "-e req-split" : "-e no-req-split";
	case WEXTRA_EMIT_REQ_EMBED:		return e->value ? "-e req-embed" : "-e no-req-embed";
	case WEXTRA_EMIT_EMBED_STACKS:		return e->value ? "-e embed-stacks" : "-e no-embed-stacks";
	case WEXTRA_PREPARE_SPEC:		return sfmt("--prepare %s", wevent_str(hdr, e->stroff));
	case WEXTRA_ACTIVATE_SPEC:		return sfmt("--activate %s", wevent_str(hdr, e->stroff));
	case WEXTRA_STACK_CAPTURE:
		switch (e->arg) {
		case ST_TIMER:		return sfmt("--stacks=timer=%uhz", e->value);
		case ST_PMU:		return sfmt("--stacks=pmu=%s", wevent_str(hdr, e->stroff));
		case ST_OFFCPU:		return "--stacks=offcpu";
		case ST_WAKER:		return "--stacks=waker";
		case ST_CUDA:		return "--stacks=cuda";
		case ST_REQ:		return "--stacks=req";
		case ST_UTRACE:		return "--stacks=utrace";
		default:		return sfmt("--stacks=!!unknown!!(%llu)", e->arg);
		}
	case WEXTRA_FR_SPEC:			return sfmt("--flight-record=%s", wevent_str(hdr, e->stroff));
	default:
		BUG("unknown extra param kind %d\n", e->kind);
	}
}

static volatile bool exiting;

static void sig_term(int sig)
{
	exiting = true;
	if (env.sess_ctl.sig_efd >= 0) {
		u64 v = 1;
		(void)write(env.sess_ctl.sig_efd, &v, sizeof(v));
	}
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
}

static void sig_pipe(int sig)
{
	eprintf("!!! Got unexpected SIGPIPE!\n");
}

/*
 * Flight-recorder thread state (flightrec mode only). Workers hand off their
 * just-completed chunks via the intrusive `incoming` list; the FR thread
 * fcloses them, pushes them into the PQ, and tracks size/newest-ts. The lock
 * guards ONLY `incoming` + `stopping`; the PQ and the scalars below it are
 * touched solely by the FR thread (and by main only after the thread joins).
 */
struct fr_state {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	struct fr_chunk *incoming;	/* intrusive singly-linked handoff list; NULL when empty */
	bool stopping;

	char *workdir;			/* where rotated chunks are created; set before threads run */

	/* FR-thread-private (no lock); main-readable after join */
	struct wppq *pq;
	u64 total_size;
	u64 rec_max_ts;			/* max end_ts over completed chunks */
	u64 rec_min_ts;			/* window floor: max end_ts of evicted chunks */
	pthread_t thread;
	bool joined;			/* thread already joined; fr_join() is then a no-op */
};

static struct fr_state *fr;

static void *fr_worker(void *ctx)
{
	struct fr_state *st = ctx;

	pthread_setname_np(pthread_self(), "wprof_flightrec");

	for (;;) {
		pthread_mutex_lock(&st->lock);
		while (!st->stopping && !st->incoming)
			pthread_cond_wait(&st->cond, &st->lock);

		struct fr_chunk *batch = st->incoming;
		st->incoming = NULL;
		bool stopping = st->stopping;
		pthread_mutex_unlock(&st->lock);

		struct fr_chunk *next;
		for (struct fr_chunk *c = batch; c; c = next) {
			next = c->next;
			c->next = NULL;
			fclose(c->f); /* flush to disk; no fsync */
			c->f = NULL;
			st->total_size += c->byte_sz;
			st->rec_max_ts = ts_max(st->rec_max_ts, c->end_ts);
			wppq_push(st->pq, c->end_ts, c);
		}

		/*
		 * Evict the oldest completed chunks while over the size or time window.
		 * The newest data lives in the per-worker current chunks, which are never
		 * in the PQ, so the PQ may legitimately drain to empty.
		 */
		while (!wppq_empty(st->pq)) {
			u64 chunk_max_ts = wppq_peek_key(st->pq);
			bool over_size = env.fr_keep_size && st->total_size > env.fr_keep_size;
			bool over_time = env.fr_keep_time_ns && st->rec_max_ts - chunk_max_ts > env.fr_keep_time_ns;

			if (!over_size && !over_time)
				break;

			struct fr_chunk *c = wppq_pop(st->pq);
			st->total_size -= c->byte_sz;
			st->rec_min_ts = ts_max(st->rec_min_ts, c->end_ts);

			unlink(c->path);
			free(c->path);
			free(c);
		}

		if (!stopping)
			continue;
		/*
		 * Re-check under the lock: a worker may have prepended a final
		 * batch between our unlock and now. Only exit once stopping is
		 * set AND nothing is left to drain.
		 */
		pthread_mutex_lock(&st->lock);
		bool done = !st->incoming;
		pthread_mutex_unlock(&st->lock);
		if (done)
			return NULL;
	}
}

/*
 * Stop and join the flight-recorder thread, leaving the PQ and its chunks
 * intact for a consumer (merge). Idempotent: a no-op when `fr` is NULL or the
 * thread was already joined.
 */
static void fr_join(void)
{
	if (!fr || fr->joined)
		return;

	pthread_mutex_lock(&fr->lock);
	fr->stopping = true;
	pthread_cond_signal(&fr->cond);
	pthread_mutex_unlock(&fr->lock);
	pthread_join(fr->thread, NULL);
	fr->joined = true;
}

/*
 * Stop the flight-recorder thread, drain and free the PQ, and free `fr`.
 * Idempotent: a no-op when `fr` is NULL, so it's safe on every cleanup path.
 */
static void fr_teardown(void)
{
	if (!fr)
		return;

	fr_join();

	/*
	 * Free whatever chunks merge didn't consume (e.g. the error path, where
	 * merge never ran). On the success path merge has already drained the PQ
	 * to empty, so this loop is a no-op. Chunk files stay on disk; the error
	 * path deletes the whole workdir afterwards unless keep-workdir is set.
	 */
	while (!wppq_empty(fr->pq)) {
		struct fr_chunk *c = wppq_pop(fr->pq);

		free(c->path);
		free(c);
	}
	wppq_free(fr->pq);
	pthread_cond_destroy(&fr->cond);
	pthread_mutex_destroy(&fr->lock);
	free(fr->workdir);
	free(fr);
	fr = NULL;
}

/* Receive events from the ring buffer. */
static int handle_rb_event(void *ctx, void *data, size_t size)
{
	struct wprof_event *e = data;
	struct worker_state *w = ctx;

	if (exiting)
		return -EINTR;

	if (env.sess_end_ts && ts_after_or_at(e->ts, env.sess_end_ts)) {
		w->rb_ignored_cnt++;
		w->rb_ignored_sz += size;
		return 0;
	}

	if (fwrite(data, size, 1, w->dump) != 1) {
		int err = -errno;

		eprintf("Failed to write raw data dump: %d\n", err);
		return err;
	}

	w->rb_handled_cnt++;
	w->rb_handled_sz += size;

	w->cur_chunk->byte_sz += size;
	w->cur_chunk->event_cnt++;
	w->cur_chunk->end_ts = ts_max(w->cur_chunk->end_ts, e->ts);

	if (!env.flightrec || w->cur_chunk->byte_sz < env.fr_chunk_size)
		return 0;

	/*
	 * Rotate: open a fresh current chunk and hand the just-completed one to
	 * the FR thread. The current chunk is never handed off, so each chunk
	 * has a single owner (this worker, or the FR thread) and is fclosed once.
	 */
	struct fr_chunk *old = w->cur_chunk;

	char chunk_path[PATH_MAX];
	snprintf(chunk_path, sizeof(chunk_path), "%s/bpf-rb.%03d.%d.chunk",
		 fr->workdir, old->worker_idx, old->seq + 1);

	struct fr_chunk *new = calloc(1, sizeof(*new));
	new->path = strdup(chunk_path);
	new->f = fopen_buffered(chunk_path, "w+");
	new->worker_idx = old->worker_idx;
	new->seq = old->seq + 1;
	if (!new->f) {
		int err = -errno;

		eprintf("Failed to create data dump at '%s': %d\n", chunk_path, err);
		free(new->path);
		free(new);
		return err;
	}

	/* Re-point to the new chunk BEFORE the old one becomes visible to the FR thread. */
	w->cur_chunk = new;
	w->dump = new->f;
	w->dump_path = new->path;

	pthread_mutex_lock(&fr->lock);
	old->next = fr->incoming;
	fr->incoming = old;
	pthread_cond_signal(&fr->cond);
	pthread_mutex_unlock(&fr->lock);

	return 0;
}

static void print_stats(const struct wprof_stats *s, int exit_code)
{
	double dur_s = env.duration_ns / 1000000000.0;
	u64 total_handled_cnt = 0, total_handled_sz = 0;
	u64 total_drops = 0, total_rescues = 0;

	if (!s || !env.emit_stats)
		goto skip_prog_stats;

	wprintf("BPF program stats:\n");

	int num_cpus = s->cpu_cnt;
	u64 total_run_cnt = wstat(s, WSTAT_PROG_RUN_CNT, 0);
	u64 total_run_ns = wstat(s, WSTAT_PROG_RUN_TIME_NS, 0);

	/*
	 * Per-program run_cnt/run_time come from the kernel's BPF stats subsystem
	 * (BPF_STATS_RUN_TIME), which wprof only enables when capturing with
	 * --stats. A zero total means it was off at capture time -- no real
	 * capture runs zero BPF programs -- so say so instead of printing a table
	 * of misleading zeros (e.g. when replaying a dump captured without --stats
	 * via --replay-info --stats).
	 */
	if (total_run_cnt == 0) {
		wprintf("\tNot captured. Re-run with --stats to collect BPF stats.\n");
		goto skip_prog_stats;
	}

	for (int i = 0; i < s->prog_cnt; i++) {
		u64 name_off = wstat(s, WSTAT_PROG_NAME, 1 + i);
		u64 run_cnt = wstat(s, WSTAT_PROG_RUN_CNT, 1 + i);
		u64 run_time_ns = wstat(s, WSTAT_PROG_RUN_TIME_NS, 1 + i);
		const char *name = wevent_str(env.data_hdr, name_off);

		wprintf("\t%s%-*s %8llu (%6.0lf/CPU/s) runs for total of %.3lfms (%.3lfms/CPU/s).\n",
			name,
			(int)max(1UL, 24 - strlen(name)), ":",
			run_cnt,
			run_cnt / num_cpus / dur_s,
			run_time_ns / 1000000.0,
			run_time_ns / 1000000.0 / num_cpus / dur_s);
	}

	wprintf("\t%-24s %8llu (%6.0lf/CPU/s) runs for total of %.3lfms (%.3lfms/CPU/s).\n",
		"TOTAL:", total_run_cnt,
		total_run_cnt / num_cpus / dur_s,
		total_run_ns / 1000000.0,
		total_run_ns / 1000000.0 / num_cpus / dur_s);

skip_prog_stats:
	if (!s)
		goto skip_rb_stats;

	total_handled_cnt = wstat(s, WSTAT_RB_HANDLED_CNT, 0);
	total_handled_sz = wstat(s, WSTAT_RB_HANDLED_SZ, 0);
	total_drops = wstat(s, WSTAT_RB_DROPS, 0);
	total_rescues = wstat(s, WSTAT_RB_RESCUES, 0);

	if (!env.emit_stats)
		goto skip_rb_stats;

	wprintf("Data procesing stats:\n");

	for (int i = 0; i < s->rb_cnt; i++) {
		u64 handled_cnt = wstat(s, WSTAT_RB_HANDLED_CNT, 1 + i);
		u64 handled_sz = wstat(s, WSTAT_RB_HANDLED_SZ, 1 + i);
		u64 drops = wstat(s, WSTAT_RB_DROPS, 1 + i);
		u64 rescues = wstat(s, WSTAT_RB_RESCUES, 1 + i);

		char rb_name[32];
		snprintf(rb_name, sizeof(rb_name), "RB #%d:", i);

		wprintf("\t%-8s %8llu (%.3lf%%) records (%.3lfMB, %.3lfMB/s) processed, %llu rescued (%.3lf%%), %llu dropped (%.3lf%%).\n",
			rb_name,
			handled_cnt, handled_cnt * 100.0 / (handled_cnt + drops),
			handled_sz / 1024.0 / 1024.0, handled_sz / 1024.0 / 1024.0 / dur_s,
			rescues, rescues * 100.0 / (handled_cnt + drops),
			drops, drops * 100.0 / (handled_cnt + drops));
	}
	wprintf("\t%-8s %8llu (%.3lf%%) records (%.3lfMB, %.3lfMB/s, %.3lfMB/RB/s) processed, %llu rescued (%.3lf%%), %llu dropped (%.3lf%%).\n",
		"TOTAL:",
		total_handled_cnt, total_handled_cnt * 100.0 / (total_handled_cnt + total_drops),
		total_handled_sz / 1024.0 / 1024.0, total_handled_sz / 1024.0 / 1024.0 / dur_s,
		total_handled_sz / 1024.0 / 1024.0 / dur_s / s->rb_cnt,
		total_rescues, total_rescues * 100.0 / (total_handled_cnt + total_drops),
		total_drops, total_drops * 100.0 / (total_handled_cnt + total_drops));

skip_rb_stats:
	if (!s || !env.emit_stats)
		goto skip_rusage;

	wprintf("Resource usage:\n");
	wprintf("\tCPU time (user/system, s):\t\t%.3lf/%.3lf\n",     wstat(s, WSTAT_RUSAGE_UTIME_US, 0) / 1000000.0,
								     wstat(s, WSTAT_RUSAGE_STIME_US, 0) / 1000000.0);
	wprintf("\tMemory (max RSS, MB):\t\t\t%.3lf\n",		     wstat(s, WSTAT_RUSAGE_MAXRSS_KB, 0) / 1024.0);
	wprintf("\tPage faults (maj/min, K)\t\t%.3lf/%.3lf\n",	     wstat(s, WSTAT_RUSAGE_MAJFLT, 0) / 1000.0,
								     wstat(s, WSTAT_RUSAGE_MINFLT, 0) / 1000.0);
	wprintf("\tBlock I/Os (K):\t\t\t\t%.3lf/%.3lf\n",	     wstat(s, WSTAT_RUSAGE_INBLOCK, 0) / 1000.0,
								     wstat(s, WSTAT_RUSAGE_OUBLOCK, 0) / 1000.0);
	wprintf("\tContext switches (vol/invol, K):\t%.3lf/%.3lf\n", wstat(s, WSTAT_RUSAGE_NVCSW, 0) / 1000.0,
								     wstat(s, WSTAT_RUSAGE_NIVCSW, 0) / 1000.0);

skip_rusage:
	if (!s)
		goto skip_error_diag;

	for (int i = 0; i < s->cuda_cnt; i++) {
		u64 state = wstat(s, WSTAT_CUDA_STATE, 1 + i);
		const char *name = wevent_str(env.data_hdr, wstat(s, WSTAT_CUDA_NAME, 1 + i));

		if (state == INJECTEE_IGNORED)
			continue;

		if (state != INJECTEE_INACTIVE) {
			eprintf("!!! CUDA %s encountered problem. Last state: %s\n", name, injectee_state_str(state));
			continue;
		}

		u64 drop_cnt = wstat(s, WSTAT_CUDA_DROP_CNT, 1 + i);
		u64 err_cnt = wstat(s, WSTAT_CUDA_ERR_CNT, 1 + i);
		if (drop_cnt + err_cnt > 0)
			eprintf("!!! CUDA %s: %llu records dropped, %llu errors.\n", name, drop_cnt, err_cnt);
		if (env.verbose || env.emit_stats) {
			eprintf("CUDA %s: %llu records (%llu ignored), %llu buffers, %.3lfMBs.\n",
				name,
				wstat(s, WSTAT_CUDA_REC_CNT, 1 + i),
				wstat(s, WSTAT_CUDA_IGNORE_CNT, 1 + i),
				wstat(s, WSTAT_CUDA_BUF_CNT, 1 + i),
				wstat(s, WSTAT_CUDA_DATA_SZ, 1 + i) / 1024.0 / 1024.0);
		}
	}

	for (int i = 0; i < s->py_cnt; i++) {
		u64 state = wstat(s, WSTAT_PYTRACE_STATE, 1 + i);
		const char *name = wevent_str(env.data_hdr, wstat(s, WSTAT_PYTRACE_NAME, 1 + i));

		if (state != INJECTEE_INACTIVE && state != INJECTEE_SHUTDOWN_TIMEOUT) {
			eprintf("!!! Python %s encountered problem. Last state: %s\n", name, injectee_state_str(state));
			continue;
		}
		if (env.verbose || env.emit_stats) {
			if (env.capture_pytorch == TRUE)
				eprintf("PyTorch %s: %llu events.\n", name, wstat(s, WSTAT_PYTORCH_EVENT_CNT, 1 + i));
			if (env.capture_pytrace == TRUE) {
				eprintf("PyTrace %s: %llu events, %llu code objects cached.\n",
					name,
					wstat(s, WSTAT_PYTRACE_EVENT_CNT, 1 + i),
					wstat(s, WSTAT_PYTRACE_CODE_CACHE_CNT, 1 + i));
			}
		}
	}

	u64 pystacks_attempted = wstat(s, WSTAT_PYSTACKS_ATTEMPTED, 0);
	u64 pystacks_found = wstat(s, WSTAT_PYSTACKS_FOUND, 0);
	if ((env.verbose || env.emit_stats) && pystacks_attempted > 0) {
		wprintf("PyStacks: %llu attempted, %llu found (%.2lf%%)\n",
			pystacks_attempted, pystacks_found,
			pystacks_found * 100.0 / pystacks_attempted);
	}

	u64 rb_misses = wstat(s, WSTAT_RB_MISSES, 0);
	if (rb_misses)
		eprintf("!!! Ringbuf fetch misses: %llu\n", rb_misses);

	if (total_drops) {
		for (int i = 0; i < s->cpu_cnt; i++) {
			u64 cpu_drops = wstat(s, WSTAT_RB_DROPS, 1 + s->rb_cnt + i);
			if (cpu_drops == 0)
				continue;

			u64 cpu_handled = wstat(s, WSTAT_RB_HANDLED_CNT, 1 + s->rb_cnt + i);
			u64 cpu_rescues = wstat(s, WSTAT_RB_RESCUES, 1 + s->rb_cnt + i);
			eprintf("!!! Drops (CPU #%d): %llu (%.3lf%% handled, %.3lf%% rescued, %.3lf%% dropped)\n",
				i, cpu_drops,
				cpu_handled * 100.0 / (cpu_handled + cpu_drops),
				cpu_rescues * 100.0 / (cpu_handled + cpu_drops),
				cpu_drops * 100.0 / (cpu_handled + cpu_drops));
		}
		for (int i = 0; i < s->rb_cnt; i++) {
			u64 rb_drops = wstat(s, WSTAT_RB_DROPS, 1 + i);
			if (rb_drops == 0)
				continue;

			u64 rb_hcnt = wstat(s, WSTAT_RB_HANDLED_CNT, 1 + i);
			u64 rb_rescues = wstat(s, WSTAT_RB_RESCUES, 1 + i);
			eprintf("!!! Drops (RB #%d): %llu (%.3lf%% handled, %.3lf%% rescued, %.3lf%% dropped)\n",
				i, rb_drops,
				rb_hcnt * 100.0 / (rb_hcnt + rb_drops),
				rb_rescues * 100.0 / (rb_hcnt + rb_drops),
				rb_drops * 100.0 / (rb_hcnt + rb_drops));
		}
		eprintf("!!! Drops (TOTAL): %llu (%.3lf%% handled, %.3lf%% rescued, %.3lf%% dropped)\n",
			total_drops,
			total_handled_cnt * 100.0 / (total_handled_cnt + total_drops),
			total_rescues * 100.0 / (total_handled_cnt + total_drops),
			total_drops * 100.0 / (total_handled_cnt + total_drops));
	}

	u64 task_drops = wstat(s, WSTAT_TASK_STATE_DROPS, 0);
	u64 task_fallbacks = wstat(s, WSTAT_TASK_STORAGE_FALLBACKS, 0);
	u64 req_drops = wstat(s, WSTAT_REQ_STATE_DROPS, 0);

	if (env.emit_stats) {
		if (task_drops || task_fallbacks) {
			eprintf("%sTask state drops: %llu, storage fallbacks: %llu\n",
				task_drops ? "!!! " : "", task_drops, task_fallbacks);
		}
	} else if (task_drops) {
		eprintf("!!! Task state drops: %llu\n", task_drops);
	}
	if (req_drops)
		eprintf("!!! Request state drops: %llu\n", req_drops);

	for (int i = 0; i < s->prog_cnt; i++) {
		u64 rec_misses = wstat(s, WSTAT_PROG_RECURSION_MISSES, 1 + i);
		if (rec_misses) {
			const char *name = wevent_str(env.data_hdr, wstat(s, WSTAT_PROG_NAME, 1 + i));
			eprintf("!!! %s: %llu recursion misses!\n", name, rec_misses);
		}
	}

	double *pmu_active_frac = (double *)wstats(s, WSTAT_PMU_ACTIVE_FRAC, NULL);
	for (int i = 0; pmu_active_frac && i < s->pmu_cnt; i++) {
		double active_frac = pmu_active_frac[1 + i];

		/* 0 = not captured, 1.0 = always running; anything else means multiplexed */
		if (active_frac == 0.0 || active_frac == 1.0)
			continue;

		struct wevent_pmu_def *def = wevent_pmu_def(env.data_hdr, i);
		const char *name = wevent_str(env.data_hdr, def->name_stroff);
		eprintf("!!! PMU counter '%s' was multiplexed by kernel (active %.2f%%), values can be unreliable!\n",
			name, 100.0 * active_frac);
	}

skip_error_diag:
	return;
}

struct timer_plan {
	int cpu;
	u64 delay_ns;
};

static int timer_plan_cmp(const void *a, const void *b)
{
	const struct timer_plan *x = a, *y = b;

	if (x->delay_ns != y->delay_ns)
		return x->delay_ns < y->delay_ns ? -1 : 1;

	return x->cpu - y->cpu;
}

static int setup_perf_timer_ticks(struct bpf_state *st, int num_cpus)
{
	struct perf_event_attr attr;

	st->perf_timer_fds = calloc(num_cpus, sizeof(int));
	for (int i = 0; i < num_cpus; i++)
		st->perf_timer_fds[i] = -1;

	/* determine randomized spread-out "plan" for attaching to timers to
	 * avoid too aligned (in time) triggerings across all CPUs
	 */
	u64 timer_start_ts = ktime_now_ns();
	struct timer_plan *timer_plan = calloc(num_cpus, sizeof(*timer_plan));

	for (int cpu = 0; cpu < num_cpus; cpu++) {
		timer_plan[cpu].cpu = cpu;
		timer_plan[cpu].delay_ns = 1000000000ULL / env.timer_freq_hz * ((double)rand() / RAND_MAX);
	}
	qsort(timer_plan, num_cpus, sizeof(*timer_plan), timer_plan_cmp);

	for (int i = 0; i < num_cpus; i++) {
		int cpu = timer_plan[i].cpu;

		/* skip offline/not present CPUs */
		if (cpu >= st->num_online_cpus || !st->online_mask[cpu])
			continue;

		/* timer perf event */
		memset(&attr, 0, sizeof(attr));
		attr.size = sizeof(attr);
		attr.type = PERF_TYPE_SOFTWARE;
		attr.config = PERF_COUNT_SW_CPU_CLOCK;
		attr.sample_freq = env.timer_freq_hz;
		attr.freq = 1;

		u64 now = ktime_now_ns();
		if (now < timer_start_ts + timer_plan[i].delay_ns)
			usleep((timer_start_ts + timer_plan[i].delay_ns - now) / 1000);

		int pefd = sys_perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (pefd < 0) {
			int err = -errno;
			eprintf("Failed to set up performance monitor on CPU %d: %d\n", cpu, err);
			return err;
		}
		st->perf_timer_fds[cpu] = pefd;
	}

	return 0;
}

static int setup_perf_counters(struct bpf_state *st, int num_cpus)
{
	struct perf_event_attr attr;
	bool warned[env.pmu_real_cnt] = {};
	int err;

	st->perf_counter_fds = calloc(st->perf_counter_fd_cnt, sizeof(int));
	for (int i = 0; i < num_cpus; i++) {
		for (int j = 0; j < env.pmu_real_cnt; j++)
			st->perf_counter_fds[i * env.pmu_real_cnt + j] = -1;
	}

	for (int cpu = 0; cpu < num_cpus; cpu++) {
		/* set up requested perf counters */
		for (int j = 0; j < env.pmu_real_cnt; j++) {
			const struct pmu_event *ev = &env.pmu_reals[j];
			int pe_idx = cpu * env.pmu_real_cnt + j;

			memset(&attr, 0, sizeof(attr));
			attr.size = sizeof(attr);
			attr.type = ev->perf_type;
			attr.config = ev->config;
			attr.config1 = ev->config1;
			attr.config2 = ev->config2;
			/*
			 * So we can detect multiplexing at session end by comparing
			 * time_running against time_enabled per event.
			 */
			attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;
			/*
			 * A -Spmu= event that reuses this counter turns it into the sampling
			 * source: it overflows at the requested rate and the BPF program
			 * attaches to its fd (see attach_bpf). A sampling perf event still
			 * counts, so the same fd doubles as the --pmu counter.
			 */
			if (ev->sampling_period) {
				attr.sample_period = ev->sampling_period;
				attr.freq = 0;
			} else if (ev->sampling_freq) {
				attr.sample_freq = ev->sampling_freq;
				attr.freq = 1;
			}

			int pefd = sys_perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
			if (pefd < 0) {
				/* warn once per counter, not once per (online) CPU */
				if (!warned[j]) {
					eprintf("WARNING: failed to create PMU counter '%s': perf_event_open() failed with %s, skipping...\n",
						ev->name, errstr(-errno));
					warned[j] = true;
				}
			} else {
				st->perf_counter_fds[pe_idx] = pefd;
				err = bpf_map__update_elem(st->skel->maps.perf_cntrs,
							   &pe_idx, sizeof(pe_idx),
							   &pefd, sizeof(pefd), 0);
				if (err) {
					eprintf("Failed to set up %s PMU on CPU#%d for BPF: %s\n", ev->name, cpu, errstr(err));
					return err;
				}
				err = ioctl(pefd, PERF_EVENT_IOC_ENABLE, 0);
				if (err) {
					err = -errno;
					eprintf("Failed to enable %s PMU on CPU#%d: %s\n", ev->name, cpu, errstr(err));
					return err;
				}
			}
		}
	}

	return 0;
}

static int setup_pmu_events(struct bpf_state *st, int num_cpus)
{
	struct perf_event_attr attr;

	st->pmu_event_fd_cnt = env.pmu_event_cnt * num_cpus;
	st->pmu_event_fds = calloc(st->pmu_event_fd_cnt, sizeof(int));
	for (int i = 0; i < st->pmu_event_fd_cnt; i++)
		st->pmu_event_fds[i] = -1;

	for (int s = 0; s < env.pmu_event_cnt; s++) {
		const struct pmu_event *ev = &env.pmu_events[s];

		/* events reusing a --pmu real are sampled off that real's fd in setup_perf_counters() */
		if (ev->reuse_pmu_idx >= 0)
			continue;

		for (int cpu = 0; cpu < num_cpus; cpu++) {
			/* skip offline/not present CPUs */
			if (cpu >= st->num_online_cpus || !st->online_mask[cpu])
				continue;

			memset(&attr, 0, sizeof(attr));
			attr.size = sizeof(attr);
			attr.type = ev->perf_type;
			attr.config = ev->config;
			attr.config1 = ev->config1;
			attr.config2 = ev->config2;
			if (ev->sampling_period) {
				attr.sample_period = ev->sampling_period;
				attr.freq = 0;
			} else {
				attr.sample_freq = ev->sampling_freq;
				attr.freq = 1;
			}

			int pefd = sys_perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
			if (pefd < 0) {
				int err = -errno;
				eprintf("Failed to set up PMU sampling event '%s' on CPU %d: %s\n", ev->name, cpu, errstr(err));
				return err;
			}
			st->pmu_event_fds[s * num_cpus + cpu] = pefd;
		}
	}

	return 0;
}

static int setup_bpf(struct bpf_state *st, struct worker_state *workers, int num_cpus, int workdir_fd)
{
	const char *online_cpus_file = "/sys/devices/system/cpu/online";
	struct wprof_bpf *skel;
	int i, err = 0;

#if !defined(__x86_64__) && !defined(__aarch64__)
	if (env.capture_ipis) {
		eprintf("IPI capture is supported only on x86-64 and arm64 architectures!\n");
		return -EOPNOTSUPP;
	}
#endif

	libbpf_set_print(libbpf_print_fn);

	err = parse_cpu_mask(online_cpus_file, &st->online_mask, &st->num_online_cpus);
	if (err) {
		eprintf("Failed to get online CPU numbers: %d\n", err);
		return -EINVAL;
	}

	env.skel = st->skel = skel = wprof_bpf__open();
	if (!skel) {
		err = -errno;
		eprintf("Failed to open and load BPF skeleton: %d\n", err);
		return err;
	}

	if (env.capture_ipis) {
		bpf_program__set_autoload(skel->progs.wprof_ipi_send_cpu, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_send_mask, true);
#if defined(__x86_64__)
		bpf_program__set_autoload(skel->progs.wprof_ipi_single_entry, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_single_exit, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_multi_entry, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_multi_exit, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_resched_entry, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_resched_exit, true);
#elif defined(__aarch64__)
		bpf_program__set_autoload(skel->progs.wprof_ipi_entry, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_exit, true);
#endif
	}

	if (env.capture_softirq) {
		bpf_program__set_autoload(skel->progs.wprof_softirq_entry, true);
		bpf_program__set_autoload(skel->progs.wprof_softirq_exit, true);
	}
	if (env.capture_hardirq) {
		bpf_program__set_autoload(skel->progs.wprof_hardirq_entry, true);
		bpf_program__set_autoload(skel->progs.wprof_hardirq_exit, true);
	}

	if (env.capture_sched)
		bpf_program__set_autoload(skel->progs.wprof_task_switch, true);

	if (env.capture_wakeup) {
		bpf_program__set_autoload(skel->progs.wprof_task_waking, true);
		bpf_program__set_autoload(skel->progs.wprof_task_wakeup_new, true);
	}

	/*
	 * Task lifetime events. wprof_task_free stays always-loaded because it also
	 * frees the per-task task_states entry; it only emits its event when enabled.
	 */
	if (env.capture_task_life) {
		bpf_program__set_autoload(skel->progs.wprof_task_rename, true);
		bpf_program__set_autoload(skel->progs.wprof_task_fork, true);
		bpf_program__set_autoload(skel->progs.wprof_task_exec, true);
		bpf_program__set_autoload(skel->progs.wprof_task_exit, true);
	}

	if (env.capture_wq) {
		bpf_program__set_autoload(skel->progs.wprof_wq_exec_start, true);
		bpf_program__set_autoload(skel->progs.wprof_wq_exec_end, true);
	}

	if (env.req_pid_cnt > 0 || env.req_path_cnt > 0 || env.req_global_discovery) {
		err = setup_req_tracking_discovery();
		if (err) {
			eprintf("Request tracking discovery step failed: %d\n", err);
			return err;
		}
	}

	/*
	 * task_states is the per-task state map. With task-local storage on it only
	 * backs rare allocation-failure fallbacks (e.g. hard/soft-irq context) so it
	 * can stay small; without storage it is the sole backend and needs the full
	 * size. Either default is overridable; resolve before its first use.
	 */
	if (env.task_state_sz < 0)
		env.task_state_sz = env.no_task_storage ? DEFAULT_TASK_STATE_SZ : TASK_STATE_FALLBACK_SZ;

	if (env.req_binaries) {
		bpf_program__set_autoload(skel->progs.wprof_req_ctx, true);
		bpf_program__set_autoload(skel->progs.wprof_req_task_enqueue, true);
		bpf_program__set_autoload(skel->progs.wprof_req_task_dequeue, true);
		bpf_program__set_autoload(skel->progs.wprof_req_task_stats, true);
		bpf_map__set_max_entries(skel->maps.req_states, max(16 * 1024, env.task_state_sz));
	} else {
		bpf_map__set_autocreate(skel->maps.req_states, false);
		env.capture_requests = false;
	}

	bool want_cuda = (env.cuda_pid_cnt > 0 || env.cuda_discovery);
	bool want_python = ((env.capture_pytrace == TRUE || env.capture_pytorch == TRUE) &&
			    (env.pytrace_pid_cnt > 0 || env.pytorch_pid_cnt > 0 ||
			     env.pytrace_discovery || env.pytorch_discovery));

	if (want_cuda || want_python) {
		err = injmgr_setup(workdir_fd);
		if (err) {
			eprintf("Trace injection setup failed: %d\n", err);
			return err;
		}
		if (want_cuda && (env.requested_stack_traces & ST_CUDA))
			bpf_program__set_autoload(skel->progs.wprof_cuda_call, true);
	}

	/*
	 * Expand `-p nv-smi` / `-P nv-smi` into concrete PIDs from nvidia-smi.
	 * Done here (record-mode setup) so the resolved PIDs flow through the
	 * normal allow/deny filter path (BPF maps + persisted WEXTRA filters);
	 * replay restores those concrete PIDs, so no replay-side handling needed.
	 */
	if (env.allow_pids_nv_smi || env.deny_pids_nv_smi) {
		ensure_nv_smi_pids();
		for (int i = 0; i < env.nv_smi_pid_cnt; i++) {
			if (env.allow_pids_nv_smi &&
			    (err = append_int(&env.allow_pids, &env.allow_pid_cnt, env.nv_smi_pids[i])))
				return err;
			if (env.deny_pids_nv_smi &&
			    (err = append_int(&env.deny_pids, &env.deny_pid_cnt, env.nv_smi_pids[i])))
				return err;
		}
	}

	if (env.capture_scx) {
		struct btf *vmlinux_btf = load_vmlinux_btf();

		if (btf__find_by_name_kind(vmlinux_btf, "scx_bpf_dsq_insert", BTF_KIND_FUNC) < 0) {
			bpf_program__set_autoload(skel->progs.wprof_dispatch, true);
		} else {
			bpf_program__set_autoload(skel->progs.wprof_dsq_insert, true);
		}
		if (btf__find_by_name_kind(vmlinux_btf, "scx_bpf_dsq_insert_vtime", BTF_KIND_FUNC) < 0) {
			bpf_program__set_autoload(skel->progs.wprof_dispatch_vtime, true);
		} else {
			bpf_program__set_autoload(skel->progs.wprof_dsq_insert_vtime, true);
		}
		if (btf__find_by_name_kind(vmlinux_btf, "scx_bpf_dsq_move", BTF_KIND_FUNC) < 0) {
			bpf_program__set_autoload(skel->progs.wprof_dispatch_from_dsq, true);
		} else {
			bpf_program__set_autoload(skel->progs.wprof_dsq_move, true);
		}
		if (btf__find_by_name_kind(vmlinux_btf, "scx_bpf_dsq_move_vtime", BTF_KIND_FUNC) < 0) {
			bpf_program__set_autoload(skel->progs.wprof_dispatch_vtime_from_dsq, true);
		} else {
			bpf_program__set_autoload(skel->progs.wprof_dsq_move_vtime, true);
		}

		/*
		 * Try to find scx_layered's task_ctxs map for reliable layer_id.
		 * If found, we reuse its fd so our BPF code can look up layer_id
		 * directly from scx_layered's task-local storage.
		 */
		u32 next_id = 0;
		bool found = false;

		while (true) {
			err = bpf_map_get_next_id(next_id, &next_id);
			if (err == -ENOENT)
				break;
			if (err < 0) {
				eprintf("Failed to iterate BPF maps: %d\n", err);
				return err;
			}

			int map_fd = bpf_map_get_fd_by_id(next_id);
			if (map_fd == -ENOENT)
				continue;
			if (map_fd < 0) {
				eprintf("Failed to fetch map FD for map #%d: %d\n", next_id, map_fd);
				continue;
			}

			struct bpf_map_info info;
			u32 info_len = sizeof(info);

			memset(&info, 0, sizeof(info));
			err = bpf_obj_get_info_by_fd(map_fd, &info, &info_len);
			if (err) {
				eprintf("Failed to fetch map info for map #%d: %d\n", next_id, err);
				close(map_fd);
				continue;
			}

			if (strcmp(info.name, "task_ctxs") != 0) {
				close(map_fd);
				continue;
			}

			if (found) {
				close(map_fd);
				eprintf("Found multiple 'task_ctxs' BPF maps, unsure which one to use!\n");
				return -EINVAL;
			}

			err = bpf_map__reuse_fd(skel->maps.scx_task_ctxs, map_fd);
			close(map_fd);
			if (err) {
				eprintf("Failed to reuse map #%d ('%s'): %d\n",
					next_id, info.name, err);
				continue;
			}
			found = true;
		}

		if (!found)
			eprintf("WARNING: scx_layered's 'task_ctxs' map not found; layer_id will not be available\n");
		else
			skel->rodata->capture_scx_layer_id = true;
	}
	bpf_map__set_autocreate(skel->maps.scx_task_ctxs, skel->rodata->capture_scx_layer_id);

	skel->rodata->capture_scx = env.capture_scx == TRUE;
	skel->rodata->capture_task_life = env.capture_task_life == TRUE;

	skel->rodata->rb_cnt = env.ringbuf_cnt;
	bpf_map__set_max_entries(skel->maps.rbs, env.ringbuf_cnt);
	bpf_map__set_max_entries(skel->maps.task_states, env.task_state_sz);

	/* Per-task state uses BPF task-local storage by default; --debug=no-task-storage opts out to the hash. */
	if (env.no_task_storage) {
		skel->rodata->use_task_storage = false;
		bpf_map__set_autocreate(skel->maps.task_states_storage, false);
	}

	/* FILTERING */
	struct {
		enum wprof_filt_mode filt_mode;
		const char *name;
		int cnt;
		int *ints;
		struct bpf_map *map;
		int **mmap;
		int *skel_cnt;
	} int_filters[] = {
		{
			FILT_ALLOW_PID, "PID allowlist",
			env.allow_pid_cnt, env.allow_pids,
			skel->maps.data_allow_pids, (int **)&skel->data_allow_pids,
			&skel->rodata->allow_pid_cnt,
		},
		{
			FILT_DENY_PID, "PID denylist",
			env.deny_pid_cnt, env.deny_pids,
			skel->maps.data_deny_pids, (int **)&skel->data_deny_pids,
			&skel->rodata->deny_pid_cnt,
		},
		{
			FILT_ALLOW_TID, "TID allowlist",
			env.allow_tid_cnt, env.allow_tids,
			skel->maps.data_allow_tids, (int **)&skel->data_allow_tids,
			&skel->rodata->allow_tid_cnt,
		},
		{
			FILT_DENY_TID, "TID denylist",
			env.deny_tid_cnt, env.deny_tids,
			skel->maps.data_deny_tids, (int **)&skel->data_deny_tids,
			&skel->rodata->deny_tid_cnt,
		},
	};
	for (int i = 0; i < ARRAY_SIZE(int_filters); i++) {
		const typeof(int_filters[0]) *f = &int_filters[i];
		size_t _sz;

		if (f->cnt == 0)
			continue;

		skel->rodata->filt_mode |= f->filt_mode;
		*f->skel_cnt = f->cnt;
		if ((err = bpf_map__set_value_size(f->map, f->cnt * sizeof(int)))) {
			eprintf("Failed to size BPF-side %s: %d\n", f->name, err);
			return err;
		}
		*f->mmap = bpf_map__initial_value(f->map, &_sz);
		for (int i = 0; i < f->cnt; i++)
			(*f->mmap)[i] = f->ints[i];
	}

	struct {
		enum wprof_filt_mode filt_mode;
		const char *name;
		int cnt;
		char **globs;
		struct bpf_map *map;
		struct glob_str **mmap;
		int *skel_cnt;
	} glob_filters[] = {
		{
			FILT_ALLOW_PNAME, "process name allowlist",
			env.allow_pname_cnt, env.allow_pnames,
			skel->maps.data_allow_pnames, (struct glob_str **)&skel->data_allow_pnames,
			&skel->rodata->allow_pname_cnt,
		},
		{
			FILT_DENY_PNAME, "process name denylist",
			env.deny_pname_cnt, env.deny_pnames,
			skel->maps.data_deny_pnames, (struct glob_str **)&skel->data_deny_pnames,
			&skel->rodata->deny_pname_cnt,
		},
		{
			FILT_ALLOW_TNAME, "thread name allowlist",
			env.allow_tname_cnt, env.allow_tnames,
			skel->maps.data_allow_tnames, (struct glob_str **)&skel->data_allow_tnames,
			&skel->rodata->allow_tname_cnt,
		},
		{
			FILT_DENY_TNAME, "thread name denylist",
			env.deny_tname_cnt, env.deny_tnames,
			skel->maps.data_deny_tnames, (struct glob_str **)&skel->data_deny_tnames,
			&skel->rodata->deny_tname_cnt,
		},
	};
	for (int i = 0; i < ARRAY_SIZE(glob_filters); i++) {
		const typeof(glob_filters[0]) *f = &glob_filters[i];
		size_t _sz;

		if (f->cnt == 0)
			continue;

		skel->rodata->filt_mode |= f->filt_mode;
		*f->skel_cnt = f->cnt;
		if ((err = bpf_map__set_value_size(f->map, f->cnt * sizeof(**f->mmap)))) {
			eprintf("Failed to size BPF-side %s: %d\n", f->name, err);
			return err;
		}
		*f->mmap = bpf_map__initial_value(f->map, &_sz);
		for (int i = 0; i < f->cnt; i++)
			wprof_strlcpy((*f->mmap)[i].pat, f->globs[i], sizeof(**f->mmap));
	}

	if (env.allow_idle)
		skel->rodata->filt_mode |= FILT_ALLOW_IDLE;
	if (env.deny_idle)
		skel->rodata->filt_mode |= FILT_DENY_IDLE;
	if (env.allow_kthread)
		skel->rodata->filt_mode |= FILT_ALLOW_KTHREAD;
	if (env.deny_kthread)
		skel->rodata->filt_mode |= FILT_DENY_KTHREAD;

	st->perf_counter_fd_cnt = num_cpus * env.pmu_real_cnt;
	skel->rodata->perf_ctr_cnt = env.pmu_real_cnt;
	bpf_map__set_max_entries(skel->maps.perf_cntrs, st->perf_counter_fd_cnt);

	if (env.requested_stack_traces & ST_TIMER)
		bpf_program__set_autoload(st->skel->progs.wprof_timer_tick, true);
	if (env.pmu_event_cnt > 0)
		bpf_program__set_autoload(st->skel->progs.wprof_pmu_event, true);
	skel->rodata->requested_stack_traces = env.requested_stack_traces;

	int cpu_cnt_pow2 = round_pow_of_2(num_cpus);
	skel->rodata->rb_cpu_map_mask = cpu_cnt_pow2 - 1;
	if ((err = bpf_map__set_value_size(skel->maps.data_rb_cpu_map, cpu_cnt_pow2 * sizeof(*skel->data_rb_cpu_map)))) {
		eprintf("Failed to size RB-to-CPU mapping: %d\n", err);
		return err;
	}
	size_t _sz;
	skel->data_rb_cpu_map = bpf_map__initial_value(skel->maps.data_rb_cpu_map, &_sz);

	err = setup_cpu_to_ringbuf_mapping(skel->data_rb_cpu_map->rb_cpu_map, env.ringbuf_cnt, num_cpus);
	if (err) {
		eprintf("Failed to setup RB-to-CPU mapping: %d\n", err);
		return err;
	}

	err = utrace_setup(skel);
	if (err) {
		eprintf("Failed to setup utrace: %d\n", err);
		return err;
	}

	 /* force RB notification when at least 2.0MB or 25% of ringbuf (whichever is less) is full */
	skel->rodata->rb_submit_threshold_bytes = min(2 * 1024 * 1024, env.ringbuf_sz / 4);

	if (env.emit_stats) {
		st->stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
		if (st->stats_fd < 0)
			eprintf("Failed to enable BPF run stats tracking: %d!\n", st->stats_fd);
	}

	err = bpf_object__prepare(skel->obj);
	if (err) {
		eprintf("Failed to prepare BPF skeleton: %d\n", err);
		return err;
	}

	/*
	 * BPF fentry/fexit templates needed to be autoloaded for prepare() to
	 * process them, but must not be loaded into the kernel — they are only
	 * used as clone sources. Unconditionally disable; harmless if unused.
	 */
	bpf_program__set_autoload(skel->progs.wprof_ut_bpf_entry, false);
	bpf_program__set_autoload(skel->progs.wprof_ut_bpf_exit, false);

	err = wprof_bpf__load(skel);
	if (err) {
		eprintf("Failed to load BPF skeleton: %d\n", err);
		return err;
	}

	st->rb_map_fds = calloc(env.ringbuf_cnt, sizeof(*st->rb_map_fds));
	u32 *rb_keys = calloc(env.ringbuf_cnt, sizeof(*rb_keys));
	for (int i = 0; i < env.ringbuf_cnt; i++) {
		int map_fd;

		map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, sfmt("wprof_rb_%d", i), 0, 0, env.ringbuf_sz, NULL);
		if (map_fd < 0) {
			eprintf("Failed to create BPF ringbuf #%d: %d\n", i, map_fd);
			return map_fd;
		}

		rb_keys[i] = i;
		st->rb_map_fds[i] = map_fd;
	}

	u32 rb_cnt = env.ringbuf_cnt;
	LIBBPF_OPTS(bpf_map_batch_opts, batch_opts);
	err = bpf_map_update_batch(bpf_map__fd(skel->maps.rbs), rb_keys, st->rb_map_fds,
				   &rb_cnt, &batch_opts);
	free(rb_keys);
	if (err < 0) {
		eprintf("Failed to set BPF ringbufs into ringbuf map-of-maps: %d\n", err);
		return err;
	}

	/* Prepare ring buffers to receive events from the BPF program. */
	st->rb_managers = calloc(env.ringbuf_cnt, sizeof(*st->rb_managers));
	for (i = 0; i < env.ringbuf_cnt; i++) {
		st->rb_managers[i] = ring_buffer__new(st->rb_map_fds[i], handle_rb_event, &workers[i], NULL);
		if (!st->rb_managers[i]) {
			eprintf("Failed to create ring buffer manager for ringbuf #%d: %d\n", i, err);
			err = -errno;
			return err;
		}
		workers[i].rb_manager = st->rb_managers[i];
	}

	if (env.requested_stack_traces & ST_TIMER) {
		err = setup_perf_timer_ticks(st, num_cpus);
		if (err) {
			eprintf("Failed to setup timer tick events: %d\n", err);
			return err;
		}
	}

	if (env.pmu_real_cnt) {
		err = setup_perf_counters(st, num_cpus);
		if (err) {
			eprintf("Failed to setup perf counters: %s\n", errstr(err));
			return err;
		}
	}

	if (env.pmu_event_cnt > 0) {
		err = setup_pmu_events(st, num_cpus);
		if (err) {
			eprintf("Failed to setup PMU sampling events: %s\n", errstr(err));
			return err;
		}
	}

	if (env.capture_pystacks) {
		err = pystacks_init(skel);
		if (err) {
			eprintf("Failed to initialize pystacks: %d\n", err);
			return err;
		}
	}

	return 0;
}

static atomic_int rb_workers_ready = 0;

static void *rb_worker(void *ctx)
{
	struct worker_state *worker = ctx;
	char name[32];

	snprintf(name, sizeof(name), "wprof_rb%03d", worker->worker_id);
	pthread_setname_np(pthread_self(), name);

	rb_workers_ready += 1;

	while (!exiting) {
		ring_buffer__poll(worker->rb_manager, 100);
	}

	return NULL;
}

int attach_usdt_probe(struct bpf_state *st, struct bpf_program *prog,
		      const char *binary_path, const char *binary_attach_path,
		      const char *usdt_provider, const char *usdt_name)
{
	struct bpf_link *link, **tmp;
	struct usdt_info info;

	if (elf_find_usdt(binary_attach_path, usdt_provider, usdt_name, &info)) {
		dlogf(USDT, 2, "No USDT %s:%s in %s (%s), skipping.\n",
		      usdt_provider, usdt_name, binary_path, binary_attach_path);
		return -ENOENT;
	}

	link = bpf_program__attach_usdt(prog, -1, binary_attach_path,
					usdt_provider, usdt_name, NULL);
	if (!link) {
		vprintf("Failed to attach USDT %s:%s to %s (%s): %d, skipping.\n",
		      usdt_provider, usdt_name, binary_path, binary_attach_path, -errno);
		return -ENOENT;
	}

	dlogf(USDT, 1, "Attached USDT %s:%s to %s (%s).\n",
	      usdt_provider, usdt_name, binary_path, binary_attach_path);

	tmp = realloc(st->links, (st->link_cnt + 1) * sizeof(struct bpf_link *));
	if (!tmp)
		return -ENOMEM;
	st->links = tmp;
	st->links[st->link_cnt] = link;
	st->link_cnt++;

	return 0;
}

static int attach_bpf(struct bpf_state *st, struct worker_state *workers, int num_cpus)
{
	int err = 0;

	st->links = calloc(num_cpus, sizeof(struct bpf_link *));
	for (int cpu = 0; cpu < num_cpus; cpu++) {
		if (!st->perf_timer_fds || st->perf_timer_fds[cpu] < 0)
			continue;

		struct bpf_link *link = bpf_program__attach_perf_event(st->skel->progs.wprof_timer_tick,
								       st->perf_timer_fds[cpu]);
		if (!link) {
			err = -errno;
			return err;
		}
		st->links[st->link_cnt++] = link;
	}

	/*
	 * Attach the PMU-event program to each sampled event's per-CPU overflow fd,
	 * passing the event's 0-based index as the bpf_cookie so emit can recover it.
	 * An event reusing a --pmu real overflows on that real's counter fd; a pure
	 * sampler overflows on its own fd. Their links go into the shared ->links.
	 */
	if (env.pmu_event_cnt > 0) {
		st->links = realloc(st->links, (st->link_cnt + env.pmu_event_cnt * num_cpus) * sizeof(*st->links));

		for (int pmu_idx = 0; pmu_idx < env.pmu_event_cnt; pmu_idx++) {
			LIBBPF_OPTS(bpf_perf_event_opts, popts, .bpf_cookie = pmu_idx);
			int reuse_pmu_idx = env.pmu_events[pmu_idx].reuse_pmu_idx;

			for (int cpu = 0; cpu < num_cpus; cpu++) {
				struct bpf_link *link;
				int fd = reuse_pmu_idx >= 0 ? st->perf_counter_fds[cpu * env.pmu_real_cnt + reuse_pmu_idx]
							    : st->pmu_event_fds[pmu_idx * num_cpus + cpu];
				if (fd < 0)
					continue;

				link = bpf_program__attach_perf_event_opts(st->skel->progs.wprof_pmu_event,
									   fd, &popts);
				if (!link) {
					err = -errno;
					return err;
				}
				st->links[st->link_cnt++] = link;
			}
		}
	}

	err = wprof_bpf__attach(st->skel);
	if (err) {
		eprintf("Failed to attach skeleton: %d\n", err);
		return err;
	}

	if (env.req_binaries) {
		err = attach_req_tracking_usdts(st);
		if (err) {
			eprintf("Failed to attach request tracking USDTs: %d\n", err);
			return err;
		}
	}

	if (env.utrace_cfg_cnt > 0) {
		err = utrace_attach(st, st->skel);
		if (err) {
			eprintf("Failed to attach utrace probes: %d\n", err);
			return err;
		}
	}

	/* spin up and ready ringbuf consumer threads */
	st->rb_threads = calloc(env.ringbuf_cnt, sizeof(*st->rb_threads));

	for (int i = 0; i < env.ringbuf_cnt; i++) {
		int err = pthread_create(&st->rb_threads[i], NULL, rb_worker, &workers[i]);
		if (err) {
			/* pthread_create returns the error positively, doesn't set errno */
			err = -err;
			eprintf("Failed to spawn ringbuf worker thread #%d: %d\n", i, err);
			return err;
		}
		st->rb_spawned++;
	}

	while (rb_workers_ready != env.ringbuf_cnt)
		sched_yield();

	return 0;
}

static int wait_bpf(struct bpf_state *st)
{
	for (int i = 0; i < st->rb_spawned; i++) {
		int err = pthread_join(st->rb_threads[i], NULL);
		if (err) {
			/* pthread_join returns the error positively, doesn't set errno */
			err = -err;
			eprintf("Failed to cleanly join ringbuf worker thread #%d: %d\n", i, err);
		}
	}

	return 0;
}

/*
 * Stop and join the ringbuf worker threads. Idempotent: a no-op if they were
 * never created or were already joined, so it's safe to call on every cleanup
 * path. Sets `exiting` so the workers leave their consume loops.
 */
static int stop_rb_workers(struct bpf_state *st)
{
	if (!st->rb_spawned)
		return 0;

	exiting = true;
	int err = wait_bpf(st);
	st->rb_spawned = 0;
	return err;
}

static void detach_bpf(struct bpf_state *st, int num_cpus)
{
	if (env.replay)
		return;
	if (st->detached)
		return;

	if (st->skel)
		wprof_bpf__detach(st->skel);
	if (st->stats_fd >= 0)
		close(st->stats_fd);
	if (st->links) {
		for (int i = 0; i < st->link_cnt; i++)
			bpf_link__destroy(st->links[i]);
		free(st->links);
	}
	if (st->link_fds) {
		for (int i = 0; i < st->link_fd_cnt; i++)
			close(st->link_fds[i]);
		free(st->link_fds);
	}
	if (st->perf_timer_fds) {
		for (int i = 0; i < num_cpus; i++) {
			if (st->perf_timer_fds[i] >= 0)
				close(st->perf_timer_fds[i]);
		}
		free(st->perf_timer_fds);
	}
	if (st->pmu_event_fds) {
		for (int i = 0; i < st->pmu_event_fd_cnt; i++) {
			if (st->pmu_event_fds[i] >= 0)
				close(st->pmu_event_fds[i]);
		}
		free(st->pmu_event_fds);
	}
	if (st->perf_counter_fds) {
		/*
		 * Disable, read, and close each PMU fd. time_enabled/time_running
		 * are accumulated per real PMU to compute active_frac, which is
		 * later persisted via WSTAT_PMU_ACTIVE_FRAC.
		 */
		for (int i = 0; i < env.pmu_real_cnt; i++) {
			u64 tot_enabled = 0, tot_running = 0;

			for (int cpu = 0; cpu < num_cpus; cpu++) {
				int pe_idx = cpu * env.pmu_real_cnt + i;
				int fd = st->perf_counter_fds[pe_idx];
				if (fd < 0)
					continue;

				(void)ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

				u64 buf[3] = {}; /* value, time_enabled, time_running */
				if (read(fd, buf, sizeof(buf)) == sizeof(buf)) {
					tot_enabled += buf[1];
					tot_running += buf[2];
				}

				close(fd);
			}

			if (tot_enabled == tot_running)
				env.pmu_reals[i].active_frac = 1.0;
			else if (tot_enabled == 0)
				env.pmu_reals[i].active_frac = 0.0;
			else
				env.pmu_reals[i].active_frac = tot_running / (double)tot_enabled;
		}
		free(st->perf_counter_fds);
	}

	st->detached = true;
}

static void drain_bpf(struct bpf_state *st, int num_cpus)
{
	if (env.replay)
		return;
	if (st->drained)
		return;

	if (st->rb_managers) {
		for (int i = 0; i < env.ringbuf_cnt; i++) {
			if (st->rb_managers[i]) { /* drain ringbuf */
				exiting = false; /* ringbuf callback will stop early, if exiting is set */
				(void)ring_buffer__consume(st->rb_managers[i]);
			}
			ring_buffer__free(st->rb_managers[i]);
		}
	}

	if (st->rb_map_fds) {
		for (int i = 0; i < env.ringbuf_cnt; i++)
			if (st->rb_map_fds[i])
				close(st->rb_map_fds[i]);
	}

	st->drained = true;
}

static void cleanup_bpf(struct bpf_state *st)
{
	if (env.replay)
		return;

	wprof_bpf__destroy(st->skel);
	st->skel = NULL;

	free(st->online_mask);
	st->online_mask = NULL;
}

static void cleanup_workers(struct worker_state *workers, int worker_cnt)
{
	for (int i = 0; i < worker_cnt; i++) {
		struct worker_state *w = &workers[i];
		if (!w)
			return;

		wpb_writer_free(w->wpb_writer);

		if (w->trace && w->trace != stdout)
			fclose(w->trace);

		if (w->dump_mem && w->dump_mem != MAP_FAILED) {
			int err = munmap(w->dump_mem, w->dump_sz);
			if (err < 0) {
				err = -errno;
				eprintf("Failed to munmap() dump file '%s': %d\n", env.data_path, err);
			}
		}

		if (w->dump)
			fclose(w->dump);

		free(w->dump_path);
		free(w->req_allowlist.ids);

		/*
		 * cur_chunk->path aliases dump_path (freed above) and cur_chunk->f
		 * aliases dump (closed above), so only the chunk node itself is freed.
		 */
		free(w->cur_chunk);
		w->cur_chunk = NULL;

		w->dump_mem = NULL;
		w->dump = NULL;
	}
}


static int arm_timer_abs(int tfd, u64 abs_ktime_ns)
{
	struct itimerspec its = {
		.it_value = {
			.tv_sec  = abs_ktime_ns / 1000000000ULL,
			.tv_nsec = abs_ktime_ns % 1000000000ULL,
		},
	};
	return timerfd_settime(tfd, TFD_TIMER_ABSTIME, &its, NULL);
}

static void drain_fd(int fd)
{
	u64 v;
	(void)read(fd, &v, sizeof(v));
}

static int ctl_epoll_add(int epoll_fd, int fd, u32 tag)
{
	struct epoll_event ev = { .events = EPOLLIN, .data = { .u32 = tag } };
	return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
}

/* SESS_PREP: discovery, BPF load/attach, and tracee injection. */
static int do_prepare(struct bpf_state *bpf, struct worker_state *workers, int num_cpus, int workdir_fd)
{
	int err;
	/*
	 * Injected agents auto-retract if wprof dies without tearing them down.
	 * Size that timeout to cover the whole window from now to the planned
	 * session end (the wait for activation plus the run duration), with margin.
	 */
	u64 activate_at = env.sess_ctl.activate_target_ts ?: ktime_now_ns();
	long sess_timeout_ms = (s64)(activate_at + env.duration_ns - ktime_now_ns()) / 1000000 +
			       LIBWPROFINJ_SESSION_TIMEOUT_MS;

	err = setup_bpf(bpf, workers, num_cpus, workdir_fd);
	if (err) {
		eprintf("Failed to setup BPF parts: %d\n", err);
		return err;
	}

	err = attach_bpf(bpf, workers, num_cpus);
	if (err) {
		eprintf("Failed to attach BPF parts: %d\n", err);
		return err;
	}

	if (env.injectee_cnt > 0) {
		wprintf("Preparing trace injectees...\n");
		err = injmgr_prepare(workdir_fd, sess_timeout_ms);
		if (err) {
			eprintf("Failed to prepare trace injection sessions: %d\n", err);
			return err;
		}
	}

	return 0;
}

/* SESS_ARMED -> SESS_RECORDING: stamp t=0, open the session window, activate tracees. */
static int do_activate(struct bpf_state *bpf)
{
	int err;

	if (env.flightrec)
		wprintf("Running in flight recorder mode, press Ctrl-C to stop...\n");
	else
		wprintf("Running...\n");

	env.ktime_start_ns = ktime_now_ns();
	env.realtime_start_ns = ktime_to_realtime_ns(env.ktime_start_ns);
	env.sess_start_ts = env.ktime_start_ns;
	/* flightrec runs until stopped: leave the end at 0 (gate treats 0 as no-end) */
	env.sess_end_ts = env.flightrec ? 0 : env.ktime_start_ns + env.duration_ns;

	bpf->skel->bss->session_start_ts = env.sess_start_ts;
	bpf->skel->bss->session_end_ts = env.sess_end_ts;

	if (env.injectee_cnt > 0) {
		wprintf("Activating trace injectees...\n");
		err = injmgr_activate(env.sess_start_ts, env.sess_end_ts);
		if (err) {
			eprintf("Failed to activate trace injection sessions: %d\n", err);
			return err;
		}

		if (env.requested_stack_traces & ST_CUDA) {
			wprintf("Attaching CUDA USDTs...\n");
			err = injmgr_attach_usdts(bpf, bpf->skel->progs.wprof_cuda_call);
			if (err) {
				eprintf("Failed to attach CUDA tracking USDTs: %d\n", err);
				return err;
			}
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_state bpf_state = {};
	int num_cpus = 0, err = 0;
	int worker_cnt = 0;
	struct worker_state *workers = NULL;
	char workdir_name[PATH_MAX] = {};
	int workdir_fd = -1;

	env.actual_start_ts = ktime_now_ns();
	calibrate_ktime(); /* establish the ktime<->realtime mapping up front, so it is always available */
	elf_init(); /* set libelf's version up front so concurrent ELF parsing can't race on it */
	env.sess_ctl.sig_efd = -1; /* so an early SIGINT (before the eventfd exists) is a no-op */

	/* Parse command line arguments */
	setenv("ARGP_HELP_FMT", "opt-doc-col=35,rmargin=150", 0); /* widen default --help output */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) {
		err = -1;
		goto cleanup;
	}

	{
		int output_modes = !!(env.trace_path || env.json_path) + env.req_list + !!env.replay_info;
		if (output_modes > 1) {
			eprintf("Only one of -T, -J, --req-list, and --replay-info (-RI) can be specified at a time!\n");
			err = -EINVAL;
			goto cleanup;
		}
		if (env.replay && output_modes == 0) {
			eprintf("Replay mode (-R) requires an output: -T, -J, -I, or --req-list.\n");
			err = -EINVAL;
			goto cleanup;
		}
		if (env.req_list_cfg && !env.req_list) {
			if (env.req_list_cfg->sort_cnt > 0 || env.req_list_cfg->top_n > 0 || env.req_list_cfg->bottom_n > 0) {
				eprintf("--req-sort, --req-top-n, and --req-bottom-n require --req-list!\n");
				err = -EINVAL;
				goto cleanup;
			}
			if (env.req_list_cfg->filter_cnt > 0 && !env.trace_path && !env.json_path) {
				eprintf("--req-filter requires --req-list or -T/-J!\n");
				err = -EINVAL;
				goto cleanup;
			}
		}
	}

	if (env.flightrec && env.duration_ns) {
		eprintf("--flight-record (-F) is mutually exclusive with --dur (-d)!\n");
		err = -EINVAL;
		goto cleanup;
	}
	if (env.flightrec && (env.capture_cuda == TRUE ||
			      env.capture_pytrace == TRUE || env.capture_pytorch == TRUE)) {
		eprintf("--flight-record (-F) does not support injected-tracee features (cuda/py-trace/py-torch)!\n");
		err = -EINVAL;
		goto cleanup;
	}

	if (!env.replay && geteuid() != 0)
		eprintf("WARNING: wprof is not running as root, data capture will most probably FAIL due to insufficient permissions!\n");

	vprintf("wprof v%s (%s) (PID %d) started! [build-id %s, libwprofinj.so build-id %s]\n",
		WPROF_VERSION, WPROF_GIT_SHA, getpid(), elf_self_build_id(), wprof_injectee_build_id());

	env.num_cpus = num_cpus = libbpf_num_possible_cpus();
	if (num_cpus <= 0) {
		eprintf("Failed to get the number of processors\n");
		err = -1;
		goto cleanup;
	}

	signal(SIGINT, sig_term);
	signal(SIGTERM, sig_term);
	signal(SIGPIPE, sig_pipe);

	if (env.ringbuf_cnt == 0) {
		if (env.replay) {
			env.ringbuf_cnt = 1;
		} else {
			/* random heuristics: 8 CPUs per ringbuf, but at least 4 ringbuf */
			env.ringbuf_cnt = max(4, (num_cpus + 7) / 8);
		}
	}
	env.ringbuf_cnt = min(env.ringbuf_cnt, num_cpus);
	if (!env.replay) {
		vprintf("Using %zu BPF ring buffers.\n", env.ringbuf_cnt);
		/* -1 is only meaningful for the replay mode to autoload counters */
		if (env.pmu_real_cnt == -1)
			env.pmu_real_cnt = 0;
		if (env.pmu_deriv_cnt == -1)
			env.pmu_deriv_cnt = 0;
		if (env.pmu_unresolved_cnt == -1)
			env.pmu_unresolved_cnt = 0;
	}

	/* during replay or trace generation there is only one worker */
	worker_cnt = env.replay ? 1 : env.ringbuf_cnt;
	workers = calloc(worker_cnt, sizeof(*workers));
	for (int i = 0; i < worker_cnt; i++)
		workers[i].worker_id = i;
	workers[0].name_iids = (struct str_iid_domain) {
		.str_iids = hashmap__new(str_hash_fn, str_equal_fn, NULL),
		.next_str_iid = IID_FIXED_LAST_ID,
		.domain_desc = "dynamic",
	};

	if (env.replay) {
		/* nv-smi PID discovery needs a live nvidia-smi; numeric -p/-P still work in replay */
		if (env.allow_pids_nv_smi || env.deny_pids_nv_smi) {
			eprintf("-p/-P nv-smi only works in record mode (needs live nvidia-smi)!\n");
			err = -EINVAL;
			goto cleanup;
		}
		struct worker_state *worker = &workers[0];
		worker->dump = fopen(env.data_path, "r");
		if (!worker->dump) {
			err = -errno;
			eprintf("Failed to open data dump at '%s': %d\n", env.data_path, err);
			goto cleanup;
		}
		err = wprof_load_data_dump(worker);
		if (err) {
			eprintf("Failed to load data dump at '%s': %d\n", env.data_path, err);
			goto cleanup;
		}
		struct wprof_data_hdr *dump_hdr = worker->dump_hdr;
		const struct wprof_data_cfg *cfg = wprof_cfg(dump_hdr);
		env.data_hdr = dump_hdr;

		enum stack_trace_kind captured_stack_traces = 0;
		for (u64 i = 0; i < dump_hdr->extra_cnt; i++) {
			struct wprof_extra_param *ep = wevent_extra_param(dump_hdr, i);
			if (ep->kind == WEXTRA_STATS) {
				env.stats = wevent_blob(dump_hdr, ep->bloboff);
			} else if (ep->kind == WEXTRA_STACK_CAPTURE) {
				captured_stack_traces |= ep->arg;
				if (ep->arg == ST_TIMER)
					env.timer_freq_hz = ep->value;
			}
		}
		if (env.timer_freq_hz)
			env.timer_period_ns = 1000000000ULL / env.timer_freq_hz;

		/*
		 * Restore captured feature flags into env from the recorded config so
		 * replay reflects what was captured. Needed by both --replay-info (the
		 * per-tracee stats summary) and full replay; the full-replay path below
		 * additionally validates explicitly-requested features against the dump.
		 */
		for (int i = 0; i < ARRAY_SIZE(capture_features); i++) {
			const struct capture_feature *f = &capture_features[i];
			enum tristate *flag = (void *)&env + f->env_flag_off;

			if (*flag == UNSET)
				*flag = cfg_has_feat(cfg->capture_features, f);
		}

		/* handle all the ways to specify time range */
		if (env.duration_ns != 0 && (env.replay_start_offset_ns != 0 || env.replay_end_offset_ns != 0)) {
			eprintf("Time range start/end offsets and duration are mutually exlusive!\n");
			err = -EINVAL;
			goto cleanup;
		}
		/* if unspecified explicitly, derive time range from duration parameter */
		if (env.duration_ns != 0) {
			env.replay_start_offset_ns = 0;
			env.replay_end_offset_ns = env.duration_ns;
		}
		/* if unspecified explicitly, derive replay end from recorded duration */
		if (env.replay_start_offset_ns != 0 && env.replay_end_offset_ns == 0)
			env.replay_end_offset_ns = cfg->duration_ns;
		/* if neither duration nor time range is provided, use recorded time range */
		if (env.replay_start_offset_ns == 0 && env.replay_end_offset_ns == 0) {
			env.replay_start_offset_ns = 0;
			env.replay_end_offset_ns = cfg->duration_ns;
		}
		/* validate requested time range */
		if (env.replay_end_offset_ns <= env.replay_start_offset_ns) {
			eprintf("replay: invalid time range specified: [%.3lfms, %.3lfms)!\n",
				env.replay_start_offset_ns / 1000000.0, env.replay_end_offset_ns / 1000000.0);
			err = -EINVAL;
			goto cleanup;
		}
		if (env.replay_end_offset_ns > cfg->duration_ns) {
			eprintf("replay: requested time range [%.3lfms, %.3lfms) is larger than recorded time range [0ms, %.3lfms)!\n",
				env.replay_start_offset_ns / 1000000.0, env.replay_end_offset_ns / 1000000.0,
				cfg->duration_ns / 1000000.0);
			err = -EINVAL;
			goto cleanup;
		}

		/* setup original (replayed) time markers */
		env.sess_start_ts = cfg->ktime_start_ns + env.replay_start_offset_ns;
		env.sess_end_ts = cfg->ktime_start_ns + env.replay_end_offset_ns;
		set_ktime_off(cfg->ktime_start_ns, cfg->realtime_start_ns);
		env.duration_ns = env.replay_end_offset_ns - env.replay_start_offset_ns;

		if (env.replay_info) {
			const int w = 26;
			const double MB = 1024.0 * 1024.0;
			const double S = 1000000000.0;

			wprintf("Replay info:\n");
			wprintf("============\n");
			wprintf("%-*s%s\n", w, "Timestamp:", fmt_timestamp_ns(cfg->realtime_start_ns + env.replay_start_offset_ns));
			wprintf("%-*s%.3lfs\n", w, "Duration:", env.duration_ns / S);
			wprintf("%-*s%u.%u\n", w, "Data version:", dump_hdr->version_major, dump_hdr->version_minor);
			if (captured_stack_traces) {
				wprintf("%-*s\n", w, "Stack traces:");
				if (captured_stack_traces & ST_TIMER)
					wprintf("    --stacks timer=%dhz\n", env.timer_freq_hz);
				if (captured_stack_traces & ST_OFFCPU)
					wprintf("    --stacks offcpu\n");
				if (captured_stack_traces & ST_WAKER)
					wprintf("    --stacks waker\n");
				if (captured_stack_traces & ST_CUDA)
					wprintf("    --stacks cuda\n");
				if (captured_stack_traces & ST_REQ)
					wprintf("    --stacks req\n");
				if (captured_stack_traces & ST_UTRACE)
					wprintf("    --stacks utrace\n");
				if (captured_stack_traces & ST_PMU) {
					/* one -S pmu= sampled event per stored spec, with its rate */
					for (u64 i = 0; i < dump_hdr->extra_cnt; i++) {
						struct wprof_extra_param *e = wevent_extra_param(dump_hdr, i);
						if (e->kind == WEXTRA_STACK_CAPTURE && e->arg == ST_PMU)
							wprintf("    --stacks pmu=%s\n", wevent_str(dump_hdr, e->stroff));
					}
				}
			}
			if (dump_hdr->pmu_def_real_cnt + dump_hdr->pmu_def_deriv_cnt) {
				wprintf("%-*s\n", w, "PMU counters:");
				for (int i = 0; i < dump_hdr->pmu_def_real_cnt; i++) {
					struct wevent_pmu_def *def = wevent_pmu_def(dump_hdr, i);
					wprintf("    %s\n", wevent_str(dump_hdr, def->name_stroff));
				}
				for (int i = 0; i < dump_hdr->pmu_def_deriv_cnt; i++) {
					struct wevent_pmu_def *def = wevent_pmu_def(dump_hdr, dump_hdr->pmu_def_real_cnt + i);
					wprintf("    %s (derived)\n", wevent_str(dump_hdr, def->name_stroff));
				}
			}

			/* only show features whose captured state differs from the default */
			for (int i = 0; i < ARRAY_SIZE(capture_features); i++) {
				const struct capture_feature *f = &capture_features[i];
				bool captured = cfg_has_feat(cfg->capture_features, f);

				if (captured != (f->default_val == TRUE))
					wprintf("%-*s%s\n", w, f->header, captured ? "YES" : "NO");
			}

			if (dump_hdr->extra_cnt > 0) {
				bool has_extras = false, has_metadata = false;
				for (u64 i = 0; i < dump_hdr->extra_cnt; i++) {
					struct wprof_extra_param *e = wevent_extra_param(dump_hdr, i);
					if (e->kind == WEXTRA_METADATA) {
						has_metadata = true;
					} else if (e->kind == WEXTRA_STATS || e->kind == WEXTRA_STACK_CAPTURE) {
						/* excluded from extras printing */
					} else {
						has_extras = true;
					}
				}
				if (env.stats) {
					wprintf("%-*s\n", w, "Config:");
					wprintf("    %-*s%u\n", w - 4, "CPUs:", env.stats->cpu_cnt);
					wprintf("    %-*s%u x %uMB\n", w - 4, "Ringbufs:", env.stats->rb_cnt, env.stats->ringbuf_sz / 1024 / 1024);
					wprintf("    %-*s%u\n", w - 4, "Tasks capacity:", env.stats->task_state_sz);
				}
				if (has_metadata) {
					wprintf("%-*s\n", w, "Metadata:");
					for (u64 i = 0; i < dump_hdr->extra_cnt; i++) {
						struct wprof_extra_param *e = wevent_extra_param(dump_hdr, i);
						if (e->kind != WEXTRA_METADATA)
							continue;
						const char *kv = wevent_str(dump_hdr, e->stroff);
						const char *eq = strchr(kv, '=');
						if (eq)
							wprintf("    %.*s = %s\n", (int)(eq - kv), kv, eq + 1);
						else
							wprintf("    %s\n", kv);
					}
				}
				if (has_extras) {
					wprintf("%-*s\n", w, "Extras:");
					for (u64 i = 0; i < dump_hdr->extra_cnt; i++) {
						struct wprof_extra_param *e = wevent_extra_param(dump_hdr, i);
						if (e->kind == WEXTRA_METADATA || e->kind == WEXTRA_STATS ||
						    e->kind == WEXTRA_STACK_CAPTURE)
							continue;
						wprintf("    %s\n", extra_param_str(dump_hdr, e));
					}
				}
			}

			u64 kind_cnt[__EV_KIND_MAX] = {};
			u64 kind_sz[__EV_KIND_MAX] = {};
			u64 unknown_cnt = 0, unknown_sz = 0;
			u64 ev_cnt = 0, ev_sz = 0;
			struct wevent_record *rec;
			wevent_for_each_event(rec, dump_hdr, env.sess_start_ts, env.sess_end_ts) {
				u32 kind = rec->e->kind;

				if (kind < __EV_KIND_MAX) {
					kind_cnt[kind]++;
					kind_sz[kind] += rec->e->sz;
				} else {
					/* kind unknown to this build (e.g. newer data file) */
					unknown_cnt++;
					unknown_sz += rec->e->sz;
				}
				ev_cnt++;
				ev_sz += rec->e->sz;
			}
			wprintf("%-*s%.3lfMB total\n", w, "Data:", worker->dump_sz / MB);
			wprintf("    %-*s%.3lfMB (%llu entries)\n", w - 4, "Thread info:", dump_hdr->threads_sz / MB, dump_hdr->thread_cnt);

			u64 str_cnt = 0;
			for (const char *s = (void *)dump_hdr + dump_hdr->hdr_sz + dump_hdr->strs_off,
					*end = s + dump_hdr->strs_sz;
			     s < end; s++) {
				if (*s == '\0')
					str_cnt++;
			}
			wprintf("    %-*s%.3lfMB (%llu unique strings)\n", w - 4, "Strings:", dump_hdr->strs_sz / MB, str_cnt);
			if (dump_hdr->blobs_sz)
				wprintf("    %-*s%.3lfMB\n", w - 4, "Blobs:", dump_hdr->blobs_sz / MB);

			wprintf("    %-*s%.3lfMB (%llu entries)\n", w - 4, "Time index:", dump_hdr->tsidx_sz / MB, dump_hdr->tsidx_cnt);
			if (env.stats)
				wprintf("    %-*s%u bytes\n", w - 4, "Stats:", env.stats->sz);

			wprintf("    %-*s%.3lfMB (%llu records)\n", w - 4, "Events:", ev_sz / MB, ev_cnt);
			for (int i = 0; i < __EV_KIND_MAX; i++) {
				if (kind_cnt[i] == 0)
					continue;
				wprintf("        %-*s%.3lfMB (%llu records)\n", w - 8, wevent_kind_name(i), kind_sz[i] / MB, kind_cnt[i]);
			}
			if (unknown_cnt)
				wprintf("        %-*s%.3lfMB (%llu records)\n", w - 8, "UNKNOWN", unknown_sz / MB, unknown_cnt);
			if (captured_stack_traces) {
				const struct wstack_hdr *shdr = wstack_hdr(dump_hdr);
				wprintf("    %-*s%.3lfMB (%u unique stacks)\n", w - 4, "Stack traces:", dump_hdr->stacks_sz / MB, shdr->stack_cnt);
				wprintf("        %-*s%.3lfMB (%u entries)\n", w - 8, "Call stacks:", shdr->stack_cnt * sizeof(struct wstack_trace) / MB, shdr->stack_cnt);
				wprintf("        %-*s%.3lfMB (%u entries)\n", w - 8, "Frames:", shdr->frame_cnt * sizeof(struct wstack_frame) / MB, shdr->frame_cnt);
				u64 stack_str_cnt = 0;
				for (const char *s = wstack_str(dump_hdr, 0), *end = s + shdr->strs_sz; s < end; s++) {
					if (*s == '\0')
						stack_str_cnt++;
				}
				wprintf("        %-*s%.3lfMB (%llu unique strings)\n", w - 8, "Strings:", shdr->strs_sz / MB, stack_str_cnt);
			}
			if (dump_hdr->pmu_def_real_cnt + dump_hdr->pmu_def_deriv_cnt)
				wprintf("    %-*s%.3lfMB (%llu entries)\n", w - 4, "PMU data:", dump_hdr->pmu_vals_sz / MB, dump_hdr->pmu_val_cnt);

			/*
			 * If --stats is not set, we'll still print all the drops and recursion
			 * misses warnings, just like in normal recording mode.
			 */
			print_stats(env.stats, 0);

			goto cleanup;
		}

		if (env.emit_stats) {
			eprintf("replay: --stats should only be used with --replay-info!\n");
			err = -EINVAL;
			goto cleanup;
		}

		/* validate data capture config compatibility (flags already restored above) */
		for (int i = 0; i < ARRAY_SIZE(capture_features); i++) {
			const struct capture_feature *f = &capture_features[i];
			enum tristate *flag = (void *)&env + f->env_flag_off;
			bool cfg_flag = cfg_has_feat(cfg->capture_features, f);

			if (*flag == TRUE && !cfg_flag) {
				eprintf("replay: %s requested, but not recorded in data dump!\n", f->name);
				err = -EINVAL;
				goto cleanup;
			}
		}

		if (env.requested_stack_traces == ST_UNSET)
			env.requested_stack_traces = captured_stack_traces;
		if ((env.requested_stack_traces & captured_stack_traces) != env.requested_stack_traces) {
			eprintf("replay: some of requested kinds of stack traces were not captured (check --replay-info)!\n");
			err = -EINVAL;
			goto cleanup;
		}

		err = pmu_resolve_replay_defs(dump_hdr);
		if (err)
			goto cleanup;

		/*
		 * Restore persisted capture-time filters; a CLI process/thread
		 * filter overrides the recorded process/thread filters.
		 */
		bool cli_proc_thread_filter =
			env.allow_pid_cnt || env.deny_pid_cnt ||
			env.allow_tid_cnt || env.deny_tid_cnt ||
			env.allow_pname_cnt || env.deny_pname_cnt ||
			env.allow_tname_cnt || env.deny_tname_cnt;
		for (u64 i = 0; i < dump_hdr->extra_cnt; i++) {
			struct wprof_extra_param *ep = wevent_extra_param(dump_hdr, i);
			const char *val = ep->stroff ? wevent_str(dump_hdr, ep->stroff) : "";

			switch (ep->kind) {
			case WEXTRA_FILTER_PID_ALLOW:
				if (!cli_proc_thread_filter)
					err = append_num(&env.allow_pids, &env.allow_pid_cnt, val);
				break;
			case WEXTRA_FILTER_PID_DENY:
				if (!cli_proc_thread_filter)
					err = append_num(&env.deny_pids, &env.deny_pid_cnt, val);
				break;
			case WEXTRA_FILTER_TID_ALLOW:
				if (!cli_proc_thread_filter)
					err = append_num(&env.allow_tids, &env.allow_tid_cnt, val);
				break;
			case WEXTRA_FILTER_TID_DENY:
				if (!cli_proc_thread_filter)
					err = append_num(&env.deny_tids, &env.deny_tid_cnt, val);
				break;
			case WEXTRA_FILTER_PNAME_ALLOW:
				if (!cli_proc_thread_filter)
					err = append_str(&env.allow_pnames, &env.allow_pname_cnt, val);
				break;
			case WEXTRA_FILTER_PNAME_DENY:
				if (!cli_proc_thread_filter)
					err = append_str(&env.deny_pnames, &env.deny_pname_cnt, val);
				break;
			case WEXTRA_FILTER_TNAME_ALLOW:
				if (!cli_proc_thread_filter)
					err = append_str(&env.allow_tnames, &env.allow_tname_cnt, val);
				break;
			case WEXTRA_FILTER_TNAME_DENY:
				if (!cli_proc_thread_filter)
					err = append_str(&env.deny_tnames, &env.deny_tname_cnt, val);
				break;
			case WEXTRA_FILTER_IDLE_ALLOW:
				env.allow_idle = true;
				break;
			case WEXTRA_FILTER_IDLE_DENY:
				env.deny_idle = true;
				break;
			case WEXTRA_FILTER_KTHREAD_ALLOW:
				env.allow_kthread = true;
				break;
			case WEXTRA_FILTER_KTHREAD_DENY:
				env.deny_kthread = true;
				break;
			case WEXTRA_UTRACE_DEF:
				err = utrace_cfg_parse(val);
				break;
			/*
			 * Emit (-e) options keep their CLI value if set, otherwise
			 * inherit the persisted on/off value.
			 */
			case WEXTRA_EMIT_NUMA:
				env.emit_numa = env.emit_numa != UNSET ? env.emit_numa : ep->value;
				break;
			case WEXTRA_EMIT_TIDPID:
				env.emit_tidpid = env.emit_tidpid != UNSET ? env.emit_tidpid : ep->value;
				break;
			case WEXTRA_EMIT_TIMER_TICKS:
				env.emit_timer_ticks = env.emit_timer_ticks != UNSET ? env.emit_timer_ticks : ep->value;
				break;
			case WEXTRA_EMIT_SCHED:
				env.emit_sched_view = env.emit_sched_view != UNSET ? env.emit_sched_view : ep->value;
				break;
			case WEXTRA_EMIT_SCHED_EXTRAS:
				env.emit_sched_extras = env.emit_sched_extras != UNSET ? env.emit_sched_extras : ep->value;
				break;
			case WEXTRA_EMIT_PYSTACKS_ONLY:
				env.emit_pystacks_only = env.emit_pystacks_only != UNSET ? env.emit_pystacks_only : ep->value;
				break;
			case WEXTRA_EMIT_REQ_SPLIT:
				env.emit_req_split = env.emit_req_split != UNSET ? env.emit_req_split : ep->value;
				break;
			case WEXTRA_EMIT_REQ_EMBED:
				env.emit_req_embed = env.emit_req_embed != UNSET ? env.emit_req_embed : ep->value;
				break;
			case WEXTRA_EMIT_EMBED_STACKS:
				env.emit_embed_stacks = env.emit_embed_stacks != UNSET ? env.emit_embed_stacks : ep->value;
				break;
			case WEXTRA_METADATA:
			case WEXTRA_STATS:
			case WEXTRA_PMU:
			case WEXTRA_PREPARE_SPEC:
			case WEXTRA_ACTIVATE_SPEC:
			case WEXTRA_FR_SPEC:
			case WEXTRA_STACK_CAPTURE:
				/* capture-time only; informational at replay (see cmdline reconstruction) */
				break;
			default:
				eprintf("Unrecognized extra param kind %d in data file, skipping\n", ep->kind);
				break;
			}
			if (err)
				goto cleanup;
		}

		/* resolve emit (-e) options not set on the CLI or in the data dump */
		for (int i = 0; i < emit_feature_cnt; i++) {
			const struct emit_feature *f = &emit_features[i];
			enum tristate *flag = (void *)&env + f->env_flag_off;

			if (*flag == UNSET)
				*flag = f->default_val;
		}

		goto skip_data_collection;
	}

	if (env.replay_info) {
		eprintf("Replay information can be printed in replay mode only (specify -R)!\n");
		err = -EINVAL;
		goto cleanup;
	}
	if (env.replay_start_offset_ns || env.replay_end_offset_ns) {
		eprintf("Time range start/end offsets can only be specified in replay mode!\n");
		err = -EINVAL;
		goto cleanup;
	}
	if (env.pmu_unresolved_cnt > 0) {
		for (int i = 0; i < env.pmu_unresolved_cnt; i++)
			eprintf("Failed to resolve PMU counter '%s'!\n", env.pmu_unresolveds[i].name);
		err = -EINVAL;
		goto cleanup;
	}

	/* Init data capture settings defaults, if they were not set */
	if (env.timer_freq_hz == 0)
		env.timer_freq_hz = DEFAULT_TIMER_FREQ_HZ;
	env.timer_period_ns = 1000000000ULL / env.timer_freq_hz;
	if (!env.flightrec && env.duration_ns == 0)
		env.duration_ns = DEFAULT_DURATION_MS * 1000000ULL;
	if (env.flightrec) {
		/*
		 * Bare -F (neither limit given) uses the default time+size pair.
		 * Once any dimension is named, the unspecified one is left
		 * unlimited (0) rather than silently re-imposing a default.
		 */
		if (env.fr_keep_time_ns < 0 && env.fr_keep_size < 0) {
			env.fr_keep_time_ns = DEFAULT_FR_KEEP_TIME_NS;
			env.fr_keep_size = DEFAULT_FR_KEEP_SIZE;
		} else {
			if (env.fr_keep_time_ns < 0)
				env.fr_keep_time_ns = 0;
			if (env.fr_keep_size < 0)
				env.fr_keep_size = 0;
		}
	}

	/*
	 * Resolve -S pmu= sampling events (deferred so --pmu can be referenced by name)
	 * and apply the default rate. The bpf_cookie is the 0-based index here, which
	 * emit maps back to env.pmu_events[]. If the event matches an explicit --pmu
	 * real, point reuse_pmu_idx at it and move the sampling rate onto that real, so
	 * the real's single fd both samples and counts (no second hardware counter).
	 */
	for (int i = 0; i < env.pmu_event_cnt; i++) {
		struct pmu_event *s = &env.pmu_events[i];

		err = pmu_event_resolve(s, env.pmu_derivs, env.pmu_deriv_cnt);
		if (err)
			goto cleanup;
		if (s->sampling_freq == 0 && s->sampling_period == 0)
			s->sampling_freq = DEFAULT_PMU_EVENT_FREQ_HZ;

		s->reuse_pmu_idx = -1;
		for (int j = 0; j < env.pmu_real_cnt; j++) {
			struct pmu_event *r = &env.pmu_reals[j];

			if (r->perf_type != s->perf_type ||
			    r->config != s->config ||
			    r->config1 != s->config1 ||
			    r->config2 != s->config2)
				continue;

			if (r->sampling_freq || r->sampling_period) {
				eprintf("--pmu counter '%s' can't back two -S pmu= sampling events\n", r->name);
				err = -EINVAL;
				goto cleanup;
			}

			r->sampling_freq = s->sampling_freq;
			r->sampling_period = s->sampling_period;
			s->reuse_pmu_idx = j;
			break;
		}
	}

	/*
	 * Resolve --feature sched / wakeup and their dependencies. Off-CPU stacks,
	 * scx attribution, and the wakee side of a wakeup are all rendered off the
	 * context switch, so they constrain what is possible under -f no-sched.
	 * sched is resolved first because the rest keys off it.
	 */
	if (env.capture_sched == UNSET)
		env.capture_sched = DEFAULT_CAPTURE_SCHED;
	if (env.requested_stack_traces == ST_UNSET)
		env.requested_stack_traces = DEFAULT_REQUESTED_STACK_TRACES;
	/*
	 * wakeup tracking defaults on with sched and off under -f no-sched, but
	 * -Swaker forces it on (the waker stack is rendered standalone). An explicit
	 * -f wakeup without -Swaker under -f no-sched has nothing to render -> error.
	 */
	if (env.capture_wakeup == UNSET)
		env.capture_wakeup = env.capture_sched || (env.requested_stack_traces & ST_WAKER);

	if (!env.capture_sched && env.capture_scx == TRUE) {
		eprintf("-f scx requires context-switch tracking; drop -f no-sched!\n");
		err = -EINVAL;
		goto cleanup;
	}
	if (!env.capture_sched && (env.requested_stack_traces & ST_OFFCPU)) {
		eprintf("-Soffcpu requires context-switch tracking; drop -f no-sched!\n");
		err = -EINVAL;
		goto cleanup;
	}
	if (!env.capture_wakeup && (env.requested_stack_traces & ST_WAKER)) {
		eprintf("-Swaker requires wakeup tracking; drop -f no-wakeup!\n");
		err = -EINVAL;
		goto cleanup;
	}
	if (env.capture_wakeup && !env.capture_sched && !(env.requested_stack_traces & ST_WAKER)) {
		eprintf("-Swaker is required when -f wakeup is requested explicitly!\n");
		err = -EINVAL;
		goto cleanup;
	}

	for (int i = 0; i < ARRAY_SIZE(capture_features); i++) {
		const struct capture_feature *f = &capture_features[i];
		enum tristate *flag = (void *)&env + f->env_flag_off;

		if (*flag == UNSET)
			*flag = f->default_val;
	}
	/* resolve emit (-e) options not set on the CLI */
	for (int i = 0; i < emit_feature_cnt; i++) {
		const struct emit_feature *f = &emit_features[i];
		enum tristate *flag = (void *)&env + f->env_flag_off;

		if (*flag == UNSET)
			*flag = f->default_val;
	}

	if (env.capture_pystacks && env.requested_stack_traces == ST_NONE) {
		eprintf("-f py-stacks requires stack capture; enable it with -S (e.g. -S timer).\n");
		err = -EINVAL;
		goto cleanup;
	}

	/* create workdir specific to this wprof run */
	struct timespec ts_now;
	struct tm *tm_now;
	char tm_str[32];
	char *data_path_copy = strdup(env.data_path);
	char *data_dir = dirname(data_path_copy);
	clock_gettime(CLOCK_REALTIME, &ts_now);
	tm_now = localtime(&ts_now.tv_sec);
	strftime(tm_str, sizeof(tm_str), "%Y-%m-%d_%H%M%S", tm_now);
	snprintf(workdir_name, sizeof(workdir_name), "%s/wprof-session.%d.%s.%06ld",
		 data_dir, getpid(), tm_str, ts_now.tv_nsec / 1000);
	free(data_path_copy);

	if (mkdir(workdir_name, 0755) < 0) {
		err = -errno;
		eprintf("Failed to create session workdir '%s': %d\n", workdir_name, err);
		goto cleanup;
	}
	workdir_fd = open(workdir_name, O_DIRECTORY | O_RDONLY);
	if (workdir_fd < 0) {
		err = -errno;
		eprintf("Failed to open() session workdir at '%s': %d\n", workdir_name, err);
		goto cleanup;
	}
	if (fchmod(workdir_fd, 0777) < 0) {
		err = -errno;
		eprintf("Failed to chmod(0777) session workdir at '%s': %d\n", workdir_name, err);
		goto cleanup;
	}

	for (int i = 0; i < env.ringbuf_cnt; i++) {
		struct worker_state *worker = &workers[i];

		char chunk_path[PATH_MAX];
		snprintf(chunk_path, sizeof(chunk_path), "%s/bpf-rb.%03d.0.chunk", workdir_name, i);

		struct fr_chunk *chunk = calloc(1, sizeof(*chunk));
		chunk->path = strdup(chunk_path);
		chunk->f = fopen_buffered(chunk_path, "w+");
		chunk->worker_idx = i;
		if (!chunk->f) {
			err = -errno;
			eprintf("Failed to create data dump at '%s': %d\n", chunk_path, err);
			goto cleanup;
		}

		worker->cur_chunk = chunk;
		worker->dump = chunk->f;
		worker->dump_path = chunk->path;
	}

	if (env.flightrec) {
		/*
		 * Build into a local until the thread actually starts; only then
		 * publish to the global `fr`. That way an early pthread_create
		 * failure leaves `fr == NULL`, so fr_teardown() never joins a
		 * thread that was never created.
		 */
		struct fr_state *st = calloc(1, sizeof(*st));

		pthread_mutex_init(&st->lock, NULL);
		pthread_cond_init(&st->cond, NULL);
		st->pq = wppq_new(1024);
		st->workdir = strdup(workdir_name);

		err = pthread_create(&st->thread, NULL, fr_worker, st);
		if (err) {
			err = -err;
			eprintf("Failed to start flight-recorder thread: %d\n", err);
			wppq_free(st->pq);
			pthread_cond_destroy(&st->cond);
			pthread_mutex_destroy(&st->lock);
			free(st);
			goto cleanup;
		}
		fr = st;
	}

	err = pmu_resolve_derived(env.pmu_reals, env.pmu_real_cnt, env.pmu_derivs, env.pmu_deriv_cnt);
	if (err) {
		eprintf("Failed to resolve derived PMU definitions: %s\n", errstr(err));
		goto cleanup;
	}

	/*
	 * Session control loop: a single epoll multiplexes the various
	 * asynchronous sources of control-state transitions (the timerfds and the
	 * signal eventfd) into one place.
	 */
	env.sess_ctl.state = SESS_STANDBY;

	env.sess_ctl.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (env.sess_ctl.epoll_fd < 0) {
		err = -errno;
		eprintf("Failed to create session control epoll: %d\n", err);
		goto cleanup;
	}

	env.sess_ctl.prep_tfd     = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	env.sess_ctl.activate_tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	env.sess_ctl.sess_end_tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	if (env.sess_ctl.prep_tfd < 0 || env.sess_ctl.activate_tfd < 0 || env.sess_ctl.sess_end_tfd < 0) {
		err = -errno;
		eprintf("Failed to create session timerfds: %d\n", err);
		goto cleanup;
	}

	env.sess_ctl.sig_efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (env.sess_ctl.sig_efd < 0) {
		err = -errno;
		eprintf("Failed to create session signal eventfd: %d\n", err);
		goto cleanup;
	}

	if (ctl_epoll_add(env.sess_ctl.epoll_fd, env.sess_ctl.prep_tfd, CTL_PREP_TIMER) ||
	    ctl_epoll_add(env.sess_ctl.epoll_fd, env.sess_ctl.activate_tfd, CTL_ACTIVATE_TIMER) ||
	    ctl_epoll_add(env.sess_ctl.epoll_fd, env.sess_ctl.sess_end_tfd, CTL_END_TIMER) ||
	    ctl_epoll_add(env.sess_ctl.epoll_fd, env.sess_ctl.sig_efd, CTL_SIGNAL)) {
		err = -errno;
		eprintf("Failed to register session control fds: %d\n", err);
		goto cleanup;
	}

	/*
	 * Resolve --prepare/--activate wall-clock specs into absolute ktime
	 * targets; a zero target means "immediately" (prepare at startup, activate
	 * as soon as prepare finishes).
	 */
	if (env.prepare_spec.kind) {
		env.sess_ctl.prepare_target_ts = resolve_timespec(&env.prepare_spec, env.actual_start_ts);
		if (ts_before(env.sess_ctl.prepare_target_ts, ktime_now_ns())) {
			eprintf("Preparation time (--prepare) is in the past!\n");
			err = -EINVAL;
			goto cleanup;
		}
	}
	if (env.activate_spec.kind) {
		env.sess_ctl.activate_target_ts = resolve_timespec(&env.activate_spec, env.actual_start_ts);
		if (ts_before(env.sess_ctl.activate_target_ts, ktime_now_ns())) {
			eprintf("Activation time (--activate) is in the past!\n");
			err = -EINVAL;
			goto cleanup;
		}
	}
	if (env.sess_ctl.prepare_target_ts && env.sess_ctl.activate_target_ts &&
	    ts_before(env.sess_ctl.activate_target_ts, env.sess_ctl.prepare_target_ts)) {
		eprintf("Activation time (--activate) is before preparation time (--prepare)!\n");
		err = -EINVAL;
		goto cleanup;
	}

	arm_timer_abs(env.sess_ctl.prep_tfd, env.sess_ctl.prepare_target_ts ?: ktime_now_ns());
	if (env.prepare_spec.kind)
		wprintf("Pending preparation trigger...\n");

	while (env.sess_ctl.state != SESS_DONE) {
		struct epoll_event evs[8];
		int n = epoll_wait(env.sess_ctl.epoll_fd, evs, ARRAY_SIZE(evs), -1);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			err = -errno;
			eprintf("Session control epoll_wait() failed: %d\n", err);
			goto cleanup;
		}

		for (int i = 0; i < n && env.sess_ctl.state != SESS_DONE; i++) {
			switch (evs[i].data.u32) {
			case CTL_SIGNAL:
				drain_fd(env.sess_ctl.sig_efd);
				env.sess_ctl.state = SESS_DONE;
				break;
			case CTL_PREP_TIMER:
				drain_fd(env.sess_ctl.prep_tfd);
				env.sess_ctl.state = SESS_PREP;
				err = do_prepare(&bpf_state, workers, num_cpus, workdir_fd);
				if (err)
					goto cleanup;
				env.sess_ctl.state = SESS_ARMED;
				if (env.sess_ctl.activate_target_ts &&
				    ts_before(env.sess_ctl.activate_target_ts, ktime_now_ns())) {
					eprintf("Activation time (--activate) already passed during preparation!\n");
					err = -EINVAL;
					goto cleanup;
				}
				arm_timer_abs(env.sess_ctl.activate_tfd, env.sess_ctl.activate_target_ts ?: ktime_now_ns());
				if (env.activate_spec.kind)
					wprintf("Pending activation trigger...\n");
				break;
			case CTL_ACTIVATE_TIMER:
				drain_fd(env.sess_ctl.activate_tfd);
				err = do_activate(&bpf_state);
				if (err)
					goto cleanup;
				env.sess_ctl.session_activated = true;
				env.sess_ctl.state = SESS_RECORDING;
				/* flightrec has no planned end: run until stopped (Ctrl-C via CTL_SIGNAL) */
				if (!env.flightrec) {
					env.sess_ctl.sess_end_target_ts = env.sess_end_ts;
					arm_timer_abs(env.sess_ctl.sess_end_tfd, env.sess_ctl.sess_end_target_ts);
				}
				break;
			case CTL_END_TIMER:
				drain_fd(env.sess_ctl.sess_end_tfd);
				env.sess_ctl.session_complete = true;
				env.sess_ctl.state = SESS_DONE;
				break;
			}
		}
	}

	err = stop_rb_workers(&bpf_state); /* tell ringbuf worker threads to stop and join them */
	if (err) {
		eprintf("Failed during collecting BPF-generated data: %d\n", err);
		goto cleanup;
	}

	if (!env.sess_ctl.session_activated) {
		/* interrupted before recording started: unclean exit, nothing to persist */
		err = -EINTR;
		goto cleanup;
	}

	/*
	 * If the session was cut short (signal) rather than reaching its planned
	 * end, clamp the recorded window to now. This is the point past which the
	 * various data sources (BPF ringbufs, CUDA/pytrace tracee dumps) are torn
	 * down at staggered times and can no longer be considered mutually
	 * consistent. When the session-end timerfd fires it signals the planned
	 * end, which already carries the correct session end.
	 */
	if (!env.sess_ctl.session_complete) {
		env.sess_end_ts = ktime_now_ns();
		env.duration_ns = env.sess_end_ts - env.sess_start_ts;
		/*
		 * flightrec ran with no in-kernel end (0); push the stop time into
		 * the gate so it stops generating late events before detach_bpf.
		 */
		if (env.flightrec && bpf_state.skel)
			bpf_state.skel->bss->session_end_ts = env.sess_end_ts;
	}

	wprintf("Stopping...\n");
	detach_bpf(&bpf_state, num_cpus);

	if (env.injectee_cnt > 0) {
		injmgr_deactivate();
		/*
		 * If we capture CUDA stack traces, we want libwprofinj.so to be loaded during
		 * stack symbolization, so we'll perform final retraction later.
		 */
		if (!(env.requested_stack_traces & ST_CUDA))
			injmgr_retract();
	}

	wprintf("Draining...\n");
	drain_bpf(&bpf_state, num_cpus);

	/*
	 * All event production has stopped; join the FR thread but keep its PQ:
	 * merge consumes the retained chunks below. The PQ + `fr` are freed by
	 * fr_teardown() on the cleanup fall-through (its join is then a no-op).
	 */
	fr_join();

	if (env.capture_pystacks && bpf_state.skel) {
		err = pysym_init(bpf_map__fd(bpf_state.skel->maps.pystacks_symbols),
				 bpf_map__fd(bpf_state.skel->maps.pystacks_linetables));
		if (err) {
			eprintf("Failed to initialize Python symbol table: %d\n", err);
			goto cleanup;
		}
	}

	bool any_python = false;
	u64 cuda_rec_cnt = 0;
	for (int i = 0; i < env.injectee_cnt; i++) {
		struct injectee *inj = &env.injectees[i];

		if (inj->detect_feats & (INJ_FEAT_PYTRACE | INJ_FEAT_PYTORCH))
			any_python = true;
		if (inj->ctx)
			cuda_rec_cnt += inj->ctx->cupti_rec_cnt;
	}

	if (cuda_rec_cnt == 0) {
		/* don't claim CUDA capture if no CUDA records were collected (e.g. CUPTI busy) */
		env.requested_stack_traces &= ~ST_CUDA;
		env.capture_cuda = false;
	}

	if (!any_python) {
		env.capture_pytrace = false;
		env.capture_pytorch = false;
	}

	/*
	 * For flight-recorder, the consistent window ends at the stop time and
	 * starts at the recording floor. rec_min_ts (the newest evicted chunk's
	 * end_ts) is computed from completed chunks only, so it lags the newest
	 * data still held in the current chunks; bound the time dimension here
	 * instead, where sess_end_ts is the true stop, keeping exactly the last
	 * fr_keep_time_ns. Take the later of the two so a binding size limit
	 * (which evicts further) still wins. Re-anchor the recorded window
	 * start/length to [floor, stop] so the header, tsidx, and wallclock
	 * conversions all reflect the retained window rather than the full run.
	 * Capture is over, so mutating these is safe. Merge drops everything
	 * below the floor.
	 */
	if (env.flightrec) {
		u64 floor_ts = fr->rec_min_ts;
		if (env.fr_keep_time_ns)
			floor_ts = ts_max(floor_ts, env.sess_end_ts - env.fr_keep_time_ns);
		/*
		 * A window longer than the run would push the floor before
		 * recording began; clamp up to the real start so we never report a
		 * start earlier than the real one. No upper clamp is needed:
		 * rec_min_ts and sess_end_ts - keep_time are both <= stop.
		 */
		floor_ts = ts_max(floor_ts, env.sess_start_ts);

		env.ktime_start_ns = floor_ts;
		env.realtime_start_ns = ktime_to_realtime_ns(floor_ts);
		env.sess_start_ts = floor_ts;
		env.duration_ns = env.sess_end_ts - floor_ts;
	}

	err = wprof_persist_data(workdir_name, workers,
				 env.flightrec ? fr->pq : NULL,
				 env.sess_start_ts, env.sess_end_ts);
	if (err) {
		eprintf("Failed to finalize data dump: %d\n", err);
		goto cleanup;
	}

	pysym_free();

	/* we delayed ptrace retraction to symbolize libwprofinj.so stacks */
	if ((env.requested_stack_traces & ST_CUDA) && env.injectee_cnt > 0)
		injmgr_retract();

	{
		fflush(workers[0].dump);
		if (fchmod(fileno(workers[0].dump), 0644)) {
			err = -errno;
			eprintf("Failed to chmod() data file '%s': %d\n", env.data_path, err);
			goto cleanup;
		}
		ssize_t file_sz = file_size(workers[0].dump);
		wprintf("Produced %.3lfMB data file at '%s'.\n",
			file_sz / (1024.0 * 1024.0), env.data_path);
	}

skip_data_collection:
	if (env.req_list) {
		err = req_list_output(&workers[0]);
		if (err)
			goto cleanup;
	}

	const char *output_path = env.trace_path ?: env.json_path;
	if (output_path) {
		struct worker_state *w = &workers[0];

		if (env.req_list_cfg && env.req_list_cfg->filter_cnt > 0) {
			err = req_filter_build_allowlist(w, &w->req_allowlist);
			if (err)
				goto cleanup;
		}

		if (strcmp(output_path, "-") == 0) {
			w->trace = stdout;
			signal(SIGPIPE, SIG_IGN);
		} else {
			w->trace = fopen_buffered(output_path, "w+");
			if (!w->trace) {
				err = -errno;
				eprintf("Failed to create trace file '%s': %d\n", output_path, err);
				goto cleanup;
			}
		}

		if (!env.json_path) {
			w->wpb_writer = wpb_writer_new(wpb_stream_write, w->trace);
		}

		err = init_emit(w);
		if (err) {
			eprintf("Failed to init trace emitting logic: %d\n", err);
			goto cleanup;
		}

		if (!env.json_path) {
			if (init_pb_trace(w->wpb_writer, w->dump_hdr)) {
				err = -1;
				eprintf("Failed to init protobuf!\n");
				goto cleanup;
			}
		}

		/* process dumped events, and generate trace */
		err = emit_trace(w);
		if (err) {
			eprintf("Failed to generate trace: %d\n", err);
			goto cleanup;
		}

		fflush(w->trace);
		if (w->trace != stdout) {
			ssize_t file_sz = file_size(w->trace);
			wprintf("Produced %.3lfMB trace file at '%s'.\n",
				file_sz / (1024.0 * 1024.0), output_path);
		}
	}
	print_stats(env.stats, err);

cleanup:
	/*
	 * Idempotent teardown, ordered for the error paths that jump here with
	 * ringbuf workers still running and `fr`/chunks still live (e.g. a
	 * do_prepare/do_activate failure after attach_bpf):
	 *   1. join the ringbuf workers   -> no more producers of events/chunks;
	 *   2. detach + drain on the main thread, which calls handle_rb_event
	 *      while the chunks and `fr` are still VALID;
	 *   3. tear down the FR thread, which frees the chunks in the PQ + `fr`;
	 *   4. THEN free the workers' current chunks.
	 * On the normal success fall-through these all re-run harmlessly as
	 * no-ops (workers already joined, ringbufs drained, `fr` already NULL).
	 */
	stop_rb_workers(&bpf_state);
	detach_bpf(&bpf_state, num_cpus);
	drain_bpf(&bpf_state, num_cpus);
	fr_teardown();
	if (env.injectee_cnt > 0)
		injmgr_teardown();
	cleanup_workers(workers, worker_cnt);
	cleanup_bpf(&bpf_state);
	if (workdir_fd >= 0)
		close(workdir_fd);
	if (!env.keep_workdir && workdir_name[0])
		delete_dir(workdir_name);
	wprintf("Exited %s (after %.3lfs).\n",
		err ? "with errors" : "cleanly",
		(ktime_now_ns() - env.actual_start_ts) / 1000000000.0);
	return -err;
}
