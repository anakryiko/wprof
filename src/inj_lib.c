// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <time.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <linux/futex.h>

#include "inj.h"
#include "inj_common.h"
#include "strset.h"
#include "cuda_data.h"
#include "pytrace_data.h"

#define WPROFINJ_THREAD_NAME "wprofinj"
#define WPROFINJ_CUPTI_THREAD_NAME "wprofinj-cupti"

#define zclose(fd) do { if (fd >= 0) { close(fd); fd = -1; } } while (0)
#define __printf(a, b)	__attribute__((format(printf, a, b)))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#define DEBUG_LOG 0
#define elog(fmt, ...) do { log_printf(0, fmt, ##__VA_ARGS__); } while (0)
#define log(fmt, ...) do { log_printf(1, fmt, ##__VA_ARGS__); } while (0)
#define vlog(fmt, ...) do { log_printf(2, fmt, ##__VA_ARGS__); } while (0)
#define dlog(fmt, ...) do { log_printf(3, fmt, ##__VA_ARGS__); } while (0)

struct inj_setup_ctx *setup_ctx;
struct inj_run_ctx *run_ctx;

/*
 * Live dump fds, redirected to /dev/null in a forked child (see inj_atfork_child).
 * Tracked on the worker thread at session setup/teardown; read in the atfork
 * child handler. A fork() on an app thread can race a track/untrack, so the
 * count is published with release / read with acquire and each slot is written
 * before the count is bumped, so a racing reader only ever sees fully-stored fds.
 */
#define INJ_MAX_DUMP_FDS 8
static int inj_dump_fds[INJ_MAX_DUMP_FDS];
static int inj_dump_fd_cnt;

void inj_track_dump_fd(int fd)
{
	int n = __atomic_load_n(&inj_dump_fd_cnt, __ATOMIC_RELAXED);

	if (fd < 0)
		return;
	if (n >= INJ_MAX_DUMP_FDS) {
		elog("dump fd registry full (%d slots), fd %d not tracked; forked children may corrupt the capture\n",
		     INJ_MAX_DUMP_FDS, fd);
		return;
	}
	inj_dump_fds[n] = fd;
	__atomic_store_n(&inj_dump_fd_cnt, n + 1, __ATOMIC_RELEASE);
}

void inj_untrack_dump_fd(int fd)
{
	int n = __atomic_load_n(&inj_dump_fd_cnt, __ATOMIC_RELAXED);

	for (int i = 0; i < n; i++) {
		if (inj_dump_fds[i] != fd)
			continue;
		inj_dump_fds[i] = inj_dump_fds[n - 1];
		__atomic_store_n(&inj_dump_fd_cnt, n - 1, __ATOMIC_RELEASE);
		return;
	}
}

static int log_fd = -1;
static int filelog_verbosity = -1;

#if DEBUG_LOG
static int stderr_verbosity = 3;
#else /* !DEBUG_LOG */
static int stderr_verbosity = -1;
#endif /* DEBUG_LOG */

static void write_all(int fd, void *buf, size_t sz)
{
	ssize_t done = 0, len;

	while (done < sz) {
		len = write(fd, buf + done, sz - done);
		if (len < 0)
			return;
		done += len;
	}
}

__printf(2, 3)
void log_printf(int verbosity, const char *fmt, ...)
{
	va_list args;
	int old_errno;

	if (verbosity > stderr_verbosity && (log_fd < 0 || verbosity > filelog_verbosity))
		return;

	old_errno = errno;

	struct timeval tv;
	struct tm *tm;
	char buf[4096];
	size_t len;

	gettimeofday(&tv, NULL);
	tm = localtime(&tv.tv_sec);
	len = snprintf(buf, sizeof(buf), "WPROFINJ(%d/%d) %02d:%02d:%02d.%06ld: ",
		       setup_ctx ? setup_ctx->tracee_pid : getpid(), gettid(),
		       tm->tm_hour, tm->tm_min, tm->tm_sec, tv.tv_usec);

	va_start(args, fmt);
	len += vsnprintf(buf + len, sizeof(buf) - len, fmt, args);
	va_end(args);

	if (verbosity <= stderr_verbosity)
		write_all(STDERR_FILENO, buf, len);
	if (log_fd >= 0 && verbosity <= filelog_verbosity)
		write_all(log_fd, buf, len);

	errno = old_errno;
}

/*
 * XXX: this is a hacky way to make sure strset from libbpf can be used
 * without dragging in entire libbpf...
 */
void *libbpf_add_mem(void **data, size_t *cap_cnt, size_t elem_sz,
		     size_t cur_cnt, size_t max_cnt, size_t add_cnt)
{
	size_t new_cnt;
	void *new_data;

	if (cur_cnt + add_cnt <= *cap_cnt)
		return *data + cur_cnt * elem_sz;

	/* requested more than the set limit */
	if (cur_cnt + add_cnt > max_cnt)
		return NULL;

	new_cnt = *cap_cnt;
	new_cnt += new_cnt / 4;		  /* expand by 25% */
	if (new_cnt < 16)		  /* but at least 16 elements */
		new_cnt = 16;
	if (new_cnt > max_cnt)		  /* but not exceeding a set limit */
		new_cnt = max_cnt;
	if (new_cnt < cur_cnt + add_cnt)  /* also ensure we have enough memory */
		new_cnt = cur_cnt + add_cnt;

	new_data = realloc(*data, new_cnt * elem_sz);
	if (!new_data)
		return NULL;

	/* zero out newly allocated portion of memory */
	memset(new_data + (*cap_cnt) * elem_sz, 0, (new_cnt - *cap_cnt) * elem_sz);

	*data = new_data;
	*cap_cnt = new_cnt;
	return new_data + cur_cnt * elem_sz;
}

void *dyn_resolve_sym(const char *sym_name, void *dlopen_handle)
{
	void *sym;

	if (dlopen_handle) {
		sym = dlsym(dlopen_handle, sym_name);
		if (sym) {
			vlog("Found '%s' at %p in shared lib.\n", sym_name, sym);
			return sym;
		}
	}

	sym = dlsym(RTLD_DEFAULT, sym_name);
	if (sym) {
		vlog("Found '%s' at %p in global symbols table.\n", sym_name, sym);
		return sym;
	}

	elog("Failed to resolve '%s()'!\n", sym_name);
	return NULL;
}

#define WORKER_STACK_SIZE (256 * 1024)
#define UDS_MAX_MSG_LEN 1024

static int (*inj_pthread_create)(pthread_t *thread, const void *attr, typeof(void *(void *)) *start_routine, void *arg);
static int (*inj_pthread_join)(pthread_t thread, void **retval);
static bool use_pthread;
static pthread_t worker_pthread;

static pid_t inj_tid = -1;
static void *stack = NULL;
static int exit_fd = -1;
static int chunk_handoff_efd = -1;	/* tracee threads bump this on chunk rotation to wake the worker */
static pid_t worker_tid; /* for clone() and futex() only */
static int epoll_fd = -1;
static int session_timer_fd = -1;

static char msg_buf[UDS_MAX_MSG_LEN] __attribute__((aligned(8)));

enum epoll_kind {
	EK_EXIT,
	EK_UDS,
	EK_TIMER_SESSION,
	EK_CHUNK_HANDOFF,		/* a chunker rotated; hand its completed chunk to wprof */
};

static int epoll_add(int epoll_fd, int fd, __u32 epoll_events, enum epoll_kind kind)
{
	struct epoll_event ev = {
		.events = epoll_events,
		.data = {
			.u32 = kind,
		},
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		int err = -errno;
		elog("Failed to EPOLL_CTL_ADD FD %d (kind %d) to epoll_fd %d: %d\n", fd, kind, epoll_fd, err);
		return err;
	}
	return 0;
}

__attribute__((unused))
static int epoll_del(int epoll_fd, int fd)
{
	if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL) < 0) {
		int err = -errno;
		elog("Failed to EPOLL_CTL_DEL FD %d from epoll_fd %d: %d\n", fd, epoll_fd, err);
		return err;
	}
	return 0;
}

/* Signal an eventfd (bump its counter); its epoll watcher wakes. */
static void poke_eventfd(int fd)
{
	u64 one = 1;
	(void)write(fd, &one, sizeof(one));
}

/* Consume an eventfd's counter after an epoll wakeup. */
static void reset_eventfd(int fd)
{
	u64 v;
	(void)read(fd, &v, sizeof(v));
}

static bool session_ended;

/* ==================== Chunked data-stream writer ==================== */

/*
 * The active chunkers, one fixed slot per feature (chunker_slot()), so CHUNK_FD
 * can install a spare into the right one and the worker can walk them for
 * completed chunks. A feature that isn't set up leaves a NULL slot.
 */
#define INJ_CHUNKER_CNT 3
static struct chunker *chunkers[INJ_CHUNKER_CNT];

static int chunker_slot(enum inj_feature feature)
{
	switch (feature) {
	case INJ_FEAT_CUDA: return 0;
	case INJ_FEAT_PYTRACE: return 1;
	case INJ_FEAT_PYTORCH: return 2;
	}
	return -1;
}

/*
 * Allocate a chunk around fd: fdopen + buffer + track it for fork safety (the
 * atfork child redirects tracked dump fds to /dev/null). Consumes fd on success;
 * on failure returns NULL and leaves fd to the caller.
 */
static struct chunk *chunk_new(int fd, size_t buf_sz)
{
	struct chunk *c = calloc(1, sizeof(*c));
	if (!c)
		return NULL;

	c->f = fdopen(fd, "w");
	if (!c->f) {
		free(c);
		return NULL;
	}
	setvbuf(c->f, NULL, _IOFBF, buf_sz);
	inj_track_dump_fd(fd);
	return c;
}

/* Untrack, close (flushing the stdio buffer to the fd), and free a chunk. */
static void chunk_free(struct chunk *c)
{
	inj_untrack_dump_fd(fileno(c->f));
	fclose(c->f);
	free(c);
}

/* On success takes ownership of events_fd (via fdopen); on failure the caller keeps it. */
int chunker_init(struct chunker *chunker, int events_fd, enum inj_feature feature, size_t buf_sz)
{
	memset(chunker, 0, sizeof(*chunker));
	chunker->feature = feature;
	chunker->buf_sz = buf_sz;

	/* data stream is headerless: records are written from offset 0 */
	chunker->cur = chunk_new(events_fd, buf_sz);
	if (!chunker->cur) {
		int err = -errno;
		elog("Failed to create initial data chunk (FD %d): %d\n", events_fd, err);
		return err;
	}
	pthread_mutex_init(&chunker->lock, NULL);
	chunkers[chunker_slot(feature)] = chunker;
	return 0;
}

/*
 * The event write path runs on many tracee threads, so serialize the write and
 * accounting under the lock. fwrite_unlocked is safe here since we hold the lock
 * (fwrite already serialized writes per FILE, so this just moves that point).
 *
 * In flight-recorder mode (run_ctx->fr_chunk_size set), once the current chunk
 * fills and a spare is in hand, rotate onto it and publish the completed chunk
 * for the worker to hand off. With no spare the current chunk just keeps growing
 * (overshoot, never blocks the tracee thread).
 */
int chunker_write(struct chunker *chunker, const void *rec, size_t sz, u64 ts)
{
	bool rotated = false;
	int err = 0;

	pthread_mutex_lock(&chunker->lock);
	struct chunk *c = chunker->cur;
	if (fwrite_unlocked(rec, sz, 1, c->f) == 1) {
		c->byte_sz += sz;
		c->event_cnt++;
		chunker->total_event_cnt++;
		chunker->total_byte_sz += sz;
		if (ts > c->end_ts)
			c->end_ts = ts;

		/*
		 * handoff != NULL means the worker hasn't taken the previous chunk yet;
		 * the load is racy (the worker clears it lock-free), which is fine -- a
		 * stale "still pending" just delays this rotation and we overshoot. The
		 * completed chunk is published as a single atomic store: its stats
		 * travel with the pointer, so the worker reads them coherently.
		 */
		u64 chunk_size = run_ctx->fr_chunk_size;
		if (chunk_size && c->byte_sz >= chunk_size &&
		    chunker->spare && !atomic_load(&chunker->handoff)) {
			atomic_store(&chunker->handoff, c);
			chunker->cur = chunker->spare;
			chunker->spare = NULL;
			rotated = true;
		}
	} else {
		err = -errno;
	}
	pthread_mutex_unlock(&chunker->lock);

	if (rotated)
		poke_eventfd(chunk_handoff_efd);	/* wake the worker to hand off the chunk */
	return err;
}

/* Install a freshly received chunk fd (CHUNK_FD) as feature's next spare. Consumes fd. */
static int chunker_install_spare(enum inj_feature feature, int fd)
{
	int slot = chunker_slot(feature);
	struct chunker *chunker = slot >= 0 ? chunkers[slot] : NULL;

	/* !cur means the feature never set up or was already finalized */
	if (!chunker || !chunker->cur) {
		elog("CHUNK_FD for unknown/inactive feature %s\n", inj_feature_str(feature));
		zclose(fd);
		return -ENOENT;
	}

	struct chunk *c = chunk_new(fd, chunker->buf_sz);
	if (!c) {
		int err = -errno;
		elog("Failed to create spare chunk (fd %d): %d\n", fd, err);
		zclose(fd);	/* chunk_new left it to us on failure */
		return err;
	}

	/* wprof replenishes 1:1, so the spare is guaranteed NULL here */
	pthread_mutex_lock(&chunker->lock);
	chunker->spare = c;
	pthread_mutex_unlock(&chunker->lock);
	return 0;
}

/*
 * Worker thread: hand each completed chunk off to wprof (CHUNK_DONE). Lock-free
 * against the tracee writers: atomic-xchg the pointer to claim the chunk (NULL if
 * nothing is pending), then read its bundled stats (ordered by the xchg acquire).
 */
static void chunkers_handoff(void)
{
	for (int i = 0; i < INJ_CHUNKER_CNT; i++) {
		struct chunker *chunker = chunkers[i];

		if (!chunker)
			continue;

		struct chunk *c = atomic_xchg(&chunker->handoff, NULL);
		if (!c)
			continue;

		struct inj_msg msg = {
			.kind = INJ_MSG_CHUNK_DONE,
			.chunk_done = {
				.feature = chunker->feature,
				.end_ts = c->end_ts,
				.byte_sz = c->byte_sz,
				.event_cnt = c->event_cnt,
			},
		};
		chunk_free(c);	/* no more tracee writes it: flush + close */

		/* best-effort: the chunk is on disk and wprof reads it by path regardless */
		if (send(setup_ctx->uds_fd, &msg, sizeof(msg), MSG_NOSIGNAL) != sizeof(msg))
			elog("Failed to send CHUNK_DONE for feature %s: %d\n", inj_feature_str(chunker->feature), -errno);
	}
}

/*
 * Flush and close the current chunk (plus any spare / undrained completed chunk).
 * Called on the worker thread once the feature's event source is stopped and its
 * callbacks are drained, so no tracee thread writes and no handoff races -- this
 * is worker-exclusive and needs no lock.
 */
int chunker_finalize(struct chunker *chunker)
{
	if (!chunker->cur)
		return 0;

	/*
	 * A completed chunk the worker never drained is still on disk and owned by
	 * wprof (which reads it by path at merge), so just release it here. The spare
	 * was never written; drop it too.
	 */
	if (chunker->handoff) {
		chunk_free(chunker->handoff);
		chunker->handoff = NULL;
	}
	if (chunker->spare) {
		chunk_free(chunker->spare);
		chunker->spare = NULL;
	}

	fflush(chunker->cur->f);
	fsync(fileno(chunker->cur->f));
	chunk_free(chunker->cur);
	chunker->cur = NULL;
	pthread_mutex_destroy(&chunker->lock);
	return 0;
}

/* ==================== CUDA event dump ==================== */

#define CUDA_DUMP_BUF_SZ (256 * 1024)
static struct chunker cuda_chunker;
static FILE *cuda_respool_dump;		/* resource pool (header + string pool), written at finalize */

#define CUDA_DUMP_MAX_STRS_SZ (1024 * 1024 * 1024)
struct strset *cuda_respool_strs;

int cuda_dump_event(struct wcuda_event *e)
{
	int err = chunker_write(&cuda_chunker, e, sizeof(*e), e->ts);
	if (err) {
		elog("Failed to fwrite() CUDA event: %d\n", err);
		return err;
	}
	return 0;
}

static void init_wcuda_header(struct wcuda_data_hdr *hdr)
{
	memset(hdr, 0, sizeof(*hdr));
	memcpy(hdr->magic, "WCUDA", 6);
	hdr->hdr_sz = sizeof(*hdr);
	hdr->flags = 0;
	hdr->version_major = WCUDA_DATA_MAJOR;
	hdr->version_minor = WCUDA_DATA_MINOR;
}

static int cuda_dump_setup(int events_fd, int respool_fd)
{
	int err;

	cuda_respool_strs = strset__new(CUDA_DUMP_MAX_STRS_SZ, "", 1);

	err = chunker_init(&cuda_chunker, events_fd, INJ_FEAT_CUDA, CUDA_DUMP_BUF_SZ);
	if (err)
		goto cleanup;
	events_fd = -1;		/* the chunker owns it now */

	cuda_respool_dump = fdopen(respool_fd, "w");
	if (!cuda_respool_dump) {
		err = -errno;
		elog("Failed to create FILE wrapper around CUDA resource pool FD %d: %d\n", respool_fd, err);
		goto cleanup;
	}

	inj_track_dump_fd(respool_fd);

	return 0;

cleanup:
	chunker_finalize(&cuda_chunker);
	strset__free(cuda_respool_strs);
	cuda_respool_strs = NULL;
	if (cuda_respool_dump) {
		fclose(cuda_respool_dump);
		cuda_respool_dump = NULL;
	} else {
		zclose(respool_fd);
	}
	zclose(events_fd);
	return err;
}

int cuda_dump_finalize(void)
{
	int err = 0;

	if (!cuda_chunker.cur)
		return 0;

	/* finalize the headerless data stream: just flush and close */
	chunker_finalize(&cuda_chunker);

	/* write the resource pool: header followed by the string pool */
	const char *strs = strset__data(cuda_respool_strs);
	size_t strs_sz = strset__data_size(cuda_respool_strs);

	struct wcuda_data_hdr hdr;
	init_wcuda_header(&hdr);
	hdr.sess_start_ns = run_ctx->sess_start_ts;
	hdr.sess_end_ns = run_ctx->sess_end_ts;
	hdr.strs_sz = strs_sz;
	hdr.cfg.dummy = 0;

	inj_untrack_dump_fd(fileno(cuda_respool_dump));

	if (fwrite(&hdr, sizeof(hdr), 1, cuda_respool_dump) != 1) {
		err = -errno;
		elog("Failed to fwrite() CUDA resource pool header: %d\n", err);
		return err;
	}

	if (fwrite(strs, 1, strs_sz, cuda_respool_dump) != strs_sz) {
		err = -errno;
		elog("Failed to write strings to CUDA resource pool: %d\n", err);
		return err;
	}

	fflush(cuda_respool_dump);
	fsync(fileno(cuda_respool_dump));
	fclose(cuda_respool_dump);
	cuda_respool_dump = NULL;

	return 0;
}

static int handle_session_end(void)
{
	int err = 0, ret;

	/*
	 * Exit and timer events are racing each other (plus tracer death,
	 * SHUTDOWN, and the worker cleanup label all funnel here), so finalize
	 * just once.
	 */
	if (session_ended)
		return 0;
	session_ended = true;

	finalize_cupti_activities();

	if (cuda_chunker.cur) {
		ret = cuda_dump_finalize();
		if (ret) {
			/* keep going so the other features still get finalized */
			elog("Failed to finalize CUDA data dump: %d\n", ret);
			err = err ?: ret;
		}
	}

	/*
	 * Finalize PyTorch before PyTrace: PyTorch teardown doesn't need the GIL,
	 * while PyTrace's profiler uninstall takes it. Each is a no-op if its
	 * feature wasn't set up.
	 */
	ret = pytorch_session_finalize();
	if (ret) {
		elog("Failed to finalize PyTorch data dump: %d\n", ret);
		err = err ?: ret;
	}

	ret = pytrace_session_finalize();
	if (ret) {
		elog("Failed to finalize PyTrace data dump: %d\n", ret);
		err = err ?: ret;
	}

	return err;
}

static int setup_session_timer(int *timer_fd_out, long timeout_ms, enum epoll_kind kind)
{
	int err;
	int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (fd < 0) {
		err = -errno;
		elog("Failed to create timerfd: %d\n", err);
		return err;
	}

	struct itimerspec spec = {
		.it_value = {
			.tv_sec = timeout_ms / 1000,
			.tv_nsec = timeout_ms % 1000 * 1000000,
		},
	};
	if (timerfd_settime(fd, 0, &spec, NULL) < 0) {
		err = -errno;
		elog("Failed to timerfd_settime(): %d\n", err);
		zclose(fd);
		return err;
	}

	if ((err = epoll_add(epoll_fd, fd, EPOLLIN, kind)) < 0) {
		elog("Failed to add timerfd into epoll: %d\n", err);
		zclose(fd);
		return err;
	}

	*timer_fd_out = fd;
	return 0;
}

static int handle_msg(struct inj_msg *msg, int *fds, int fd_cnt)
{
	int err = 0;

	switch (msg->kind) {
	case INJ_MSG_SETUP: {
		const int exp_fd_cnt = 2;
		if (fd_cnt != exp_fd_cnt) {
			elog("Unexpected number of FDs received for INJ_MSG_SETUP message (got %d, expected %d)\n",
			     fd_cnt, exp_fd_cnt);
			return -EPROTO;
		}

		int run_ctx_memfd = fds[0];
		log_fd = fds[1];

		/* fd[0] is memfd for run context */
		run_ctx = mmap(NULL, sizeof(struct inj_run_ctx), PROT_READ | PROT_WRITE, MAP_SHARED,
			       run_ctx_memfd, 0);
		if (run_ctx == MAP_FAILED) {
			err = -errno;
			elog("Failed to mmap() provided run_ctx: %d\n", err);
			return err;
		}

		vlog("Log setup completed successfully! wprof PID is %d. wprofinj TID %d PID %d REAL PID %d\n",
		     setup_ctx->parent_pid, gettid(), getpid(), setup_ctx->tracee_pid);

		zclose(run_ctx_memfd);
		break;
	}
	case INJ_MSG_CUDA_SETUP: {
		if (fd_cnt != 2) {
			elog("Received CUDA_SETUP with unexpected FD count %d (want 2)!\n", fd_cnt);
			return -EPROTO;
		}
		int events_fd = fds[0];	/* headerless event dump */
		int respool_fd = fds[1];	/* resource pool */

		vlog("Setting up CUDA feature...\n");

		err = init_cupti_activities();
		if (err) {
			elog("Failed to initialize CUPTI: %d\n", err);
			run_ctx->cuda_feat_state = FEAT_FAILED;
			inj_set_feat_hint(run_ctx->cuda_feat_hint, "Failed to initialize CUPTI: %d", err);
			zclose(events_fd);
			zclose(respool_fd);
			return 0;
		}

		if ((err = cuda_dump_setup(events_fd, respool_fd)) < 0) {
			elog("Failed to setup CUDA data dump: %d\n", err);
			run_ctx->cuda_feat_state = FEAT_FAILED;
			inj_set_feat_hint(run_ctx->cuda_feat_hint, "Failed to set up CUDA data dump: %d", err);
			/* cuda_dump_setup() closes both fds on failure */
			return 0;
		}

		/*
		 * Temporarily set name to CUPTI-specific variant as CUPTI might create more
		 * pthreads and will inherit current thread name. This will lead to confusion due
		 * to multiple "wprofinj" threads. Renaming to "wprofinj-cupti" (and then back to
		 * "wprofinj" once we are done with CUPTI initialization) we make sure that we can
		 * distinguish our own thread and CUPTI-owned ones
		 */
		(void)prctl(PR_SET_NAME, WPROFINJ_CUPTI_THREAD_NAME, 0, 0, 0);

		err = start_cupti_activities();

		/* restore original "wprofinj" name now */
		(void)prctl(PR_SET_NAME, WPROFINJ_THREAD_NAME, 0, 0, 0);

		if (err) {
			/*
			 * -EBUSY means CUPTI rejected our subscription, which in practice
			 * means this process doesn't actually use CUDA (or, rarely, another
			 * CUPTI tool is active). Treat as "ignore this feature", not a hard
			 * failure, so co-resident features still run. The CUDA dump stays
			 * owned by cuda_events_dump and is finalized (empty) at session end.
			 */
			run_ctx->cuda_feat_state = (err == -EBUSY) ? FEAT_IGNORED : FEAT_FAILED;
			/* -EBUSY: start_cupti_activities() already recorded the busy reason. */
			if (err != -EBUSY)
				inj_set_feat_hint(run_ctx->cuda_feat_hint, "Failed to start CUDA activity tracing: %d", err);
			elog("Failed to start CUDA activity tracing: %d (feature %s)\n",
			     err, err == -EBUSY ? "ignored" : "failed");
			return 0;
		}

		run_ctx->cuda_feat_state = FEAT_READY;
		vlog("CUDA feature ready.\n");
		break;
	}
	case INJ_MSG_PYTRACE_SETUP: {
		if (fd_cnt != 2) {
			elog("Received PYTRACE_SETUP with unexpected FD count %d (want 2)!\n", fd_cnt);
			return -EPROTO;
		}
		int events_fd = fds[0];		/* headerless event dump */
		int respool_fd = fds[1];	/* resource pool */
		int py_ver_minor = msg->pytrace_setup.py_version_minor;

		vlog("Setting up PyTrace feature (Python 3.%d)...\n", py_ver_minor);

		err = pytrace_session_setup(events_fd, respool_fd, py_ver_minor,
					    msg->pytrace_setup.sym_addrs,
					    ARRAY_SIZE(msg->pytrace_setup.sym_addrs));
		if (err) {
			elog("Failed to setup PyTrace feature: %d\n", err);
			/* pytrace_session_setup() consumes both fds on failure */
			run_ctx->pytrace_feat_state = FEAT_FAILED;
			inj_set_feat_hint(run_ctx->pytrace_feat_hint, "Failed to set up PyTrace: %d", err);
			return 0;
		}

		run_ctx->pytrace_feat_state = FEAT_READY;
		vlog("PyTrace feature ready.\n");
		break;
	}
	case INJ_MSG_PYTORCH_SETUP: {
		if (fd_cnt != 2) {
			elog("Received PYTORCH_SETUP with unexpected FD count %d (want 2)!\n", fd_cnt);
			return -EPROTO;
		}
		int events_fd = fds[0];		/* headerless event dump */
		int respool_fd = fds[1];	/* resource pool */

		vlog("Setting up PyTorch feature...\n");

		err = pytorch_session_setup(events_fd, respool_fd, msg->pytorch_setup.pytorch_sym_addrs,
					    ARRAY_SIZE(msg->pytorch_setup.pytorch_sym_addrs));
		if (err) {
			elog("Failed to setup PyTorch feature: %d\n", err);
			/* pytorch_session_setup() consumes both fds on failure */
			run_ctx->pytorch_feat_state = FEAT_FAILED;
			inj_set_feat_hint(run_ctx->pytorch_feat_hint, "Failed to set up PyTorch: %d", err);
			return 0;
		}

		run_ctx->pytorch_feat_state = FEAT_READY;
		vlog("PyTorch feature ready.\n");
		break;
	}
	case INJ_MSG_START_SESSION: {
		long sess_timeout_ms = msg->start_session.session_timeout_ms;
		bool any_ready = run_ctx->cuda_feat_state == FEAT_READY ||
				 run_ctx->pytrace_feat_state == FEAT_READY ||
				 run_ctx->pytorch_feat_state == FEAT_READY;

		if (!any_ready) {
			vlog("START_SESSION: no feature set up successfully, marking session failed.\n");
			run_ctx->setup_state = INJ_SETUP_FAILED;
			break;
		}

		if (sess_timeout_ms != 0) {
			if ((err = setup_session_timer(&session_timer_fd, sess_timeout_ms, EK_TIMER_SESSION)) < 0) {
				elog("Failed to set up session timer: %d\n", err);
				return err;
			}
		}

		run_ctx->setup_state = INJ_SETUP_READY;
		if (sess_timeout_ms != 0)
			vlog("Session started (timeout %3ldms from now).\n", sess_timeout_ms);
		else
			vlog("Session started (flight recorder mode).\n");
		break;
	}
	case INJ_MSG_SHUTDOWN:
		vlog("Shutdown command received, cleaning up...\n");

		err = handle_session_end();
		if (err) {
			elog("Failed to cleanly handle session end: %d\n", err);
			return err;
		}

		vlog("Shutdown completed successfully.\n");
		return -ESHUTDOWN;
	case INJ_MSG_CHUNK_FD: {
		if (fd_cnt != 1) {
			elog("Received CHUNK_FD with unexpected FD count %d (want 1)!\n", fd_cnt);
			return -EPROTO;
		}
		err = chunker_install_spare(msg->chunk_fd.feature, fds[0]);
		if (err) {
			elog("Failed to install spare chunk for feature %s: %d\n",
			     inj_feature_str(msg->chunk_fd.feature), err);
			return err;
		}
		break;
	}
	default:
		elog("Unexpected message %s!\n", inj_msg_str(msg->kind));
		return -EINVAL;
	}
	return 0;
}

static int worker_thread_func(void *arg)
{
	int ret, err = 0;
	int run_ctx_memfd = -1;

	vlog("Worker thread started (TID %d, PID %d, REAL PID %d)\n",
	     gettid(), getpid(), setup_ctx->tracee_pid);

	/* let's self-identify for easier observability and debugging */
	(void)prctl(PR_SET_NAME, WPROFINJ_THREAD_NAME, 0, 0, 0);

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0) {
		err = -errno;
		elog("Failed to create epoll FD: %d\n", err);
		goto cleanup;
	}

	if ((err = epoll_add(epoll_fd, exit_fd, EPOLLIN, EK_EXIT)) < 0)
		goto cleanup;
	if ((err = epoll_add(epoll_fd, setup_ctx->uds_fd, EPOLLIN, EK_UDS)) < 0)
		goto cleanup;
	if ((err = epoll_add(epoll_fd, chunk_handoff_efd, EPOLLIN, EK_CHUNK_HANDOFF)) < 0)
		goto cleanup;

	vlog("Waiting commands or exit signal...\n");

	int *fds = NULL, fd_cnt = 0;
	struct iovec io = { .iov_base = msg_buf, .iov_len = sizeof(msg_buf) };
	char buf[CMSG_SPACE(sizeof(int) * MAX_UDS_FD_CNT)];
	struct msghdr msg = {
		.msg_iov = &io,
		.msg_iovlen = 1,
		.msg_control = buf,
		.msg_controllen = sizeof(buf),
	};

event_loop:
	struct epoll_event evs[8];
	int n = epoll_wait(epoll_fd, evs, ARRAY_SIZE(evs), -1);
	if (n < 0) {
		if (errno == EINTR)
			goto event_loop; /* interrupted by a signal, not an error; retry */
		err = -errno;
		elog("epoll_wait() failed: %d\n", err);
		goto cleanup;
	}
	for (int i = 0; i < n; i++) {
		switch (evs[i].data.u32) {
		case EK_UDS:
			/*
			 * recvmsg() shrinks msg_controllen to the ancillary size it
			 * actually received, so reset it before every call — otherwise a
			 * later fd-bearing message after a 0-fd one would be silently
			 * truncated (MSG_CTRUNC) and lose its fd.
			 */
			msg.msg_controllen = sizeof(buf);
			ret = recvmsg(setup_ctx->uds_fd, &msg, 0);
			if (ret < 0) {
				err = -errno;
				elog("UDS recvmsg() error (ret %d): %d\n", ret, err);
				goto cleanup;
			} else if (ret == 0) {
				elog("UDS recvmsg() returned ZERO, meaning tracer process died, cleaning up...\n");

				/* we still make sure that we clean up CUPTI stuff */
				err = handle_session_end();
				if (err)
					elog("Failed to cleanly handle CUDA session end: %d\n", err);

				err = -EFAULT;

				goto cleanup;
			} else if (ret != sizeof(struct inj_msg)) {
				err = -EPROTO;
				elog("UDS recvmsg() returned unexpected message size %d (expecting %zd), exiting!\n",
				     ret, sizeof(struct inj_msg));
				goto cleanup;
			}

			if (msg.msg_flags & MSG_CTRUNC) {
				err = -EPROTO;
				elog("UDS recvmsg() truncated ancillary data (lost FDs), exiting!\n");
				goto cleanup;
			}

			fds = NULL;
			fd_cnt = 0;
			if (msg.msg_controllen > 0) {
				struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

				if (cmsg->cmsg_level != SOL_SOCKET ||
				    cmsg->cmsg_type != SCM_RIGHTS) {
					err = -EPROTO;
					elog("UDS recvmsg() returned unexpected cmsghdr type, exiting!\n");
					goto cleanup;
				}

				int fds_sz = cmsg->cmsg_len - CMSG_LEN(0);
				if (fds_sz > sizeof(int) * MAX_UDS_FD_CNT || fds_sz % sizeof(int) != 0) {
					err = -EPROTO;
					elog("UDS recvmsg() returned unexpected cmsghdr FDs payload (size %d), exiting!\n", fds_sz);
					goto cleanup;
				}

				fds = (int *)CMSG_DATA(cmsg);
				fd_cnt = fds_sz / sizeof(int);
			}

			struct inj_msg *m = (void *)msg_buf;

			vlog("Received UDS message %s with %d FD%s.\n",
			     inj_msg_str(m->kind), fd_cnt, fd_cnt > 1 ? "s" : "");

			err = handle_msg(m, fds, fd_cnt);
			if (err == -ESHUTDOWN) {
				err = 0;
				goto cleanup;
			}
			if (err) {
				for (int i = 0; i < fd_cnt; i++)
					close(fds[i]);
				elog("Failure while handling message %s: %d, exiting!\n", inj_msg_str(m->kind), err);
				goto cleanup;
			}
			break;
		case EK_TIMER_SESSION: {
			long long expirations;
			(void)read(session_timer_fd, &expirations, sizeof(expirations));

			err = handle_session_end();
			if (err) {
				elog("Failed to cleanly handle session end: %d\n", err);
				goto cleanup;
			}

			vlog("Session timer expired with %.3lfms delay after planned session end.\n",
			     (ktime_now_ns() - run_ctx->sess_end_ts) / 1000000.0);
			break;
		}
		case EK_EXIT:
			reset_eventfd(exit_fd);

			err = handle_session_end();
			if (err) {
				elog("Failed to cleanly handle CUDA session end: %d\n", err);
				goto cleanup;
			}

			vlog("Worker thread received exit signal\n");
			err = 0;
			goto cleanup;
		case EK_CHUNK_HANDOFF:
			reset_eventfd(chunk_handoff_efd);
			chunkers_handoff();
			break;
		default:
			elog("Unrecognized epoll event from FD %d, exiting...\n", evs[i].data.fd);
			err = -EINVAL;
			goto cleanup;
		}
	}
	goto event_loop;

cleanup:
	/*
	 * Tear down any active session before the fds and run_ctx go away, no
	 * matter which error path landed us here. This unsubscribes the
	 * RecordFunction callback and uninstalls the Python profiler so they can
	 * never fire against freed state; the permanent trampoline is kept.
	 * Idempotent via session_ended, so paths that already finalized are no-ops.
	 */
	(void)handle_session_end();

	vlog("Worker thread exiting...\n");

	zclose(exit_fd);
	zclose(chunk_handoff_efd);
	zclose(setup_ctx->uds_fd);
	zclose(run_ctx_memfd);
	zclose(epoll_fd);
	zclose(session_timer_fd);

	if (err) {
		if (run_ctx && run_ctx->setup_state == INJ_SETUP_PENDING)
			run_ctx->setup_state = INJ_SETUP_FAILED;

		elog("Worker thread exited with ERROR %d.\n", err);
	} else {
		vlog("Worker thread exited successfully.\n");
	}

	if (run_ctx && run_ctx != MAP_FAILED) {
		run_ctx->worker_thread_done = true;
		munmap(run_ctx, sizeof(struct inj_run_ctx));
	}

	return err;
}

static void *worker_pthread_func(void *arg)
{
	return (void *)(long)worker_thread_func(arg);
}

static int start_worker_thread(void)
{
	int err;

	vlog("Creating worker thread...\n");

	/* Create eventfd()s for exit signaling */
	exit_fd = eventfd(0, EFD_CLOEXEC);
	if (exit_fd < 0) {
		err = -errno;
		elog("Failed to create exit-command eventfd: %d\n", err);
		goto err_out;
	}

	/* eventfd tracee threads bump on chunk rotation to wake the worker */
	chunk_handoff_efd = eventfd(0, EFD_CLOEXEC);
	if (chunk_handoff_efd < 0) {
		err = -errno;
		elog("Failed to create chunk-rotation eventfd: %d\n", err);
		goto err_out;
	}

	inj_pthread_create = dyn_resolve_sym("pthread_create", NULL);
	inj_pthread_join = dyn_resolve_sym("pthread_join", NULL);
	use_pthread = inj_pthread_create && inj_pthread_join;

	vlog("Using %s to manage worker thread!\n", use_pthread ? "libpthread" : "clone() syscall");

	if (use_pthread) {
		err = inj_pthread_create(&worker_pthread, NULL, worker_pthread_func, NULL);
		if (err) {
			elog("Failed to create worker thread using libpthread: %d (errno %d)!\n", err, errno);
			goto err_out;
		}

		log("Worker thread created successfully using libpthread (PID %d)\n", getpid());
		return 0;
	} else {
		/* Allocate stack for the worker thread */
		stack = mmap(NULL, WORKER_STACK_SIZE, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
		if (stack == MAP_FAILED) {
			err = -errno;
			elog("Failed to allocate worker stack: %d\n", err);
			goto err_out;
		}

		/* Now finally create a thread */
		inj_tid = clone(worker_thread_func, stack + WORKER_STACK_SIZE /* top-of-stack */,
				CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_SYSVSEM |
				CLONE_THREAD |
				CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID /* ! IMPORTANT ! */,
				NULL, /* arg */
				NULL, /* parent_tid */
				NULL, /* tls */
				&worker_tid); /* child_tid for SETTID/CLEARTID */
		if (inj_tid < 0) {
			err = -errno;
			elog("Failed to clone() worker thread: %d\n", err);
			goto err_out;
		}

		log("Worker thread created successfully (TID %d, PID %d)\n", inj_tid, getpid());
		return 0;
	}
err_out:
	if (stack && stack != MAP_FAILED)
		(void)munmap(stack, WORKER_STACK_SIZE);
	zclose(exit_fd);
	zclose(chunk_handoff_efd);
	return err;
}

/* Stop worker thread */
static void stop_worker_thread(void)
{
	int ret;

	if ((use_pthread && worker_pthread == 0) || (!use_pthread && inj_tid < 0)) {
		elog("No worker thread to stop...\n");
		return;
	}

	vlog("Signaling worker thread to exit...\n");

	if (exit_fd < 0) {
		elog("No exit signaling eventfd, exiting.\n");
		return;
	}

	poke_eventfd(exit_fd);	/* signal the worker thread to exit */

	vlog("Waiting for worker thread to exit...\n");

	if (use_pthread) {
		void *worker_retval;

		vlog("Waiting for pthread_join() to return...\n");
		ret = inj_pthread_join(worker_pthread, &worker_retval);
		if (ret)
			elog("pthread_join() returned error: %d (errno %d)\n", ret, errno);

	} else {
		vlog("Waiting for futex_wait() to return...\n");

		/* wait for worker thread to exit fully */
		while (*(volatile pid_t *)&worker_tid == inj_tid)
			syscall(SYS_futex, &worker_tid, FUTEX_WAIT, inj_tid, NULL, NULL, 0);

		/* now it's safe to munmap() thread's stack */
		if (stack) {
			(void)munmap(stack, WORKER_STACK_SIZE);
			stack = NULL;
		}
	}

	vlog("Worker thread teardown is complete.\n");
	inj_tid = -1;
	worker_pthread = 0;
}

/*
 * Runs in a forked child, before it returns from fork(). We never capture in
 * forked children: they share the parent's dump fds (one open file description)
 * and inherit copies of its stdio buffers, so any flush -- the child's own or
 * libc's flush of the inherited buffer at child exit -- would corrupt the
 * parent's capture. Manual close-on-fork: redirect every live dump fd to
 * /dev/null (the parent keeps its own fds, so it is unaffected). Also forget the
 * worker thread, which is not inherited across fork, so the destructor's
 * stop_worker_thread() no-ops instead of signaling the parent's worker through
 * the shared eventfd or hanging on the clone futex. Only async-signal-safe
 * operations are allowed here. (A child can still inherit torch_lock held and
 * deadlock on its first RecordFunction op -- child-only, no parent corruption.)
 */
static void inj_atfork_child(void)
{
	int n = __atomic_load_n(&inj_dump_fd_cnt, __ATOMIC_ACQUIRE);
	int null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);

	for (int i = 0; i < n; i++) {
		if (null_fd >= 0)
			dup2(null_fd, inj_dump_fds[i]);
		else
			close(inj_dump_fds[i]);
	}
	if (null_fd >= 0)
		close(null_fd);

	worker_pthread = 0;
	inj_tid = -1;
}

/*
 * Declared here to avoid pulling in all of <pthread.h>. Called at link time (not
 * via dlsym) on purpose: glibc ties the handler to this DSO's __dso_handle and
 * auto-unregisters it when libwprofinj.so is dlclose()'d at retract, so the
 * handler can't dangle and crash the tracee on a later fork(). The libc_nonshared
 * stub only needs __register_atfork (in libc), so this adds no libpthread dep.
 */
extern int pthread_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void));

__attribute__((constructor))
void libwprofinj_init()
{
	vlog("======= CONSTRUCTOR ======\n");

	if (pthread_atfork(NULL, NULL, inj_atfork_child) != 0)
		elog("Failed to register atfork handler; forked children may corrupt the capture\n");
}

struct inj_setup_ctx *LIBWPROFINJ_SETUP_SYM(struct inj_setup_ctx *ctx)
{
	/*
	 * If we already went through the setup step, let caller know where
	 * out setup context is located (most probably for cleanup after
	 * unclean injection)
	 */
	if (setup_ctx) {
		elog("Setup called more than once! old_setup_ctx %p new_setup_ctx %p\n", setup_ctx, ctx);
		return setup_ctx;
	}

	setup_ctx = ctx;

	zclose(setup_ctx->uds_parent_fd);

	stderr_verbosity = ctx->stderr_verbosity;
	filelog_verbosity = ctx->filelog_verbosity;

	int err = start_worker_thread();
	if (err) {
		zclose(setup_ctx->uds_fd);
		elog("Failed to start worker thread!\n");
		return NULL;
	}

	vlog("Setup completed.\n");
	return setup_ctx;
}

__attribute__((destructor))
void libwprofinj_fini()
{
	vlog("======= DESTRUCTOR STARTED ======\n");

	stop_worker_thread();

	vlog("======= DESTRUCTOR FINISHED ======\n");
}

