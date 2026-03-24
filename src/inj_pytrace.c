// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "inj.h"
#include "inj_common.h"
#include "pytrace_data.h"
#include "strset.h"
#include "hashmap.h"

/* Python C API type stubs -- opaque pointers, we only need them for signatures */
typedef void PyObject;
typedef void PyFrameObject;
typedef void PyCodeObject;
typedef void PyThreadState;
typedef void PyInterpreterState;

/* GIL state */
typedef int PyGILState_STATE;

/* Py_tracefunc signature: int callback(PyObject *obj, PyFrameObject *frame, int what, PyObject *arg) */
typedef int (*Py_tracefunc)(PyObject *, PyFrameObject *, int, PyObject *);

/* PyTrace_* constants (from cpython/pystate.h) */
#define PYTRACE_CALL    0
#define PYTRACE_RETURN  3

/* Python C API function pointers */
static void (*py_eval_set_profile)(Py_tracefunc, PyObject *);
static PyGILState_STATE (*py_gilstate_ensure)(void);
static void (*py_gilstate_release)(PyGILState_STATE);
static PyCodeObject *(*py_frame_getcode)(PyFrameObject *);
static int (*py_frame_getlineno)(PyFrameObject *);
static const char *(*py_unicode_asutf8)(PyObject *);
static PyInterpreterState *(*py_interp_head)(void);
static PyThreadState *(*py_interp_threadhead)(PyInterpreterState *);
static PyThreadState *(*py_threadstate_next)(PyThreadState *);
static PyThreadState *(*py_threadstate_swap)(PyThreadState *);
static void (*py_decref)(PyObject *);
static int (*py_is_initialized)(void);
static PyObject *(*py_getattr_string)(PyObject *, const char *);
static long (*py_long_aslong)(PyObject *);
/* Optional: 3.12+ bulk profiler install */
static void (*py_eval_set_profile_all_threads)(Py_tracefunc, PyObject *);

static void *pytrace_resolve_syms[PYTRACE_SYM_CNT] = {
	&py_eval_set_profile,
	&py_gilstate_ensure,
	&py_gilstate_release,
	&py_frame_getcode,
	&py_frame_getlineno,
	&py_unicode_asutf8,
	&py_interp_head,
	&py_interp_threadhead,
	&py_threadstate_next,
	&py_threadstate_swap,
	&py_decref,
	&py_is_initialized,
	&py_getattr_string,
	&py_long_aslong,
	&py_eval_set_profile_all_threads,
};

/* Session state */
static int py_version_minor;
static bool pytrace_active;

/* Dump file state */
#define PYTRACE_DUMP_BUF_SZ (256 * 1024)
static FILE *pytrace_dump;
static u64 pytrace_event_cnt;

#ifdef DEBUG
#define MAX_TRACED_THREADS 64
#define PYTRACE_TYPE_CNT 7  /* CALL=0, EXCEPTION=1, LINE=2, RETURN=3, C_CALL=4, C_EXCEPTION=5, C_RETURN=6 */
static struct {
	u32 tid;
	u64 counts[PYTRACE_TYPE_CNT];
} pytrace_thread_stats[MAX_TRACED_THREADS];
static int pytrace_thread_stats_cnt;
#endif

#define PYTRACE_DUMP_MAX_STRS_SZ (256 * 1024 * 1024)
struct strset *pytrace_dump_strs;

/* Code object cache: PyCodeObject* -> cached info */
struct pytrace_code_info {
	u32 func_name_off;	/* offset into pytrace_dump_strs */
	u32 file_name_off;	/* offset into pytrace_dump_strs */
	u32 lineno;
};

static struct hashmap *pytrace_code_cache;
static struct pytrace_code_info *pytrace_code_entries;
static u64 *pytrace_code_keys;
static u32 pytrace_code_cnt;
static u32 pytrace_code_cap;

static size_t pytrace_code_hash_fn(long key, void *ctx)
{
	/* Hash pointer value directly */
	u64 k = (u64)key;
	return k ^ (k >> 16) ^ (k >> 32);
}

static bool pytrace_code_equal_fn(long a, long b, void *ctx)
{
	return a == b;
}

/*
 * Extract function info from a PyCodeObject, with version-specific handling.
 * Returns the code_info index (into pytrace_code_entries).
 */
static u32 pytrace_cache_code(u64 code_key, PyCodeObject *code)
{
	long idx;

	if (hashmap__find(pytrace_code_cache, (long)code_key, &idx))
		return (u32)idx;

	/* First encounter: extract strings from the code object */
	const char *func_name = NULL;
	const char *file_name = NULL;
	int lineno = 0;

	/*
	 * co_qualname is available in 3.11+. In 3.10, fall back to co_name.
	 * Both are PyUnicodeObject fields on the code object.
	 *
	 * For name extraction, we peek at the code object's fields directly.
	 * PyCodeObject layout has co_name and co_filename as PyObject* members.
	 * We resolve them based on Python version.
	 */

	/*
	 * Use the frame's code object fields. In CPython, PyCodeObject has:
	 * - co_filename (all versions)
	 * - co_name (all versions)
	 * - co_qualname (3.11+)
	 * - co_firstlineno (all versions)
	 *
	 * We access these by resolving co_qualname/co_name/co_filename as
	 * PyObject* attributes. Since we have the code object, we use
	 * public accessors where available, otherwise struct field access.
	 */

	PyObject *name_obj = NULL;
	PyObject *file_obj = NULL;

	/* Try co_qualname first (3.11+), fall back to co_name */
	if (py_version_minor >= 11) {
		name_obj = py_getattr_string(code, "co_qualname");
		if (name_obj) {
			func_name = py_unicode_asutf8(name_obj);
			py_decref(name_obj);
		}
	}
	if (!func_name) {
		name_obj = py_getattr_string(code, "co_name");
		if (name_obj) {
			func_name = py_unicode_asutf8(name_obj);
			py_decref(name_obj);
		}
	}

	file_obj = py_getattr_string(code, "co_filename");
	if (file_obj) {
		file_name = py_unicode_asutf8(file_obj);
		py_decref(file_obj);
	}

	PyObject *lineno_obj = py_getattr_string(code, "co_firstlineno");
	if (lineno_obj) {
		lineno = (int)py_long_aslong(lineno_obj);
		py_decref(lineno_obj);
	}

	if (!func_name)
		func_name = "<unknown>";
	if (!file_name)
		file_name = "<unknown>";

	/* Grow entries array if needed */
	if (pytrace_code_cnt >= pytrace_code_cap) {
		u32 new_cap = pytrace_code_cap ? pytrace_code_cap * 3 / 2 : 1024;
		pytrace_code_entries = realloc(pytrace_code_entries, new_cap * sizeof(*pytrace_code_entries));
		pytrace_code_keys = realloc(pytrace_code_keys, new_cap * sizeof(*pytrace_code_keys));
		pytrace_code_cap = new_cap;
	}

	idx = pytrace_code_cnt;
	pytrace_code_keys[idx] = code_key;
	pytrace_code_entries[idx].func_name_off = strset__add_str(pytrace_dump_strs, func_name);
	pytrace_code_entries[idx].file_name_off = strset__add_str(pytrace_dump_strs, file_name);
	pytrace_code_entries[idx].lineno = lineno;
	pytrace_code_cnt++;

	hashmap__add(pytrace_code_cache, (long)code_key, idx);

	return (u32)idx;
}

/*
 * The profiling callback installed via PyEval_SetProfile.
 * Called on every function call/return. Must be extremely fast.
 */
static int pytrace_profile_callback(PyObject *obj, PyFrameObject *frame, int what, PyObject *arg)
{
	if (!pytrace_active)
		return 0;

	/* Minimize skew with other collectors (e.g. cuda) */
	if (!run_ctx->sess_start_ts)
		return 0;

	u64 ts = ktime_now_ns();
	u32 tid = (u32)syscall(SYS_gettid);

#ifdef DEBUG
	/* Count events by (tid, type) for debugging */
	int si;
	for (si = 0; si < pytrace_thread_stats_cnt; si++) {
		if (pytrace_thread_stats[si].tid == tid)
			break;
	}
	if (si == pytrace_thread_stats_cnt && si < MAX_TRACED_THREADS) {
		pytrace_thread_stats[si].tid = tid;
		pytrace_thread_stats_cnt++;
	}
	if (si < MAX_TRACED_THREADS && what < PYTRACE_TYPE_CNT)
		pytrace_thread_stats[si].counts[what]++;
#endif

	bool is_tracked = (what == PYTRACE_CALL || what == PYTRACE_RETURN);
	if (!is_tracked)
		return 0;

	/* Get the code object for this frame */
	PyCodeObject *code = py_frame_getcode(frame);
	u64 code_key = (u64)code;

	/* Cache the code object info (extracts strings only on first encounter) */
	pytrace_cache_code(code_key, code);

	/* In 3.11+, PyFrame_GetCode returns a new reference */
	if (py_version_minor >= 11)
		py_decref(code);

	/* Record the raw event */
	struct wpytrace_event ev = {
		.ts = ts,
		.tid = tid,
		.what = (u8)what,
		.code_key = code_key,
	};

	if (fwrite(&ev, sizeof(ev), 1, pytrace_dump) != 1) {
		elog("Failed to write pytrace event: %d\n", -errno);
		return 0;
	}

	pytrace_event_cnt++;
	return 0;
}

static void init_wpytrace_header(struct wpytrace_data_hdr *hdr)
{
	memset(hdr, 0, sizeof(*hdr));
	memcpy(hdr->magic, "WPYFUNC", 8);
	hdr->hdr_sz = sizeof(*hdr);
}

static int init_wpytrace_data(FILE *dump)
{
	int err;

	err = fseek(dump, 0, SEEK_SET);
	if (err) {
		err = -errno;
		elog("Failed to fseek(0) pytrace data dump: %d\n", err);
		return err;
	}

	struct wpytrace_data_hdr hdr;
	init_wpytrace_header(&hdr);
	hdr.flags = WPYTRACE_DATA_FLAG_INCOMPLETE;

	if (fwrite(&hdr, sizeof(hdr), 1, dump) != 1) {
		err = -errno;
		elog("Failed to fwrite() pytrace data dump header: %d\n", err);
		return err;
	}

	fflush(dump);
	fsync(fileno(dump));
	return 0;
}

int pytrace_session_setup(int dump_fd, int version_minor, unsigned long *sym_addrs)
{
	int err = 0;

	py_version_minor = version_minor;
	vlog("Setting up pytrace session (Python 3.%d)...\n", py_version_minor);

	/* Assign Python C API function pointers from host-resolved addresses */
	for (int i = 0; i < PYTRACE_SYM_CNT; i++) {
		*(void **)pytrace_resolve_syms[i] = (void *)sym_addrs[i];
		if (sym_addrs[i])
			vlog("  %s = %p\n", pytrace_sym_names[i], (void *)sym_addrs[i]);
	}

	/* Set up dump file */
	pytrace_dump_strs = strset__new(PYTRACE_DUMP_MAX_STRS_SZ, "", 1);
	if (!pytrace_dump_strs) {
		elog("Failed to create pytrace string set\n");
		return -ENOMEM;
	}

	pytrace_dump = fdopen(dump_fd, "w");
	if (!pytrace_dump) {
		err = -errno;
		elog("Failed to create FILE wrapper around pytrace dump FD %d: %d\n", dump_fd, err);
		goto cleanup;
	}
	setvbuf(pytrace_dump, NULL, _IOFBF, PYTRACE_DUMP_BUF_SZ);

	if ((err = init_wpytrace_data(pytrace_dump)) < 0) {
		elog("Failed to init pytrace dump: %d\n", err);
		goto cleanup;
	}

	/* Initialize code object cache */
	pytrace_code_cache = hashmap__new(pytrace_code_hash_fn, pytrace_code_equal_fn, NULL);
	if (!pytrace_code_cache) {
		err = -ENOMEM;
		elog("Failed to create pytrace code cache\n");
		goto cleanup;
	}

	/* Install profiler on all Python threads */
	if (!py_is_initialized()) {
		elog("Python interpreter not initialized, skipping pytrace\n");
		err = -ENOENT;
		goto cleanup;
	}

	pytrace_active = true;

	PyGILState_STATE gstate = py_gilstate_ensure();

	PyInterpreterState *interp = py_interp_head();
	if (!interp) {
		elog("No Python interpreter found!\n");
		py_gilstate_release(gstate);
		err = -ENOENT;
		goto cleanup;
	}

	int thread_cnt = 0;

	if (py_eval_set_profile_all_threads) {
		/* 3.12+: install on all threads in one call */
		py_eval_set_profile_all_threads(pytrace_profile_callback, NULL);
		for (PyThreadState *ts = py_interp_threadhead(interp); ts; ts = py_threadstate_next(ts))
			thread_cnt++;
		vlog("pytrace profiler installed on all threads via PyEval_SetProfileAllThreads\n");
	} else {
		/*
		 * Pre-3.12: swap to each thread state and install individually.
		 * PyEval_SetProfile installs on the "current" thread state, so we
		 * must swap to each real Python thread's state to install on it.
		 */
		PyThreadState *saved = py_threadstate_swap(NULL);

		for (PyThreadState *ts = py_interp_threadhead(interp); ts; ts = py_threadstate_next(ts)) {
			py_threadstate_swap(ts);
			py_eval_set_profile(pytrace_profile_callback, NULL);
			thread_cnt++;
		}

		py_threadstate_swap(saved);
		vlog("pytrace profiler installed on %d threads via PyThreadState_Swap\n", thread_cnt);
	}

	py_gilstate_release(gstate);

	vlog("pytrace session ready: profiler active on %d Python thread(s)\n", thread_cnt);


	return 0;

cleanup:
	pytrace_active = false;
	if (pytrace_code_cache) {
		hashmap__free(pytrace_code_cache);
		pytrace_code_cache = NULL;
	}
	strset__free(pytrace_dump_strs);
	pytrace_dump_strs = NULL;
	if (pytrace_dump) {
		fclose(pytrace_dump);
		pytrace_dump = NULL;
	} else {
		zclose(dump_fd);
	}
	return err;
}

int pytrace_session_finalize(void)
{
	int err = 0;

	if (!pytrace_dump)
		return 0;

	/* Uninstall profiler */
	pytrace_active = false;

	PyGILState_STATE gstate = py_gilstate_ensure();

	if (py_eval_set_profile_all_threads) {
		py_eval_set_profile_all_threads(NULL, NULL);
	} else {
		PyInterpreterState *interp = py_interp_head();
		if (interp) {
			PyThreadState *saved = py_threadstate_swap(NULL);
			for (PyThreadState *ts = py_interp_threadhead(interp); ts; ts = py_threadstate_next(ts)) {
				py_threadstate_swap(ts);
				py_eval_set_profile(NULL, NULL);
			}
			py_threadstate_swap(saved);
		}
	}

	py_gilstate_release(gstate);

	fflush(pytrace_dump);

	long events_end = ftell(pytrace_dump);
	if (events_end < 0) {
		err = -errno;
		elog("Failed to get pytrace dump file position: %d\n", err);
		return err;
	}

	/* Write code object map */
	long code_map_off = events_end - sizeof(struct wpytrace_data_hdr);
	for (u32 i = 0; i < pytrace_code_cnt; i++) {
		struct wpytrace_code_entry entry = {
			.code_key = pytrace_code_keys[i],
			.func_name_off = pytrace_code_entries[i].func_name_off,
			.file_name_off = pytrace_code_entries[i].file_name_off,
			.lineno = pytrace_code_entries[i].lineno,
		};
		if (fwrite(&entry, sizeof(entry), 1, pytrace_dump) != 1) {
			err = -errno;
			elog("Failed to write pytrace code map entry: %d\n", err);
			return err;
		}
	}
	long code_map_sz = pytrace_code_cnt * sizeof(struct wpytrace_code_entry);

	/* Write string table */
	const char *strs = strset__data(pytrace_dump_strs);
	size_t strs_sz = strset__data_size(pytrace_dump_strs);

	long strs_off = ftell(pytrace_dump) - sizeof(struct wpytrace_data_hdr);
	if (strs_sz > 0 && fwrite(strs, 1, strs_sz, pytrace_dump) != strs_sz) {
		err = -errno;
		elog("Failed to write pytrace strings: %d\n", err);
		return err;
	}

	fsync(fileno(pytrace_dump));

	/* Finalize header */
	struct wpytrace_data_hdr hdr;
	init_wpytrace_header(&hdr);

	hdr.sess_start_ns = run_ctx->sess_start_ts;
	hdr.sess_end_ns = run_ctx->sess_end_ts;
	hdr.events_off = 0;
	hdr.events_sz = events_end - sizeof(struct wpytrace_data_hdr);
	hdr.event_cnt = pytrace_event_cnt;
	hdr.code_map_off = code_map_off;
	hdr.code_map_sz = code_map_sz;
	hdr.code_map_cnt = pytrace_code_cnt;
	hdr.strs_off = strs_off;
	hdr.strs_sz = strs_sz;

	err = fseek(pytrace_dump, 0, SEEK_SET);
	if (err) {
		err = -errno;
		elog("Failed to fseek(0) pytrace dump: %d\n", err);
		return err;
	}

	if (fwrite(&hdr, sizeof(hdr), 1, pytrace_dump) != 1) {
		err = -errno;
		elog("Failed to fwrite() pytrace dump header: %d\n", err);
		return err;
	}

	fflush(pytrace_dump);
	fsync(fileno(pytrace_dump));

	/* Update run_ctx stats */
	if (run_ctx) {
		run_ctx->pytrace_event_cnt = pytrace_event_cnt;
		run_ctx->pytrace_code_cache_cnt = pytrace_code_cnt;
	}

#ifdef DEBUG
	static const char *pytrace_names[] = {"CALL", "EXCEPTION", "LINE", "RETURN", "C_CALL", "C_EXCEPTION", "C_RETURN"};
	for (int i = 0; i < pytrace_thread_stats_cnt; i++) {
		char buf[256];
		int off = snprintf(buf, sizeof(buf), "pytrace tid %u:", pytrace_thread_stats[i].tid);
		for (int j = 0; j < PYTRACE_TYPE_CNT; j++) {
			if (pytrace_thread_stats[i].counts[j])
				off += snprintf(buf + off, sizeof(buf) - off, " %s=%llu",
						pytrace_names[j], (unsigned long long)pytrace_thread_stats[i].counts[j]);
		}
		vlog("%s\n", buf);
	}
#endif

	vlog("pytrace session finalized: %llu events, %u code objects, %zu string bytes\n",
	     pytrace_event_cnt, pytrace_code_cnt, strs_sz);

	fclose(pytrace_dump);
	pytrace_dump = NULL;

	/* Cleanup */
	hashmap__free(pytrace_code_cache);
	pytrace_code_cache = NULL;
	free(pytrace_code_entries);
	pytrace_code_entries = NULL;
	free(pytrace_code_keys);
	pytrace_code_keys = NULL;
	pytrace_code_cnt = 0;
	pytrace_code_cap = 0;
	strset__free(pytrace_dump_strs);
	pytrace_dump_strs = NULL;

	return 0;
}
