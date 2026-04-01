// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <pthread.h>

#include "inj.h"
#include "pytrace_data.h"
#include "strset.h"

/* ==================== RecordFunction hooking ====================
 *
 * PyTorch's RecordFunction callback system lets us capture ops on autograd
 * threads (pt_autograd_0, etc.) which never execute Python code and thus
 * can't be reached via PyEval_SetProfile.
 *
 * We resolve the C++ API symbols from libtorch_cpu.so via their mangled names
 * and construct the RecordFunctionCallback struct manually to match the ABI.
 */

/* Dump file state (own, not shared with inj_pytrace.c) */
#define TORCH_DUMP_BUF_SZ (256 * 1024)
#define TORCH_DUMP_MAX_STRS_SZ (16 * 1024 * 1024)

static FILE *torch_dump;
static struct strset *torch_dump_strs;
static u64 torch_event_cnt;

static bool torch_active;
static pthread_mutex_t torch_lock;

/* RecordFunction C++ API — resolved via dlsym with mangled names */
static const char *(*rf_name)(const void *record_fn);
static void (*rf_remove_callback)(u64 handle);

/*
 * addGlobalCallback takes a 40-byte RecordFunctionCallback struct by value.
 * On x86_64, structs >16 bytes are passed on the stack. On aarch64, they're
 * passed by indirect reference (pointer in x0). In both cases the C compiler
 * generates the correct calling convention automatically when we call through
 * a function pointer typed to take the struct by value.
 */
static void *rf_add_global_callback_ptr;

static u64 rf_callback_handle;
static bool rf_active;

/*
 * RecordFunction start callback (C ABI matching C++ hidden-return-pointer convention).
 *
 * C++ signature: std::unique_ptr<ObserverContext> (*)(const RecordFunction&)
 * The hidden return pointer for non-trivial return types is passed differently:
 *   x86_64:  rdi (1st param reg) = ret_slot, rsi (2nd) = record_fn
 *   aarch64: x8 (dedicated reg) = ret_slot, x0 (1st param reg) = record_fn
 *
 * On x86_64 we can map ret_slot to the first C parameter directly.
 * On aarch64 we need a naked thunk to shuffle x8→x0 and x0→x1.
 */
#if defined(__aarch64__)
/*
 * aarch64 thunk: the C++ caller passes x8=ret_slot, x0=record_fn.
 * Shuffle to match rf_start_cb_impl(x0=ret_slot, x1=record_fn).
 * Top-level asm avoids GCC ignoring __attribute__((naked)) in some versions.
 */
__attribute__((visibility("hidden")))
void *rf_start_cb_impl(void *ret_slot, const void *record_fn);

__asm__(
	".type rf_start_cb, %function\n"
	"rf_start_cb:\n"
	"mov x1, x0\n"
	"mov x0, x8\n"
	"b rf_start_cb_impl\n"
	".size rf_start_cb, .-rf_start_cb\n"
);

/* Declare the asm-defined symbol so C code can reference it */
extern void *rf_start_cb();

__attribute__((visibility("hidden")))
void *rf_start_cb_impl(void *ret_slot, const void *record_fn)
#else
static void *rf_start_cb(void *ret_slot, const void *record_fn)
#endif
{
	if (!torch_active || !torch_dump) {
		*(void **)ret_slot = NULL;
		return ret_slot;
	}
	if (!run_ctx->sess_start_ts) {
		*(void **)ret_slot = NULL;
		return ret_slot;
	}

	u64 ts = ktime_now_ns();
	u32 tid = (u32)syscall(SYS_gettid);
	const char *name = rf_name ? rf_name(record_fn) : "?";

	pthread_mutex_lock(&torch_lock);
	u32 name_off = strset__add_str(torch_dump_strs, name);
	pthread_mutex_unlock(&torch_lock);

	struct wpytrace_event ev = {
		.ts = ts,
		.tid = tid,
		.what = WPYTRACE_PYTORCH_ENTRY,
		.code_key = 0,
		.rf_name_off = name_off,
	};

	if (fwrite(&ev, sizeof(ev), 1, torch_dump) == 1)
		atomic_add(&torch_event_cnt, 1);

	*(void **)ret_slot = NULL;
	return ret_slot;
}

/*
 * RecordFunction end callback.
 * C++ signature: void (*)(const RecordFunction&, ObserverContext*)
 * Void return, two pointer args — trivially portable across ABIs.
 */
static void rf_end_cb(const void *record_fn, void *ctx)
{
	if (!torch_active || !torch_dump)
		return;
	if (!run_ctx->sess_start_ts)
		return;

	u64 ts = ktime_now_ns();
	u32 tid = (u32)syscall(SYS_gettid);

	struct wpytrace_event ev = {
		.ts = ts,
		.tid = tid,
		.what = WPYTRACE_PYTORCH_EXIT,
		.code_key = 0,
		.rf_name_off = 0,
	};

	if (fwrite(&ev, sizeof(ev), 1, torch_dump) == 1)
		atomic_add(&torch_event_cnt, 1);
}

/*
 * Call addGlobalCallback with a 40-byte struct passed by value.
 *
 * The C compiler handles the platform-specific calling convention for passing
 * a 40-byte struct by value (stack on x86_64, indirect reference on aarch64).
 * We cast the resolved symbol to a function pointer typed to take the struct
 * by value, and the compiler does the rest.
 */

/* We define a wrapper struct that exactly matches the C++ layout */
struct rf_callback_struct {
	void *start;        /* 0  */
	void *end;          /* 8  */
	double prob;        /* 16 */
	bool scopes[10];    /* 24 */
	bool needs_inputs;  /* 34 */
	bool needs_outputs; /* 35 */
	bool needs_ids;     /* 36 */
	u8 pad[3];          /* 37-39 */
} __attribute__((packed));

_Static_assert(sizeof(struct rf_callback_struct) == 40,
	       "rf_callback_struct must be 40 bytes");

typedef u64 (*rf_add_cb_fn_t)(struct rf_callback_struct cb);

static u64 rf_call_add_global_callback(const struct rf_callback_struct *cb)
{
	rf_add_cb_fn_t fn = (rf_add_cb_fn_t)rf_add_global_callback_ptr;
	return fn(*cb);
}

/* RecordScope enum values from ATen/record_function.h */
#define RF_SCOPE_FUNCTION          0
#define RF_SCOPE_BACKWARD_FUNCTION 1
#define RF_SCOPE_USER_SCOPE        7
#define RF_SCOPE_COUNT             10

static void rf_register(void)
{
	struct rf_callback_struct cb = {
		.start = (void *)rf_start_cb,
		.end = (void *)rf_end_cb,
		.prob = 1.0,
		.scopes = { [RF_SCOPE_FUNCTION] = true, [RF_SCOPE_BACKWARD_FUNCTION] = true, [RF_SCOPE_USER_SCOPE] = true },
	};

	rf_callback_handle = rf_call_add_global_callback(&cb);
	rf_active = true;

	vlog("RecordFunction callback registered (handle=%llu)\n", (unsigned long long)rf_callback_handle);
}

static void rf_unregister(void)
{
	if (!rf_active)
		return;

	if (rf_remove_callback) {
		rf_remove_callback(rf_callback_handle);
		vlog("RecordFunction callback unregistered (handle=%llu)\n",
		     (unsigned long long)rf_callback_handle);
	}

	rf_active = false;
}

static int verify_mutex_symbols(void)
{
	const char *syms[] = {
		"pthread_mutex_init",
		"pthread_mutex_lock",
		"pthread_mutex_unlock",
		"pthread_mutex_destroy"
	};

	for (int i = 0; i < ARRAY_SIZE(syms); i++) {
		if (!dlsym(RTLD_DEFAULT, syms[i])) {
			elog("%s not available in tracee\n", syms[i]);
			return -ENOENT;
		}
	}
	return 0;
}

static int rf_resolve_symbols(void)
{
	/*
	 * libtorch_cpu.so is loaded by Python's import machinery with RTLD_LOCAL,
	 * so its C++ symbols aren't visible via RTLD_DEFAULT. We need to get a
	 * handle to the already-loaded library using RTLD_NOLOAD.
	 */
	void *torch_handle = dlopen("libtorch_cpu.so", RTLD_NOLOAD | RTLD_LAZY);
	if (!torch_handle) {
		vlog("dlopen(libtorch_cpu.so, NOLOAD) failed: %s\n", dlerror());
		return -ENOENT;
	}

	vlog("Got handle to libtorch_cpu.so at %p\n", torch_handle);

	rf_add_global_callback_ptr = dlsym(torch_handle,
		"_ZN2at17addGlobalCallbackENS_22RecordFunctionCallbackE");
	rf_remove_callback = dlsym(torch_handle, "_ZN2at14removeCallbackEm");
	rf_name = dlsym(torch_handle, "_ZNK2at14RecordFunction4nameEv");

	if (rf_add_global_callback_ptr)
		vlog("Resolved at::addGlobalCallback at %p\n", rf_add_global_callback_ptr);
	if (rf_remove_callback)
		vlog("Resolved at::removeCallback at %p\n", (void *)rf_remove_callback);
	if (rf_name)
		vlog("Resolved at::RecordFunction::name at %p\n", (void *)rf_name);

	dlclose(torch_handle);

	return rf_add_global_callback_ptr && rf_remove_callback && rf_name ? 0 : -ENOENT;
}

/* ==================== Dump file management ==================== */

static void init_wpytrace_header(struct wpytrace_data_hdr *hdr)
{
	memset(hdr, 0, sizeof(*hdr));
	memcpy(hdr->magic, "WPYTR", 6);
	hdr->hdr_sz = sizeof(*hdr);
}

static int init_torch_data(FILE *dump)
{
	int err;

	err = fseek(dump, 0, SEEK_SET);
	if (err) {
		err = -errno;
		elog("Failed to fseek(0) torch data dump: %d\n", err);
		return err;
	}

	struct wpytrace_data_hdr hdr;
	init_wpytrace_header(&hdr);
	hdr.flags = WPYTRACE_DATA_FLAG_INCOMPLETE;

	if (fwrite(&hdr, sizeof(hdr), 1, dump) != 1) {
		err = -errno;
		elog("Failed to fwrite() torch data dump header: %d\n", err);
		return err;
	}

	fflush(dump);
	fsync(fileno(dump));
	return 0;
}

/* ==================== Public API ==================== */

int torch_profiler_setup(int dump_fd)
{
	int err = 0;

	torch_dump_strs = strset__new(TORCH_DUMP_MAX_STRS_SZ, "", 1);
	if (!torch_dump_strs) {
		elog("Failed to create torch string set\n");
		return -ENOMEM;
	}

	torch_dump = fdopen(dump_fd, "w");
	if (!torch_dump) {
		err = -errno;
		elog("Failed to create FILE wrapper around torch dump FD %d: %d\n", dump_fd, err);
		goto cleanup;
	}
	setvbuf(torch_dump, NULL, _IOFBF, TORCH_DUMP_BUF_SZ);

	if ((err = init_torch_data(torch_dump)) < 0) {
		elog("Failed to init torch dump: %d\n", err);
		goto cleanup;
	}

	if ((err = rf_resolve_symbols()) < 0) {
		elog("Failed to resolve PyTorch record function symbols");
		goto cleanup;
	}

	if ((err = verify_mutex_symbols()) < 0)
		goto cleanup;

	torch_active = true;
	pthread_mutex_init(&torch_lock, NULL);
	rf_register();

	return 0;

cleanup:
	torch_active = false;
	strset__free(torch_dump_strs);
	torch_dump_strs = NULL;
	if (torch_dump) {
		fclose(torch_dump);
		torch_dump = NULL;
	} else {
		zclose(dump_fd);
	}
	return err;
}

int torch_profiler_teardown(void)
{
	int err = 0;

	if (!torch_dump)
		return 0;

	rf_unregister();
	torch_active = false;
	pthread_mutex_destroy(&torch_lock);

	fflush(torch_dump);

	long events_end = ftell(torch_dump);
	if (events_end < 0) {
		err = -errno;
		elog("Failed to get torch dump file position: %d\n", err);
		return err;
	}

	/*
	 * Torch dumps have no code_map (that's pytrace-only), so write
	 * code_map_off/sz/cnt as zero and go straight to the string table.
	 */

	/* Write string table */
	const char *strs = strset__data(torch_dump_strs);
	size_t strs_sz = strset__data_size(torch_dump_strs);

	long strs_off = ftell(torch_dump) - sizeof(struct wpytrace_data_hdr);
	if (strs_sz > 0 && fwrite(strs, 1, strs_sz, torch_dump) != strs_sz) {
		err = -errno;
		elog("Failed to write torch strings: %d\n", err);
		return err;
	}

	fsync(fileno(torch_dump));

	/* Finalize header */
	struct wpytrace_data_hdr hdr;
	init_wpytrace_header(&hdr);

	hdr.sess_start_ns = run_ctx->sess_start_ts;
	hdr.sess_end_ns = run_ctx->sess_end_ts;
	hdr.events_off = 0;
	hdr.events_sz = events_end - sizeof(struct wpytrace_data_hdr);
	hdr.event_cnt = torch_event_cnt;
	hdr.code_map_off = 0;
	hdr.code_map_sz = 0;
	hdr.code_map_cnt = 0;
	hdr.strs_off = strs_off;
	hdr.strs_sz = strs_sz;

	err = fseek(torch_dump, 0, SEEK_SET);
	if (err) {
		err = -errno;
		elog("Failed to fseek(0) torch dump: %d\n", err);
		return err;
	}

	if (fwrite(&hdr, sizeof(hdr), 1, torch_dump) != 1) {
		err = -errno;
		elog("Failed to fwrite() torch dump header: %d\n", err);
		return err;
	}

	fflush(torch_dump);
	fsync(fileno(torch_dump));

	vlog("torch profiler finalized: %llu events, %zu string bytes\n",
	     torch_event_cnt, strs_sz);

	fclose(torch_dump);
	torch_dump = NULL;

	strset__free(torch_dump_strs);
	torch_dump_strs = NULL;

	return 0;
}
