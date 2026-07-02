// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>

#include "inj.h"
#include "pytorch_data.h"
#include "strset.h"
#include "strcache.h"

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

static struct chunker torch_chunker;	/* headerless event stream */
static FILE *torch_respool_dump;	/* resource pool (header + string pool), written at finalize */
static struct strset *torch_respool_strs;

static bool torch_active;
static pthread_mutex_t torch_lock;

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
/*
 * addGlobalCallback takes a 40-byte RecordFunctionCallback struct by value.
 * On x86_64, structs >16 bytes are passed on the stack. On aarch64, they're
 * passed by indirect reference (pointer in x0). In both cases the C compiler
 * generates the correct calling convention automatically when we call through
 * a function pointer typed to take the struct by value.
 *
 * RecordFunction C++ APIs — resolved before inject
 */
static u64 (*rf_add_global_callback)(struct rf_callback_struct cb);
static const char *(*rf_name)(const void *record_fn);
static void (*rf_remove_callback)(u64 handle);

static u64 rf_callback_handle;
static bool rf_active;

/*
 * Lock-free op-name interner (see strcache.h). RecordFunction fires on many
 * threads, so this keeps the common path -- an op name already interned -- off
 * torch_lock; only a name's first sighting takes the lock. Backed by
 * torch_respool_strs / torch_lock, wired up in pytorch_session_setup().
 */
static struct strcache torch_name_cache;

/*
 * RecordFunction start callback.
 *
 * C++ signature: std::unique_ptr<ObserverContext> (*)(const RecordFunction&)
 * The hidden return pointer for non-trivial return types is passed differently:
 *   x86_64:  rdi (1st param reg) = ret_slot, rsi (2nd) = record_fn
 *   aarch64: x8 (dedicated reg) = ret_slot, x0 (1st param reg) = record_fn
 *
 * On x86_64 the C ABI maps ret_slot to the first parameter directly.
 * On aarch64 the trampoline handles the x8→x0, x0→x1 shuffle before calling.
 */
static void *rf_start_cb(void *ret_slot, const void *record_fn)
{
	if (!torch_active || !torch_chunker.cur) {
		*(void **)ret_slot = NULL;
		return ret_slot;
	}
	if (!run_ctx->sess_start_ts) {
		*(void **)ret_slot = NULL;
		return ret_slot;
	}

	u64 ts = ktime_now_ns();
	u32 tid = inj_gettid();
	const char *name = rf_name(record_fn);
	u32 name_off = strcache_intern(&torch_name_cache, name);

	struct wpytorch_event ev = {
		.ts = ts,
		.tid = tid,
		.what = WPYTORCH_ENTRY,
		.name_off = name_off,
	};

	int err = chunker_write(&torch_chunker, &ev, sizeof(ev), ts);
	if (err)
		elog("Failed to write PyTorch event: %d\n", err);

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
	if (!torch_active || !torch_chunker.cur)
		return;
	if (!run_ctx->sess_start_ts)
		return;

	u64 ts = ktime_now_ns();
	u32 tid = inj_gettid();
	const char *name = rf_name(record_fn);
	u32 name_off = strcache_intern(&torch_name_cache, name);

	struct wpytorch_event ev = {
		.ts = ts,
		.tid = tid,
		.what = WPYTORCH_EXIT,
		.name_off = name_off,
	};

	int err = chunker_write(&torch_chunker, &ev, sizeof(ev), ts);
	if (err)
		elog("Failed to write PyTorch event: %d\n", err);
}

/* ==================== RecordFunction trampoline ====================
 *
 * Permanent trampoline that survives dlclose of libwprofinj.so.
 * PyTorch's RecordFunction caches callback pointers at construction time;
 * if those point directly into libwprofinj.so they dangle after dlclose.
 * The trampoline lives in mmap'd memory that is never freed.
 *
 * Critical ordering: refcount++ BEFORE loading the callback pointer.
 * This pairs with the retract side which stores NULL BEFORE checking
 * refcount, giving a total order that prevents use-after-unmap.
 */
struct rf_tramp_data {
	void *start_cb;		/* offset 0 */
	void *end_cb;		/* offset 8 */
	long refcount;		/* offset 16 */
};

#if defined(__aarch64__)
__asm__(
	".pushsection .trampoline, \"ax\", @progbits\n"
	".arch_extension lse\n"
	".globl rf_tramp_start\n"
	".hidden rf_tramp_start\n"
"rf_tramp_start:\n"

	/* start trampoline: x8=ret_slot, x0=record_fn (C++ hidden-return-ptr ABI) */
	".globl rf_tramp_rf_start\n"
	".hidden rf_tramp_rf_start\n"
	".type rf_tramp_rf_start, %function\n"
"rf_tramp_rf_start:\n"
	/* data = *data_ptr */
	"adr    x9, rf_tramp_data_ptr\n"
	"ldr    x9, [x9]\n"
	/* atomic_fetch_add(&data->refcount, 1, acq_rel) */
	"add    x11, x9, #16\n"
	"mov    x10, #1\n"
	"ldaddal x10, xzr, [x11]\n"
	/* cb = data->start_cb; if (!cb) goto bail */
	"ldr    x10, [x9]\n"
	"cbz    x10, 0f\n"
	/* save frame + data ptr; shuffle x8/x0 ABI; call rf_start_cb(ret_slot, record_fn) */
	"stp    x29, x30, [sp, #-32]!\n"
	"mov    x29, sp\n"
	"str    x9, [sp, #16]\n"
	"mov    x1, x0\n"
	"mov    x0, x8\n"
	"blr    x10\n"
	/* atomic_fetch_add(&data->refcount, -1, acq_rel); return */
	"ldr    x9, [sp, #16]\n"
	"add    x11, x9, #16\n"
	"mov    x10, #-1\n"
	"ldaddal x10, xzr, [x11]\n"
	"ldp    x29, x30, [sp], #32\n"
	"ret\n"
"0:\n"
	/* bail: refcount--; *ret_slot = NULL; return ret_slot */
	"mov    x10, #-1\n"
	"ldaddal x10, xzr, [x11]\n"
	"str    xzr, [x8]\n"
	"mov    x0, x8\n"
	"ret\n"
	".size rf_tramp_rf_start, .-rf_tramp_rf_start\n"

	/* end trampoline: x0=record_fn, x1=observer_ctx */
	".globl rf_tramp_rf_end\n"
	".hidden rf_tramp_rf_end\n"
	".type rf_tramp_rf_end, %function\n"
"rf_tramp_rf_end:\n"
	/* data = *data_ptr */
	"adr    x9, rf_tramp_data_ptr\n"
	"ldr    x9, [x9]\n"
	/* atomic_fetch_add(&data->refcount, 1, acq_rel) */
	"add    x11, x9, #16\n"
	"mov    x10, #1\n"
	"ldaddal x10, xzr, [x11]\n"
	/* cb = data->end_cb; if (!cb) goto bail */
	"ldr    x10, [x9, #8]\n"
	"cbz    x10, 0f\n"
	/* save frame + data ptr; call rf_end_cb(record_fn, observer_ctx) */
	"stp    x29, x30, [sp, #-32]!\n"
	"mov    x29, sp\n"
	"str    x9, [sp, #16]\n"
	"blr    x10\n"
	/* atomic_fetch_add(&data->refcount, -1, acq_rel); return */
	"ldr    x9, [sp, #16]\n"
	"add    x11, x9, #16\n"
	"mov    x10, #-1\n"
	"ldaddal x10, xzr, [x11]\n"
	"ldp    x29, x30, [sp], #32\n"
	"ret\n"
"0:\n"
	/* bail: refcount--; return */
	"mov    x10, #-1\n"
	"ldaddal x10, xzr, [x11]\n"
	"ret\n"
	".size rf_tramp_rf_end, .-rf_tramp_rf_end\n"

	".globl rf_tramp_data_ptr\n"
	".hidden rf_tramp_data_ptr\n"
"rf_tramp_data_ptr: .quad 0\n"
	".globl rf_tramp_end\n"
	".hidden rf_tramp_end\n"
"rf_tramp_end:\n"
	".popsection\n"
);
#elif defined(__x86_64__)
__asm__(
	".pushsection .trampoline, \"ax\", @progbits\n"
	".globl rf_tramp_start\n"
	".hidden rf_tramp_start\n"
"rf_tramp_start:\n"

	/* start trampoline: rdi=ret_slot, rsi=record_fn */
	".globl rf_tramp_rf_start\n"
	".hidden rf_tramp_rf_start\n"
	".type rf_tramp_rf_start, @function\n"
"rf_tramp_rf_start:\n"
	/* data = *data_ptr */
	"lea    rf_tramp_data_ptr(%rip), %rcx\n"
	"mov    (%rcx), %rcx\n"
	/* atomic refcount++ (lock = full barrier on x86) */
	"lock addq $1, 16(%rcx)\n"
	/* cb = data->start_cb; if (!cb) goto bail */
	"mov    (%rcx), %rax\n"
	"test   %rax, %rax\n"
	"jz     0f\n"
	/* save data ptr; call rf_start_cb(ret_slot, record_fn) */
	"push   %rcx\n"
	"call   *%rax\n"
	/* atomic refcount--; return (rax = return value from callback) */
	"pop    %rcx\n"
	"lock subq $1, 16(%rcx)\n"
	"ret\n"
"0:\n"
	/* bail: refcount--; *ret_slot = NULL; return ret_slot */
	"lock subq $1, 16(%rcx)\n"
	"movq   $0, (%rdi)\n"
	"mov    %rdi, %rax\n"
	"ret\n"
	".size rf_tramp_rf_start, .-rf_tramp_rf_start\n"

	/* end trampoline: rdi=record_fn, rsi=observer_ctx */
	".globl rf_tramp_rf_end\n"
	".hidden rf_tramp_rf_end\n"
	".type rf_tramp_rf_end, @function\n"
"rf_tramp_rf_end:\n"
	/* data = *data_ptr */
	"lea    rf_tramp_data_ptr(%rip), %rcx\n"
	"mov    (%rcx), %rcx\n"
	/* atomic refcount++ */
	"lock addq $1, 16(%rcx)\n"
	/* cb = data->end_cb; if (!cb) goto bail */
	"mov    8(%rcx), %rax\n"
	"test   %rax, %rax\n"
	"jz     0f\n"
	/* save data ptr; call rf_end_cb(record_fn, observer_ctx) */
	"push   %rcx\n"
	"call   *%rax\n"
	/* atomic refcount--; return */
	"pop    %rcx\n"
	"lock subq $1, 16(%rcx)\n"
	"ret\n"
"0:\n"
	/* bail: refcount--; return */
	"lock subq $1, 16(%rcx)\n"
	"ret\n"
	".size rf_tramp_rf_end, .-rf_tramp_rf_end\n"

	".globl rf_tramp_data_ptr\n"
	".hidden rf_tramp_data_ptr\n"
"rf_tramp_data_ptr: .quad 0\n"
	".globl rf_tramp_end\n"
	".hidden rf_tramp_end\n"
"rf_tramp_end:\n"
	".popsection\n"
);
#endif

extern char rf_tramp_start[], rf_tramp_end[];
extern char rf_tramp_rf_start[], rf_tramp_rf_end[];
extern char rf_tramp_data_ptr[];

static struct rf_tramp_data *tramp_data;
static void *tramp_start_fn;
static void *tramp_end_fn;

static int rf_tramp_install(void)
{
	long page_sz = sysconf(_SC_PAGESIZE);
	size_t code_sz = rf_tramp_end - rf_tramp_start;

	void *mem = mmap(NULL, 2 * page_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED)
		return -errno;

	memcpy(mem, rf_tramp_start, code_sz);

	struct rf_tramp_data *data = mem + page_sz;
	memset(data, 0, sizeof(*data));

	/* Patch the data pointer embedded in the copied trampoline code */
	size_t dp_off = rf_tramp_data_ptr - rf_tramp_start;
	*(void **)(mem + dp_off) = data;

	if (mprotect(mem, page_sz, PROT_READ | PROT_EXEC) < 0) {
		int err = -errno;
		munmap(mem, 2 * page_sz);
		return err;
	}

	tramp_data = data;
	tramp_start_fn = mem + (rf_tramp_rf_start - rf_tramp_start);
	tramp_end_fn = mem + (rf_tramp_rf_end - rf_tramp_start);

	return 0;
}

/* RecordScope enum values from ATen/record_function.h */
#define RF_SCOPE_FUNCTION          0
#define RF_SCOPE_BACKWARD_FUNCTION 1
#define RF_SCOPE_USER_SCOPE        7
#define RF_SCOPE_COUNT             10

static void rf_register(void)
{
	if (rf_tramp_install() < 0) {
		elog("Failed to install RecordFunction trampoline, skipping callback registration\n");
		return;
	}

	__atomic_store_n(&tramp_data->start_cb, (void *)rf_start_cb, __ATOMIC_RELEASE);
	__atomic_store_n(&tramp_data->end_cb, (void *)rf_end_cb, __ATOMIC_RELEASE);

	struct rf_callback_struct cb = {
		.start = tramp_start_fn,
		.end = tramp_end_fn,
		.prob = 1.0,
		.scopes = { [RF_SCOPE_FUNCTION] = true, [RF_SCOPE_BACKWARD_FUNCTION] = true, [RF_SCOPE_USER_SCOPE] = true },
	};

	rf_callback_handle = rf_add_global_callback(cb);
	rf_active = true;

	vlog("RecordFunction callback registered via trampoline (handle=%llu)\n", (unsigned long long)rf_callback_handle);
}

static void rf_unregister(void)
{
	if (!rf_active)
		return;

	__atomic_store_n(&tramp_data->start_cb, NULL, __ATOMIC_SEQ_CST);
	__atomic_store_n(&tramp_data->end_cb, NULL, __ATOMIC_SEQ_CST);

	rf_remove_callback(rf_callback_handle);

	vlog("Draining in-flight RecordFunction trampoline calls...\n");
	while (__atomic_load_n(&tramp_data->refcount, __ATOMIC_ACQUIRE) != 0)
		usleep(1);

	vlog("RecordFunction callback unregistered (handle=%llu)\n", (unsigned long long)rf_callback_handle);
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

/* Table of function pointers assigned from host-resolved addresses, must match pytorch_sym_names order */
static void **torch_resolve_syms[PYTORCH_SYM_CNT] = {
	(void **)&rf_add_global_callback,
	(void **)&rf_remove_callback,
	(void **)&rf_name,
};

/* ==================== Dump file management ==================== */

static void init_wpytorch_header(struct wpytorch_data_hdr *hdr)
{
	memset(hdr, 0, sizeof(*hdr));
	memcpy(hdr->magic, "WPYTO", 6);
	hdr->hdr_sz = sizeof(*hdr);
}

/* ==================== Public API ==================== */

/* Always consumes events_fd and respool_fd: keeps them via fdopen on success, closes them on failure. */
int pytorch_session_setup(int events_fd, int respool_fd, unsigned long *sym_addrs, int sym_addr_cnt)
{
	int err = 0;

	if (sym_addr_cnt != PYTORCH_SYM_CNT) {
		elog("BUG: PyTorch torch_sym_addr_cnt:%d != PYTORCH_SYM_CNT:%d\n", sym_addr_cnt, PYTORCH_SYM_CNT);
		zclose(events_fd);
		zclose(respool_fd);
		return -EINVAL;
	}

	/* Assign RecordFunction API pointers from host-resolved addresses */
	for (int i = 0; i < sym_addr_cnt; i++) {
		*torch_resolve_syms[i] = (void *)sym_addrs[i];
		if (sym_addrs[i])
			vlog("  %s = %p\n", pytorch_sym_names[i], (void *)sym_addrs[i]);
	}

	if (!rf_add_global_callback || !rf_remove_callback || !rf_name) {
		elog("Missing required PyTorch RecordFunction symbols\n");
		zclose(events_fd);
		zclose(respool_fd);
		return -ENOENT;
	}

	torch_respool_strs = strset__new(TORCH_DUMP_MAX_STRS_SZ, "", 1);
	if (!torch_respool_strs) {
		elog("Failed to create PyTorch string set\n");
		err = -ENOMEM;
		goto cleanup;
	}

	err = chunker_init(&torch_chunker, events_fd, INJ_FEAT_PYTORCH, TORCH_DUMP_BUF_SZ);
	if (err)
		goto cleanup;
	events_fd = -1;		/* the chunker owns it now */

	torch_respool_dump = fdopen(respool_fd, "w");
	if (!torch_respool_dump) {
		err = -errno;
		elog("Failed to create FILE wrapper around PyTorch resource pool FD %d: %d\n", respool_fd, err);
		goto cleanup;
	}

	if ((err = verify_mutex_symbols()) < 0)
		goto cleanup;

	torch_active = true;
	pthread_mutex_init(&torch_lock, NULL);
	strcache_init(&torch_name_cache, torch_respool_strs, &torch_lock);

	/*
	 * The event fd is tracked by chunker_init; track the resource pool too, before
	 * rf_register so the RecordFunction callback can't fire on an untracked fd
	 * (a fork in that window would leave the child's fd unprotected).
	 */
	inj_track_dump_fd(respool_fd);

	rf_register();

	return 0;

cleanup:
	torch_active = false;
	strset__free(torch_respool_strs);
	torch_respool_strs = NULL;
	chunker_finalize(&torch_chunker);		/* closes and untracks the event stream */
	if (torch_respool_dump) {
		fclose(torch_respool_dump);
		torch_respool_dump = NULL;
	} else {
		zclose(respool_fd);
	}
	zclose(events_fd);
	return err;
}

int pytorch_session_finalize(void)
{
	int err = 0;

	if (!torch_chunker.cur)
		return 0;

	rf_unregister();
	strcache_reset(&torch_name_cache); /* safe: rf_unregister drained all in-flight callbacks */
	torch_active = false;
	run_ctx->pytorch_event_cnt = torch_chunker.total_event_cnt;
	run_ctx->pytorch_byte_sz = torch_chunker.total_byte_sz;
	pthread_mutex_destroy(&torch_lock);

	/* finalize the headerless event stream: just flush and close */
	chunker_finalize(&torch_chunker);

	/* write the resource pool: header followed by the string pool */
	const char *strs = strset__data(torch_respool_strs);
	size_t strs_sz = strset__data_size(torch_respool_strs);

	struct wpytorch_data_hdr hdr;
	init_wpytorch_header(&hdr);
	hdr.sess_start_ns = run_ctx->sess_start_ts;
	hdr.sess_end_ns = run_ctx->sess_end_ts;
	hdr.strs_sz = strs_sz;

	inj_untrack_dump_fd(fileno(torch_respool_dump));

	if (fwrite(&hdr, sizeof(hdr), 1, torch_respool_dump) != 1) {
		err = -errno;
		elog("Failed to fwrite() PyTorch resource pool header: %d\n", err);
		return err;
	}

	if (fwrite(strs, 1, strs_sz, torch_respool_dump) != strs_sz) {
		err = -errno;
		elog("Failed to write strings to PyTorch resource pool: %d\n", err);
		return err;
	}

	fflush(torch_respool_dump);
	fsync(fileno(torch_respool_dump));
	fclose(torch_respool_dump);
	torch_respool_dump = NULL;

	vlog("PyTorch profiler finalized: %llu events, %zu string bytes\n",
	     torch_chunker.total_event_cnt, strs_sz);

	strset__free(torch_respool_strs);
	torch_respool_strs = NULL;

	return 0;
}
