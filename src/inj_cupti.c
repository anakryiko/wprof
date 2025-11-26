// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sched.h>

#include <cupti.h>
#include <cupti_activity.h>
#include <cupti_callbacks.h>

#include "strset.h"
#include "inj.h"
#include "inj_common.h"
#include "cuda_data.h"

static CUptiResult (*cupti_activity_enable)(CUpti_ActivityKind kind);
static CUptiResult (*cupti_activity_disable)(CUpti_ActivityKind kind);
static CUptiResult (*cupti_activity_register_callbacks)(CUpti_BuffersCallbackRequestFunc, CUpti_BuffersCallbackCompleteFunc);
static CUptiResult (*cupti_activity_flush_all)(uint32_t flag);
static CUptiResult (*cupti_activity_get_next_record)(uint8_t *buffer, size_t validBufferSizeBytes, CUpti_Activity **record);
static CUptiResult (*cupti_activity_get_num_dropped_records)(CUcontext context, uint32_t streamId, size_t *dropped);
static CUptiResult (*cupti_get_timestamp)(u64 *timestamp);
static CUptiResult (*cupti_get_result_string)(CUptiResult result, const char **str);
static CUptiResult (*cupti_get_thread_id_type)(CUpti_ActivityThreadIdType *type);
static CUptiResult (*cupti_set_thread_id_type)(CUpti_ActivityThreadIdType type);

static CUptiResult (*cupti_subscribe)(CUpti_SubscriberHandle *subscriber, CUpti_CallbackFunc callback, void *userdata);
static CUptiResult (*cupti_unsubscribe)(CUpti_SubscriberHandle subscriber);
static CUptiResult (*cupti_enable_domain)(uint32_t enable, CUpti_SubscriberHandle subscriber, CUpti_CallbackDomain domain);
static CUptiResult (*cupti_finalize)(void);

static struct {
	void *sym_pptr;
	const char *sym_name;
} cupti_resolve_syms[] = {
	{&cupti_activity_enable, "cuptiActivityEnable"},
	{&cupti_activity_disable, "cuptiActivityDisable"},
	{&cupti_activity_register_callbacks, "cuptiActivityRegisterCallbacks"},
	{&cupti_activity_flush_all, "cuptiActivityFlushAll"},
	{&cupti_activity_get_next_record, "cuptiActivityGetNextRecord"},
	{&cupti_activity_get_num_dropped_records, "cuptiActivityGetNumDroppedRecords"},
	{&cupti_get_timestamp, "cuptiGetTimestamp"},
	{&cupti_get_result_string, "cuptiGetResultString"},
	{&cupti_get_thread_id_type, "cuptiGetThreadIdType"},
	{&cupti_set_thread_id_type, "cuptiSetThreadIdType"},
	{&cupti_subscribe, "cuptiSubscribe"},
	{&cupti_unsubscribe, "cuptiUnsubscribe"},
	{&cupti_enable_domain, "cuptiEnableDomain"},
	{&cupti_finalize, "cuptiFinalize"},
};

enum cupti_phase {
	CUPTI_UNINIT, /* we haven't initialized yet */
	CUPTI_INITIALIZED, /* libcupti.so loaded and symbols resolved */
	CUPTI_SUBSCR, /* we have initialized and subscribed */
	CUPTI_DRAINING, /* shutting down, but still passing through records */
	CUPTI_DRAINED, /* discard anything */
};

static void *cupti_handle = NULL;
static CUpti_ActivityThreadIdType cupti_old_thread_id_type = CUPTI_ACTIVITY_THREAD_ID_TYPE_SYSTEM;
static CUpti_SubscriberHandle cupti_subscr = NULL;

static enum cupti_phase cupti_phase = CUPTI_UNINIT;
static long cupti_alloc_buf_cnt = 0;

static long cupti_processing __aligned(64);

static uint8_t discard_buf[256 * 1024];

static const char *cupti_errstr(CUptiResult res)
{
	const char *errstr = "???";

	cupti_get_result_string(res, &errstr);

	return errstr ?: "???";
}

static u64 gpu_time_now_ns(void)
{
	u64 timestamp;
	cupti_get_timestamp(&timestamp);
	return timestamp;
}

static u64 gpu_to_cpu_time_delta_ns;

static void calibrate_gpu_clocks(void)
{
	u64 best_gap = UINT64_MAX;
	u64 best_gpu_ts = 0;
	u64 best_cpu_ts = 0;

	for (int i = 0; i < 100; i++) {
		u64 cpu_ts1 = ktime_now_ns();
		u64 gpu_ts = gpu_time_now_ns();
		u64 cpu_ts2 = ktime_now_ns();

		u64 gap = cpu_ts2 - cpu_ts1;
		if (gap < best_gap) {
			best_gap = gap;
			best_gpu_ts = gpu_ts;
			best_cpu_ts = (cpu_ts1 + cpu_ts2) / 2;
		}
	}

	gpu_to_cpu_time_delta_ns = best_cpu_ts - best_gpu_ts;
}

static u64 gpu_to_cpu_time_ns(u64 gpu_ts)
{
	return gpu_ts + gpu_to_cpu_time_delta_ns;
}

static void CUPTIAPI buffer_requested(uint8_t **buffer, size_t *size, size_t *max_num_records)
{
	const size_t cupti_buf_sz = 2 * 1024 * 1024;
	uint8_t *buf;

	atomic_add(&cupti_alloc_buf_cnt, 1);

	if (atomic_load(&cupti_phase) >= CUPTI_DRAINING) {
		*buffer = discard_buf;
		*size = sizeof(discard_buf);
		*max_num_records = 0;
		vlog("Giving DISCARD BUFFER (%p, %zu bytes) to CUPTI, we are DRAINING!..\n",
		     discard_buf, sizeof(discard_buf));
		return;
	}

	buf = (uint8_t *)malloc(cupti_buf_sz);
	if (!buf) {
		*buffer = discard_buf;
		*size = sizeof(discard_buf);
		*max_num_records = 0;
		elog("FAILED to allocate CUPTI activity buffer!\n");
		return;
	}

	vlog("CUPTI activity buffer allocated (%p, %zu bytes)\n", buf, cupti_buf_sz);

	*buffer = buf;
	*size = cupti_buf_sz;
	*max_num_records = 0; /* no limit on number of records */
}

static bool rec_within_session(u64 rec_start_ts, u64 rec_end_ts, u64 sess_start_ts, u64 sess_end_ts)
{
	if (sess_start_ts == 0)
		return false;
	if ((long)(rec_end_ts - sess_start_ts) < 0)
		return false;
	if ((long)(rec_start_ts - sess_end_ts) > 0)
		return false;
	return true;
}

static int handle_cupti_record(CUpti_Activity *rec)
{
	switch (rec->kind) {
	case CUPTI_ACTIVITY_KIND_KERNEL:
	case CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL: {
		CUpti_ActivityKernel4 *r = (CUpti_ActivityKernel4 *)rec;

		u64 start_ts = gpu_to_cpu_time_ns(r->start);
		u64 end_ts = gpu_to_cpu_time_ns(r->end);
		if (!rec_within_session(start_ts, end_ts, run_ctx->sess_start_ts, run_ctx->sess_end_ts))
			return -ENODATA;

		struct wcuda_event e = {
			.sz = sizeof(e),
			.kind = WCK_CUDA_KERNEL,
			.ts = start_ts,
			.cuda_kernel = {
				.end_ts = end_ts,
				.name_off = strset__add_str(cuda_dump_strs, r->name),
				.corr_id = r->correlationId,
				.device_id = r->deviceId,
				.stream_id = r->streamId,
				.ctx_id = r->contextId,
				.grid_x = r->gridX,
				.grid_y = r->gridY,
				.grid_z = r->gridZ,
				.block_x = r->blockX,
				.block_y = r->blockY,
				.block_z = r->blockZ,
			},
		};
		return cuda_dump_event(&e);
	}
	case CUPTI_ACTIVITY_KIND_MEMCPY: {
		CUpti_ActivityMemcpy *r = (CUpti_ActivityMemcpy *)rec;

		u64 start_ts = gpu_to_cpu_time_ns(r->start);
		u64 end_ts = gpu_to_cpu_time_ns(r->end);
		if (!rec_within_session(start_ts, end_ts, run_ctx->sess_start_ts, run_ctx->sess_end_ts))
			return -ENODATA;

		struct wcuda_event e = {
			.sz = sizeof(e),
			.kind = WCK_CUDA_MEMCPY,
			.ts = start_ts,
			.cuda_memcpy = {
				.end_ts = end_ts,
				.byte_cnt = r->bytes,
				.copy_kind = r->copyKind,
				.src_kind = r->srcKind,
				.dst_kind = r->dstKind,
				.corr_id = r->correlationId,
				.device_id = r->deviceId,
				.stream_id = r->streamId,
				.ctx_id = r->contextId,
			},
		};
		return cuda_dump_event(&e);
	}
	case CUPTI_ACTIVITY_KIND_DRIVER:
	case CUPTI_ACTIVITY_KIND_RUNTIME: {
		CUpti_ActivityAPI *r = (CUpti_ActivityAPI *)rec;

		u64 start_ts = gpu_to_cpu_time_ns(r->start);
		u64 end_ts = gpu_to_cpu_time_ns(r->end);
		if (!rec_within_session(start_ts, end_ts, run_ctx->sess_start_ts, run_ctx->sess_end_ts))
			return -ENODATA;

		enum wcuda_cuda_api_kind kind;
		if (rec->kind == CUPTI_ACTIVITY_KIND_DRIVER) {
			kind = WCUDA_CUDA_API_DRIVER;
			/* ignore not interesting but very spammy API calls */
			switch (r->cbid) {
			case CUPTI_DRIVER_TRACE_CBID_cuPointerGetAttribute:
			case CUPTI_DRIVER_TRACE_CBID_cuPointerGetAttributes:
			case CUPTI_DRIVER_TRACE_CBID_cuDevicePrimaryCtxGetState:
			case CUPTI_DRIVER_TRACE_CBID_cuCtxGetCurrent:
			case CUPTI_DRIVER_TRACE_CBID_cuKernelGetAttribute:
				return -ENODATA;
			default:
				break;
			}
		} else {
			kind = WCUDA_CUDA_API_RUNTIME;
			/* ignore not interesting but very spammy API calls */
			switch (r->cbid) {
			case CUPTI_RUNTIME_TRACE_CBID_cudaGetLastError_v3020:
			case CUPTI_RUNTIME_TRACE_CBID_cudaPeekAtLastError_v3020:
			case CUPTI_RUNTIME_TRACE_CBID_cudaGetDevice_v3020:
			case CUPTI_RUNTIME_TRACE_CBID_cudaStreamIsCapturing_v10000:
				return -ENODATA;
			default:
				break;
			}
		}

		struct wcuda_event e = {
			.sz = sizeof(e),
			.kind = WCK_CUDA_API,
			.ts = start_ts,
			.cuda_api = {
				.end_ts = end_ts,
				.kind = kind,
				.corr_id = r->correlationId,
				.pid = r->processId,
				.tid = r->threadId,
				.cbid = r->cbid,
				.ret_val = r->returnValue,
			},
		};
		return cuda_dump_event(&e);
	}
	case CUPTI_ACTIVITY_KIND_MEMSET: {
		CUpti_ActivityMemset *r = (CUpti_ActivityMemset *)rec;

		u64 start_ts = gpu_to_cpu_time_ns(r->start);
		u64 end_ts = gpu_to_cpu_time_ns(r->end);
		if (!rec_within_session(start_ts, end_ts, run_ctx->sess_start_ts, run_ctx->sess_end_ts))
			return -ENODATA;

		struct wcuda_event e = {
			.sz = sizeof(e),
			.kind = WCK_CUDA_MEMSET,
			.ts = start_ts,
			.cuda_memset = {
				.end_ts = end_ts,
				.byte_cnt = r->bytes,
				.corr_id = r->correlationId,
				.device_id = r->deviceId,
				.ctx_id = r->contextId,
				.stream_id = r->streamId,
				.value = r->value,
				.mem_kind = r->memoryKind,
			},
		};
		return cuda_dump_event(&e);
	}
	case CUPTI_ACTIVITY_KIND_SYNCHRONIZATION: {
		CUpti_ActivitySynchronization *r = (CUpti_ActivitySynchronization *)rec;

		u64 start_ts = gpu_to_cpu_time_ns(r->start);
		u64 end_ts = gpu_to_cpu_time_ns(r->end);
		if (!rec_within_session(start_ts, end_ts, run_ctx->sess_start_ts, run_ctx->sess_end_ts))
			return -ENODATA;

		struct wcuda_event e = {
			.sz = sizeof(e),
			.kind = WCK_CUDA_SYNC,
			.ts = start_ts,
			.cuda_sync = {
				.end_ts = end_ts,
				.corr_id = r->correlationId,
				.stream_id = r->streamId,
				.ctx_id = r->contextId,
				.event_id = r->cudaEventId,
				.sync_type = r->type,
			},
		};
		return cuda_dump_event(&e);
	}
	case CUPTI_ACTIVITY_KIND_CUDA_EVENT:
		/*
		 * XXX: event is a means to connect GPU-side sync scope with CPU-side sync API call,
		 * but it has no time stamp, so hard to integrate into wprof right now
		 */
		break;
	default:
		vlog("  Activity kind: %d\n", rec->kind);
		break;
	}

	return -ENODATA;
}

enum CUpti_driver_api_trace_cbid_enum driver_cbids;
enum CUpti_runtime_api_trace_cbid_enum runtime_cbids;

static void consume_activity_buf(void *buf)
{
	if (buf == discard_buf)
		return;
	free(buf);
}

static void CUPTIAPI buffer_completed(CUcontext ctx, uint32_t stream_id, uint8_t *buf,
				      size_t buf_sz, size_t data_sz)
{
	CUptiResult status;
	long err_cnt = 0;
	size_t drop_cnt = 0;
	long rec_cnt = 0;
	long ignore_cnt = 0;

	vlog("CUPTI activity buffer completed (%p, sz %zu, data_sz %zu)\n", buf, buf_sz, data_sz);

	atomic_store(&cupti_processing, 1);

	enum cupti_phase phase = atomic_load(&cupti_phase);
	if (phase >= CUPTI_DRAINED || data_sz == 0 || run_ctx->sess_start_ts == 0) {
		consume_activity_buf(buf);
		atomic_store(&cupti_processing, 0);
		return;
	}

	CUpti_Activity *rec = NULL;
	while (true) {
		status = cupti_activity_get_next_record(buf, data_sz, &rec);
		if (status == CUPTI_ERROR_MAX_LIMIT_REACHED)
			break;
		if (status != CUPTI_SUCCESS) {
			elog("Failed to get next CUPTI activity record: %d (%s)\n",
			     status, cupti_errstr(status));
			break;
		}

		int err = handle_cupti_record(rec);
		if (err == -ENODATA) {
			ignore_cnt += 1;
		} else if (err) {
			elog("Failed to handle record #%zu: %d\n", rec_cnt, err);
			err_cnt += 1;
		} else {
			rec_cnt += 1;
		}
	}

	status = cupti_activity_get_num_dropped_records(ctx, stream_id, &drop_cnt);
	if (status != CUPTI_SUCCESS) {
		elog("Failed to get number of CUPTI activity dropped record count: %d (%s)!\n",
			status, cupti_errstr(status));
	} else if (drop_cnt > 0) {
		elog("!!! CUPTI Activity API dropped %zu records!\n", drop_cnt);
	}

	consume_activity_buf(buf);

	vlog("Processed %zu CUPTI activity records (%ld errors, %zu dropped, %ld ignored).\n",
	     rec_cnt, err_cnt, drop_cnt, ignore_cnt);

	atomic_add(&run_ctx->cupti_rec_cnt, rec_cnt);
	atomic_add(&run_ctx->cupti_drop_cnt, drop_cnt);
	atomic_add(&run_ctx->cupti_err_cnt, err_cnt);
	atomic_add(&run_ctx->cupti_ignore_cnt, ignore_cnt);
	atomic_add(&run_ctx->cupti_buf_cnt, 1);
	atomic_add(&run_ctx->cupti_data_sz, data_sz);

	atomic_store(&cupti_processing, 0);
}

static bool cupti_lazy_init(void)
{
	cupti_handle = dlopen("libcupti.so", RTLD_NOLOAD | RTLD_LAZY);
	if (cupti_handle) {
		vlog("Found libcupti.so (handle %lx)!\n", (long)cupti_handle);
	} else {
		/* call dlerror() regardless to clear error */
		const char *err_msg = dlerror();
		vlog("Failed to find libcupti.so: %s!\n", err_msg);
	}

	for (int i = 0; i < ARRAY_SIZE(cupti_resolve_syms); i++) {
		const char *sym_name = cupti_resolve_syms[i].sym_name;
		void **sym_pptr = (void **)cupti_resolve_syms[i].sym_pptr;
		*sym_pptr = dyn_resolve_sym(sym_name, cupti_handle);
		if (!*sym_pptr)
			return false;
	}

	cupti_phase = CUPTI_INITIALIZED;

	return true;
}

static CUpti_ActivityKind cupti_act_kinds[] = {
	CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL,
	CUPTI_ACTIVITY_KIND_MEMCPY,
	CUPTI_ACTIVITY_KIND_DRIVER,
	CUPTI_ACTIVITY_KIND_RUNTIME,
	CUPTI_ACTIVITY_KIND_MEMSET,
	CUPTI_ACTIVITY_KIND_SYNCHRONIZATION,
};

static const char *cupti_act_kind_strs[] = {
	[CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL] = "CONCURRENT_KERNEL",
	[CUPTI_ACTIVITY_KIND_MEMCPY] = "MEMCPY",
	[CUPTI_ACTIVITY_KIND_DRIVER] = "DRIVER",
	[CUPTI_ACTIVITY_KIND_RUNTIME] = "RUNTIME",
	[CUPTI_ACTIVITY_KIND_MEMSET] = "MEMSET",
	[CUPTI_ACTIVITY_KIND_SYNCHRONIZATION] = "SYNCHRONIZATION",
	[CUPTI_ACTIVITY_KIND_CUDA_EVENT] = "EVENT",
};

static const char *cupti_act_kind_str(CUpti_ActivityKind kind)
{
	if (kind < 0 || kind >= ARRAY_SIZE(cupti_act_kind_strs))
		return "???";

	return cupti_act_kind_strs[kind] ?: "???";
}

void finalize_cupti_activities(void);

/* Initialize CUPTI activity setup */
int init_cupti_activities(void)
{
	if (!cupti_lazy_init()) {
		elog("Failed to find and resolve CUPTI library!\n");
		return -ESRCH;
	}

	calibrate_gpu_clocks();

	vlog("CUPTI setup successfully initialized.\n");

	return 0;
}

static void cupti_callback(void *userdata, CUpti_CallbackDomain domain, CUpti_CallbackId cbid, const void *cbdata);

int start_cupti_activities(void)
{
	CUptiResult ret;
	int err = -EPROTO;

	vlog("Calling cuptiSubscribe()...\n");

	ret = cupti_subscribe(&cupti_subscr, cupti_callback, NULL);
	if (ret == CUPTI_ERROR_MULTIPLE_SUBSCRIBERS_NOT_SUPPORTED) {
		elog("No CUDA is used by this process or (unlikely) another CUPTI tool is active right now! Bailing...\n");
		inj_set_exit_hint(HINT_CUPTI_BUSY,
				  "Mostly likely CUDA/GPU isn't used by this process. "
				  "Or (unlikely) CUPTI is used by someone else inside this process.\n");
		return -EBUSY;
	} else if (ret != CUPTI_SUCCESS) {
		elog("Failed to perform CUPTI subscription: %d (%s)!\n", ret, cupti_errstr(ret));
		return -EPROTO;
	}

	atomic_store(&cupti_phase, CUPTI_SUBSCR);

	vlog("Calling cuptiGetThreadIdType()...\n");
	ret = cupti_get_thread_id_type(&cupti_old_thread_id_type);
	if (ret != CUPTI_SUCCESS) {
		elog("Failed to get current thread ID type: %d (%s)!\n", ret, cupti_errstr(ret));
		goto unsubscr;
	}

	if (cupti_old_thread_id_type != CUPTI_ACTIVITY_THREAD_ID_TYPE_SYSTEM) {
		/*
		 * Ask CUPTI to give use real (though may be namespaced) thread ID,
		 * not pthread_self() garbage
		 */
		ret = cupti_set_thread_id_type(CUPTI_ACTIVITY_THREAD_ID_TYPE_SYSTEM);
		if (ret != CUPTI_SUCCESS) {
			elog("Failed to set current thread ID type to system one: %d (%s)!\n", ret, cupti_errstr(ret));
			goto unsubscr;
		}
	}

	/* Register callbacks for activity buffer management */
	vlog("Calling cuptiActivityRegisterCallbacks()...\n");
	ret = cupti_activity_register_callbacks(buffer_requested, buffer_completed);
	if (ret != CUPTI_SUCCESS) {
		elog("Failed to register CUPTI activity callbacks: %d (%s)!\n",
		     ret, cupti_errstr(ret));
		cupti_set_thread_id_type(cupti_old_thread_id_type);
		goto unsubscr;
	}

	vlog("CUPTI activity callbacks registered.\n");

	/* Subscribe to various activity kinds */
	for (int i = 0; i < ARRAY_SIZE(cupti_act_kinds); i++) {
		CUpti_ActivityKind kind = cupti_act_kinds[i];

		ret = cupti_activity_enable(kind);
		if (ret != CUPTI_SUCCESS) {
			err = -EINVAL;
			elog("Failed to subscribe to CUPTI activity kind '%s': %d (%s)!\n",
			     cupti_act_kind_str(kind), ret, cupti_errstr(ret));
			goto cleanup;
		}
		vlog("CUPTI activity kind '%s' activated successfully.\n", cupti_act_kind_str(kind));
	}

	vlog("CUPTI activity subscription initialized successfully.\n");
	
	return 0;

unsubscr:
	(void)cupti_unsubscribe(cupti_subscr);
cleanup:
	finalize_cupti_activities();
	return err;
}

static void cupti_finalize_cb(void)
{
	/* deactivate any activity we might have activated */
	for (int i = 0; i < ARRAY_SIZE(cupti_act_kinds); i++) {
		CUpti_ActivityKind kind = cupti_act_kinds[i];

		vlog("Disabling CUPTI activity %s...\n", cupti_act_kind_str(kind));
		(void)cupti_activity_disable(kind);
	}

	if (cupti_old_thread_id_type != CUPTI_ACTIVITY_THREAD_ID_TYPE_SYSTEM) {
		vlog("Restoring original CUPTI thread ID type setting...\n");
		(void)cupti_set_thread_id_type(cupti_old_thread_id_type);
	}

	/*
	 * Make sure any remaining accummulated records between last flush and
	 * disabling activities are drained and buffers are freed properly
	 */
	vlog("Flushing CUPTI activity buffers again...\n");
	/* drain buffers forcefully to avoid getting our callbacks called */
	(void)cupti_activity_flush_all(CUPTI_ACTIVITY_FLAG_FLUSH_FORCED);

	vlog("Unsubscribing from CUPTI...\n");
	cupti_unsubscribe(cupti_subscr);
	vlog("Finalizing CUPTI...\n");
	cupti_finalize();

	vlog("CUPTI finalization DONE.\n");
}

static volatile bool cupti_finalizing __aligned(64) = false;
static long cupti_fini_cnt = 0;
static int cupti_fini_pipe_fds[2] = {-1, -1};

static void cupti_callback(void *userdata, CUpti_CallbackDomain domain, CUpti_CallbackId cbid, const void *cbdata)
{
	if (domain != CUPTI_CB_DOMAIN_DRIVER_API && domain != CUPTI_CB_DOMAIN_RUNTIME_API)
		return;

	const CUpti_CallbackData *cb = cbdata;
	if (cb->callbackSite != CUPTI_API_EXIT)
		return;

	if (!cupti_finalizing)
		return;

	/* make sure only one thread performs finalization */
	if (atomic_add(&cupti_fini_cnt, 1) == 1) {
		vlog("CUDA callback thread (TID %d) is finalizing CUPTI....\n", gettid());
		cupti_finalize_cb();
		cupti_finalizing = false;
		/* unblock other CUDA threads and wprofinj thread by closing write end of pipe */
		vlog("CUDA callback thread (TID %d) is DONE, waking everyone up.\n", gettid());
		close(cupti_fini_pipe_fds[1]);
	}
}

/* Finalize CUPTI and flush any remaining activity records */
void finalize_cupti_activities(void)
{
	enum cupti_phase phase = atomic_load(&cupti_phase);
	if (phase < CUPTI_INITIALIZED)
		return;

	if (phase == CUPTI_INITIALIZED)
		goto unload_cupti; /* we didn't really subscribe */

	vlog("Starting DRAINING phase...\n");
	atomic_store(&cupti_phase, CUPTI_DRAINING);

	bool live = true || atomic_load(&cupti_alloc_buf_cnt) > 0;
	if (live) {
		vlog("Flushing CUPTI activity buffers...\n");
		/* drain buffers forcefully to avoid getting our callbacks called */
		(void)cupti_activity_flush_all(CUPTI_ACTIVITY_FLAG_FLUSH_FORCED);

		vlog("Moving to DRAINED phase and waiting for CUPTI activity processing to cease...\n");
		atomic_store(&cupti_phase, CUPTI_DRAINED);
		while (atomic_load(&cupti_processing) != 0)
			sched_yield();
	} else {
		vlog("Skipping CUPTI activity flush as CUPTI doesn't seem to be active!\n");
	}

	vlog("Finalizing CUDA data dump...\n");
	int err = cuda_dump_finalize();
	if (err) /* not much we can do about that, but report it loudly */
		elog("!!! CUDA dump finalization returned error: %d\n", err);

	if (live) {
		CUptiResult ret;

		if (pipe2(cupti_fini_pipe_fds, O_CLOEXEC) < 0)
			elog("Failed to create pipe FDs: %d!\n", -errno);

		cupti_finalizing = true;

		vlog("Enabling CUPTI_CB_DOMAIN_RUNTIME_API subscription...\n");
		ret = cupti_enable_domain(1, cupti_subscr, CUPTI_CB_DOMAIN_RUNTIME_API);
		if (ret != CUPTI_SUCCESS)
			elog("Failed to enable CUPTI_CB_DOMAIN_RUNTIME_API subscription: %d (%s)\n", ret, cupti_errstr(ret));

		vlog("Enabling CUPTI_CB_DOMAIN_DRIVER_API subscription...\n");
		ret = cupti_enable_domain(1, cupti_subscr, CUPTI_CB_DOMAIN_DRIVER_API);
		if (ret != CUPTI_SUCCESS)
			elog("Failed to enable CUPTI_CB_DOMAIN_DRIVER_API subscription: %d (%s)\n", ret, cupti_errstr(ret));

		vlog("Waiting for CUPTI finalization to be done...\n");
		char tmp;
		/* XXX: add timeout? what if no CUDA API call happens ever again? */
		int pipe_fd = cupti_fini_pipe_fds[0];
		(void)read(pipe_fd, &tmp, 1);

		atomic_store(&cupti_fini_pipe_fds[0], -1);
		close(pipe_fd);

		vlog("Letting CUPTI Callback API finish running our callbacks...\n");
		/* wait 50ms to give CUPTI Callback APIs time to exit our callbacks */
		usleep(50 * 1000);

		vlog("CUPTI activity API finalized!\n");
	}

unload_cupti:
	if (cupti_handle) {
		vlog("Performing dlclose(libcupti.so) to not leak its handle...\n");
		int err = dlclose(cupti_handle);
		if (err)
			vlog("dlclose(libcupti.so) FAILED: %d\n", -errno);
		else
			vlog("dlclose(libcupti.so) finished successfully.\n");
		cupti_handle = NULL;
	}

	atomic_store(&cupti_phase, CUPTI_UNINIT);

	vlog("Done tearing down CUPTI functionality!\n");
}
