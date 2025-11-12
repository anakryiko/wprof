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

#include <cupti.h>

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
};

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

static bool cupti_init = false;
static void *cupti_handle = NULL;
static bool cupti_alive = false;
static CUpti_ActivityThreadIdType cupti_old_thread_id_type = -1;

static void CUPTIAPI buffer_requested(uint8_t **buffer, size_t *size, size_t *max_num_records)
{
	const size_t cupti_buf_sz = 2 * 1024 * 1024;
	uint8_t *buf;

	cupti_alive = true;

	buf = (uint8_t *)malloc(cupti_buf_sz);
	if (!buf) {
		*buffer = NULL;
		*size = 0;
		*max_num_records = 0;

		elog("Failed to allocate CUPTI activity buffer!\n");
		return;
	}

	vlog("CUPTI activity buffer allocated (%zu bytes)\n", cupti_buf_sz);

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
			return 0;

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
			return 0;

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
			return 0;

		enum wcuda_cuda_api_kind kind;
		if (rec->kind == CUPTI_ACTIVITY_KIND_DRIVER)
			kind = WCUDA_CUDA_API_DRIVER;
		else
			kind = WCUDA_CUDA_API_RUNTIME;

		struct wcuda_event e = {
			.sz = sizeof(e),
			.kind = WCK_CUDA_API,
			.ts = start_ts,
			.cuda_api = {
				.end_ts = end_ts,
				.kind = kind,
				.corr_id = r->correlationId,
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
			return 0;

		struct wcuda_event e = {
			.sz = sizeof(e),
			.kind = WCK_CUDA_MEMSET,
			.ts = start_ts,
			.cuda_memset = {
				.end_ts = end_ts,
				.byte_cnt = r->bytes,
				.corr_id = r->correlationId,
				.device_id = r->deviceId,
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
			return 0;

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
	default:
		vlog("  Activity kind: %d\n", rec->kind);
		break;
	}

	return 0;
}

enum CUpti_driver_api_trace_cbid_enum driver_cbids;
enum CUpti_runtime_api_trace_cbid_enum runtime_cbids;

static void CUPTIAPI buffer_completed(CUcontext ctx, uint32_t stream_id, uint8_t *buf,
				      size_t buf_sz, size_t data_sz)
{
	CUptiResult status;
	size_t err_cnt = 0;
	size_t drop_cnt = 0;
	size_t rec_cnt = 0;

	vlog("CUPTI activity buffer completed (sz %zu, valid_sz %zu)\n", buf_sz, data_sz);

	if (data_sz == 0 || run_ctx->sess_start_ts == 0) {
		free(buf);
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
		if (err) {
			elog("Failed to handle record #%zu: %d\n", rec_cnt, err);
			err_cnt += 1;
		}

		rec_cnt += 1;
	}

	status = cupti_activity_get_num_dropped_records(ctx, stream_id, &drop_cnt);
	if (status != CUPTI_SUCCESS) {
		elog("Failed to get number of CUPTI activity dropped record count: %d (%s)!\n",
			status, cupti_errstr(status));
	} else if (drop_cnt > 0) {
		elog("!!! CUPTI Activity API dropped %zu records!\n", drop_cnt);
	}

	free(buf);

	vlog("Processed %zu CUPTI activity records (%zu errors, %zu dropped).\n",
	     rec_cnt, err_cnt, drop_cnt);
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

	cupti_init = true;
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

int start_cupti_activities(void)
{
	CUptiResult ret;
	int err = 0;

	vlog("Initializing CUPTI activity subscription...\n");

	ret = cupti_get_thread_id_type(&cupti_old_thread_id_type);
	if (ret != CUPTI_SUCCESS) {
		elog("Failed to get current thread ID type: %d (%s)!\n", ret, cupti_errstr(ret));
		return -EPROTO;
	}

	/* ask CUPTI to give use real thread ID, not pthread_self() garbage */
	ret = cupti_set_thread_id_type(CUPTI_ACTIVITY_THREAD_ID_TYPE_SYSTEM);
	if (ret != CUPTI_SUCCESS) {
		elog("Failed to set current thread ID type to system one: %d (%s)!\n", ret, cupti_errstr(ret));
		return -EPROTO;
	}

	/* Register callbacks for activity buffer management */
	ret = cupti_activity_register_callbacks(buffer_requested, buffer_completed);
	if (ret != CUPTI_SUCCESS) {
		elog("Failed to register CUPTI activity callbacks: %d (%s)!\n",
		     ret, cupti_errstr(ret));
		cupti_set_thread_id_type(cupti_old_thread_id_type);
		return -EPROTO;
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

cleanup:
	finalize_cupti_activities();
	return err;
}

/* Finalize CUPTI and flush any remaining activity records */
void finalize_cupti_activities(void)
{
	if (!cupti_init)
		return;

	if (cupti_alive) {
		vlog("Flushing CUPTI activity buffers...\n");
		/* drain buffers forcefully to avoid getting our callbacks called */
		(void)cupti_activity_flush_all(CUPTI_ACTIVITY_FLAG_FLUSH_FORCED);
	} else {
		vlog("Skipping CUPTI activity flush as CUPTI doesn't seem to be active!\n");
	}

	/* deactivate any activity we might have activated */
	for (int i = 0; i < ARRAY_SIZE(cupti_act_kinds); i++) {
		CUpti_ActivityKind kind = cupti_act_kinds[i];

		vlog("Disabling CUPTI activity %s...\n", cupti_act_kind_str(kind));
		(void)cupti_activity_disable(kind);
	}

	/*
	 * Make sure any remaining accummulated records between last flush and
	 * disabling activities are drained and recorded properly
	 */
	if (cupti_alive) {
		vlog("Flushing CUPTI activity buffers again...\n");
		/* drain buffers forcefully to avoid getting our callbacks called */
		(void)cupti_activity_flush_all(CUPTI_ACTIVITY_FLAG_FLUSH_FORCED);
	}

	if (cupti_old_thread_id_type != -1)
		(void)cupti_set_thread_id_type(cupti_old_thread_id_type);

	vlog("CUPTI activity API finalized.\n");

	if (cupti_handle) {
		vlog("Performing dlclose(libcupti.so) to not leak its handle...\n");
		int err = dlclose(cupti_handle);
		if (err)
			vlog("dlclose(libcupti.so) FAILED: %d\n", -errno);
		else
			vlog("dlclose(libcupti.so) finished successfully.\n");
		cupti_handle = NULL;
	}

	cupti_init = false;
}
