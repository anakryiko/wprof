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

#include "inj.h"
#include "inj_common.h"
#include "cuda_data.h"

static CUptiResult (*cupti_activity_enable)(CUpti_ActivityKind kind);
static CUptiResult (*cupti_activity_disable)(CUpti_ActivityKind kind);
static CUptiResult (*cupti_activity_register_callbacks)(CUpti_BuffersCallbackRequestFunc, CUpti_BuffersCallbackCompleteFunc);
static CUptiResult (*cupti_activity_flush_all)(uint32_t flag);
static CUptiResult (*cupti_activity_get_next_record)(uint8_t *buffer, size_t validBufferSizeBytes, CUpti_Activity **record);
static CUptiResult (*cupti_activity_get_num_dropped_records)(CUcontext context, uint32_t streamId, size_t *dropped);
static CUptiResult (*cupti_get_result_string)(CUptiResult result, const char **str);

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
	{&cupti_get_result_string, "cuptiGetResultString"},
};

static const char *cupti_errstr(CUptiResult res)
{
	const char *errstr = "???";

	cupti_get_result_string(res, &errstr);

	return errstr ?: "???";
}

static void CUPTIAPI buffer_requested(uint8_t **buffer, size_t *size, size_t *max_num_records)
{
	const size_t cupti_buf_sz = 512 * 1024;
	uint8_t *buf = (uint8_t *)malloc(cupti_buf_sz);

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

static int handle_cupti_record(CUpti_Activity *rec)
{
	switch (rec->kind) {
	case CUPTI_ACTIVITY_KIND_KERNEL:
	case CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL: {
		CUpti_ActivityKernel4 *kernel = (CUpti_ActivityKernel4 *)rec;
		vlog("  Kernel: %s (duration: %llu ns)\n",
		       kernel->name ? kernel->name : "<unknown>",
		       (unsigned long long)(kernel->end - kernel->start));
		break;
	}
	case CUPTI_ACTIVITY_KIND_MEMCPY: {
		CUpti_ActivityMemcpy *memcpy = (CUpti_ActivityMemcpy *)rec;
		vlog("  Memcpy: %llu bytes (duration: %llu ns)\n",
		       (unsigned long long)memcpy->bytes,
		       (unsigned long long)(memcpy->end - memcpy->start));
		break;
	}
	default:
		vlog("  Activity kind: %d\n", rec->kind);
		break;
	}

	return 0;
}

static void CUPTIAPI buffer_completed(CUcontext ctx, uint32_t stream_id, uint8_t *buf,
				      size_t buf_sz, size_t data_sz)
{
	CUptiResult status;
	size_t err_cnt = 0;
	size_t drop_cnt = 0;
	size_t rec_cnt = 0;

	vlog("CUPTI activity buffer completed (sz %zu, valid_sz %zu)\n", buf_sz, data_sz);

	if (data_sz == 0) {
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

static bool cupti_ok = false;
static void *cupti_handle = NULL;

static void *dyn_resolve_sym(const char *sym_name)
{
	void *sym;

	if (cupti_handle) {
		sym = dlsym(cupti_handle, sym_name);
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

static bool cupti_lazy_init(void)
{
	cupti_handle = dlopen("libcupti.so", RTLD_NOLOAD | RTLD_LAZY);
	if (cupti_handle) {
		run_ctx->cupti_dlhandle = (long)cupti_handle;
		vlog("Found libcupti.so (handle %lx)!\n", (long)cupti_handle);
	} else {
		/* call dlerror() regardless to clear error */
		const char *err_msg = dlerror();
		vlog("Failed to find libcupti.so: %s!\n", err_msg);
	}

	for (int i = 0; i < ARRAY_SIZE(cupti_resolve_syms); i++) {
		const char *sym_name = cupti_resolve_syms[i].sym_name;
		void **sym_pptr = (void **)cupti_resolve_syms[i].sym_pptr;
		*sym_pptr = dyn_resolve_sym(sym_name);
		if (!*sym_pptr)
			return false;
	}

	cupti_ok = true;
	return true;
}

static CUpti_ActivityKind cupti_act_kinds[] = {
	CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL,
	CUPTI_ACTIVITY_KIND_MEMCPY,
};

static const char *cupti_act_kind_strs[] = {
	[CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL] = "CONCURRENT_KERNEL",
	[CUPTI_ACTIVITY_KIND_MEMCPY] = "MEMCPY",
};

static const char *cupti_act_kind_str(CUpti_ActivityKind kind)
{
	if (kind < 0 || kind >= ARRAY_SIZE(cupti_act_kind_strs))
		return "???";

	return cupti_act_kind_strs[kind] ?: "???";
}

void finalize_cupti_activities(void);

/* Initialize CUPTI activity subscription */
int init_cupti_activities(void)
{
	CUptiResult ret;
	int err = 0;

	if (!cupti_lazy_init()) {
		elog("Failed to find and resolve CUPTI library!\n");
		return -ESRCH;
	}

	vlog("Initializing CUPTI activity subscription...\n");

	/* Register callbacks for activity buffer management */
	ret = cupti_activity_register_callbacks(buffer_requested, buffer_completed);
	if (ret != CUPTI_SUCCESS) {
		elog("Failed to register CUPTI activity callbacks: %d (%s)!\n",
		     ret, cupti_errstr(ret));
		return -EPROTO;
	}

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
	if (!cupti_ok)
		return;

	vlog("Flushing CUPTI activity buffers...\n");

	/* deactivate any activity we might have activated */
	for (int i = 0; i < ARRAY_SIZE(cupti_act_kinds); i++) {
		CUpti_ActivityKind kind = cupti_act_kinds[i];

		(void)cupti_activity_disable(kind);
	}

	/* drain buffers forcefully to avoid getting our callbacks called */
	(void)cupti_activity_flush_all(CUPTI_ACTIVITY_FLAG_FLUSH_FORCED);

	vlog("CUPTI activity API finalized.\n");

	cupti_ok = false;
}
