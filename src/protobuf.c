// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "protobuf.h"
#include "env.h"
#include "utils.h"
#include "data.h"
#include "emit.h"

int wpb_stream_write(void *ctx, const uint8_t *buf, size_t count)
{
	FILE *file = ctx;

	return fwrite(buf, 1, count, file) == count ? 0 : -EIO;
}

static struct wpb_str wpb_cstr(const char *s)
{
	if (!s)
		return (struct wpb_str){};
	return (struct wpb_str){ .s = s, .len = strlen(s) };
}

static struct wpb_str wpb_strn(const char *s, size_t len)
{
	return (struct wpb_str){ .s = s, .len = len };
}

static const char *softirq_str_map[] = {
	[HI_SOFTIRQ] = "hi",
	[TIMER_SOFTIRQ] = "timer",
	[NET_TX_SOFTIRQ] = "net-tx",
	[NET_RX_SOFTIRQ] = "net-rx",
	[BLOCK_SOFTIRQ] = "block",
	[IRQ_POLL_SOFTIRQ] = "irq-poll",
	[TASKLET_SOFTIRQ] = "tasklet",
	[SCHED_SOFTIRQ] = "sched",
	[HRTIMER_SOFTIRQ] = "hrtimer",
	[RCU_SOFTIRQ] = "rcu",
};

const char *softirq_str(int vec_nr)
{
	if (vec_nr >= 0 && vec_nr < ARRAY_SIZE(softirq_str_map))
		return softirq_str_map[vec_nr];
	return NULL;
}

const char *ipi_kind_str(enum wprof_ipi_kind kind)
{
	switch (kind) {
		case IPI_SINGLE: return "single";
		case IPI_MULTI:  return "multi";
		case IPI_RESCHED: return "resched";
		default: return "???";
	}
}

static const char *wreason_str_map[] = {
	[WREASON_UNKNOWN] = "unknown",
	[WREASON_WOKEN] = "woken",
	[WREASON_WOKEN_NEW] = "woken_new",
	[WREASON_PREEMPTED] = "preempted",
	[WREASON_INVALID] = "???",
};

enum waking_reason wreason_enum(enum waking_flags flags)
{
	switch (flags) {
		case WF_UNKNOWN:   return WREASON_UNKNOWN;
		case WF_WOKEN:     return WREASON_WOKEN;
		case WF_WOKEN_NEW: return WREASON_WOKEN_NEW;
		case WF_PREEMPTED: return WREASON_PREEMPTED;
		default:           return WREASON_UNKNOWN;
	}
}

const char *wreason_str(enum waking_flags flags)
{
	return wreason_str_map[wreason_enum(flags)];
}

static const char *cuda_memcpy_kind_str_map[] = {
	[CUDA_MEMCPY_UNKN] = "???",
	[CUDA_MEMCPY_HTOD] = "HtoD",	/* CUPTI_ACTIVITY_MEMCPY_KIND_HTOD */
	[CUDA_MEMCPY_DTOH] = "DtoH",	/* CUPTI_ACTIVITY_MEMCPY_KIND_DTOH */
	[CUDA_MEMCPY_HTOA] = "HtoA",	/* CUPTI_ACTIVITY_MEMCPY_KIND_HTOA */
	[CUDA_MEMCPY_ATOH] = "AtoH",	/* CUPTI_ACTIVITY_MEMCPY_KIND_ATOH */
	[CUDA_MEMCPY_ATOA] = "AtoA",	/* CUPTI_ACTIVITY_MEMCPY_KIND_ATOA */
	[CUDA_MEMCPY_ATOD] = "AtoD",	/* CUPTI_ACTIVITY_MEMCPY_KIND_ATOD */
	[CUDA_MEMCPY_DTOA] = "DtoA",	/* CUPTI_ACTIVITY_MEMCPY_KIND_DTOA */
	[CUDA_MEMCPY_DTOD] = "DtoD",	/* CUPTI_ACTIVITY_MEMCPY_KIND_DTOD */
	[CUDA_MEMCPY_HTOH] = "HtoH",	/* CUPTI_ACTIVITY_MEMCPY_KIND_HTOH */
	[CUDA_MEMCPY_PTOP] = "PtoP",	/* CUPTI_ACTIVITY_MEMCPY_KIND_PTOP */
};

const char* cuda_memcpy_kind_str(enum cuda_memcpy_kind kind)
{
	if (kind > CUDA_MEMCPY_UNKN && kind < NR_CUDA_MEMCPY_KIND)
		return cuda_memcpy_kind_str_map[kind];
	return cuda_memcpy_kind_str_map[CUDA_MEMCPY_UNKN];
}

static const char *cuda_memory_kind_str_map[] = {
	[0] = "???",			/* CUPTI_ACTIVITY_MEMORY_KIND_UNKNOWN */
	[1] = "pageable",		/* CUPTI_ACTIVITY_MEMORY_KIND_PAGEABLE */
	[2] = "pinned",			/* CUPTI_ACTIVITY_MEMORY_KIND_PINNED */
	[3] = "device",			/* CUPTI_ACTIVITY_MEMORY_KIND_DEVICE */
	[4] = "array",			/* CUPTI_ACTIVITY_MEMORY_KIND_ARRAY */
	[5] = "managed",		/* CUPTI_ACTIVITY_MEMORY_KIND_MANAGED */
	[6] = "device_static",		/* CUPTI_ACTIVITY_MEMORY_KIND_DEVICE_STATIC */
	[7] = "managed_static",		/* CUPTI_ACTIVITY_MEMORY_KIND_MANAGED_STATIC */
};

const char *cuda_memory_kind_str(int kind)
{
	if (kind > 0 && kind < ARRAY_SIZE(cuda_memory_kind_str_map))
		return cuda_memory_kind_str_map[kind];
	return cuda_memory_kind_str_map[0];
}

static const char *cuda_sync_type_str_map[] = {
	[0] = "???",			/* CUPTI_ACTIVITY_SYNCHRONIZATION_TYPE_UNKNOWN */
	[1] = "event_sync",		/* CUPTI_ACTIVITY_SYNCHRONIZATION_TYPE_EVENT_SYNCHRONIZE */
	[2] = "stream_wait_event",	/* CUPTI_ACTIVITY_SYNCHRONIZATION_TYPE_STREAM_WAIT_EVENT */
	[3] = "stream_sync",		/* CUPTI_ACTIVITY_SYNCHRONIZATION_TYPE_STREAM_SYNCHRONIZE */
	[4] = "context_sync",		/* CUPTI_ACTIVITY_SYNCHRONIZATION_TYPE_CONTEXT_SYNCHRONIZE */
};

const char *cuda_sync_type_str(int type)
{
	if (type > 0 && type < ARRAY_SIZE(cuda_sync_type_str_map))
		return cuda_sync_type_str_map[type];
	return cuda_sync_type_str_map[0];
}

/*
 * PROTOBUF UTILS
 */
static const char *pb_static_strs[] = {
	[IID_CAT_ONCPU] = "ONCPU",
	[IID_CAT_OFFCPU] = "OFFCPU",
	[IID_CAT_HARDIRQ] = "HARDIRQ",
	[IID_CAT_SOFTIRQ] = "SOFTIRQ",
	[IID_CAT_WQ] = "WQ",
	[IID_CAT_TIMER] = "TIMER",
	[IID_CAT_EXEC] = "EXEC",
	[IID_CAT_EXIT] = "EXIT",
	[IID_CAT_FREE] = "FREE",
	[IID_CAT_WAKEUP] = "WAKEUP",
	[IID_CAT_WAKER_NEW] = "WAKER_NEW",
	[IID_CAT_WAKEE_NEW] = "WAKEE_NEW",
	[IID_CAT_WAKER] = "WAKER",
	[IID_CAT_WAKEE] = "WAKEE",
	[IID_CAT_PREEMPTOR] = "PREEMPTOR",
	[IID_CAT_PREEMPTEE] = "PREEMPTEE",
	[IID_CAT_WAKER_UNKN] = "WAKER_UNKNOWN",
	[IID_CAT_WAKEE_UNKN] = "WAKEE_UNKNOWN",
	[IID_CAT_FORKING] = "FORKING",
	[IID_CAT_FORKED] = "FORKED",
	[IID_CAT_RENAME] = "RENAME",
	[IID_CAT_IPI] = "IPI",
	[IID_CAT_IPI_SEND] = "IPI_SEND",
	[IID_CAT_REQUEST] = "REQUEST",
	[IID_CAT_REQUEST_THREAD] = "REQUEST_THREAD",
	[IID_CAT_REQUEST_ONCPU] = "REQUEST_ONCPU",
	[IID_CAT_REQUEST_OFFCPU] = "REQUEST_OFFCPU",
	[IID_CAT_REQUEST_BEGIN] = "REQUEST_BEGIN",
	[IID_CAT_REQUEST_SET] = "REQUEST_SET",
	[IID_CAT_REQUEST_UNSET] = "REQUEST_UNSET",
	[IID_CAT_REQUEST_END] = "REQUEST_END",
	[IID_CAT_REQUEST_TASK_ENQUEUE] = "REQUEST_TASK_ENQUEUE",
	[IID_CAT_REQUEST_TASK_DEQUEUE] = "REQUEST_TASK_DEQUEUE",
	[IID_CAT_REQUEST_TASK_COMPLETE] = "REQUEST_TASK_COMPLETE",
	[IID_CAT_CUDA_KERNEL] = "CUDA_KERNEL",
	[IID_CAT_CUDA_MEMCPY] = "CUDA_MEMCPY",
	[IID_CAT_CUDA_API] = "CUDA_API",
	[IID_CAT_CUDA_MEMSET] = "CUDA_MEMSET",
	[IID_CAT_CUDA_SYNC] = "CUDA_SYNC",
	[IID_CAT_SCX_DSQ] = "SCX_DSQ",
	[IID_CAT_PYTRACE] = "PYTRACE",
	[IID_CAT_PYTORCH] = "PYTORCH",
	[IID_CAT_UTRACE] = "UTRACE",
	[IID_CAT_TIMER_CALLSTACK] = "TIMER_CALLSTACK",

	[IID_NAME_TIMER] = "TIMER",
	[IID_NAME_EXEC] = "EXEC",
	[IID_NAME_EXIT] = "EXIT",
	[IID_NAME_FREE] = "FREE",
	[IID_NAME_WAKEUP] = "WAKEUP",
	[IID_NAME_WAKER_NEW] = "WAKER_NEW",
	[IID_NAME_WAKEE_NEW] = "WAKEE_NEW",
	[IID_NAME_WAKER] = "WAKER",
	[IID_NAME_WAKEE] = "WAKEE",
	[IID_NAME_PREEMPTOR] = "PREEMPTOR",
	[IID_NAME_PREEMPTEE] = "PREEMPTEE",
	[IID_NAME_WAKER_UNKN] = "WAKER_UNKNOWN",
	[IID_NAME_WAKEE_UNKN] = "WAKEE_UNKNOWN",
	[IID_NAME_FORKING] = "FORKING",
	[IID_NAME_FORKED] = "FORKED",
	[IID_NAME_RENAME] = "RENAME",
	[IID_NAME_HARDIRQ] = "HARDIRQ",
	[IID_NAME_SOFTIRQ + HI_SOFTIRQ] = "SOFTIRQ:hi",
	[IID_NAME_SOFTIRQ + TIMER_SOFTIRQ] = "SOFTIRQ:timer",
	[IID_NAME_SOFTIRQ + NET_TX_SOFTIRQ] = "SOFTIRQ:net-tx",
	[IID_NAME_SOFTIRQ + NET_RX_SOFTIRQ] = "SOFTIRQ:net-rx",
	[IID_NAME_SOFTIRQ + BLOCK_SOFTIRQ] = "SOFTIRQ:block",
	[IID_NAME_SOFTIRQ + IRQ_POLL_SOFTIRQ] = "SOFTIRQ:irq-poll",
	[IID_NAME_SOFTIRQ + TASKLET_SOFTIRQ] = "SOFTIRQ:tasklet",
	[IID_NAME_SOFTIRQ + SCHED_SOFTIRQ] = "SOFTIRQ:sched",
	[IID_NAME_SOFTIRQ + HRTIMER_SOFTIRQ] = "SOFTIRQ:hrtimer",
	[IID_NAME_SOFTIRQ + RCU_SOFTIRQ] = "SOFTIRQ:rcu",
	[IID_NAME_IPI + IPI_INVALID] = "IPI:???",
	[IID_NAME_IPI + IPI_SINGLE] = "IPI:single",
	[IID_NAME_IPI + IPI_MULTI] = "IPI:multi",
	[IID_NAME_IPI + IPI_RESCHED] = "IPI:resched",
	[IID_NAME_IPI_SEND + IPI_INVALID] = "IPI_SEND:???",
	[IID_NAME_IPI_SEND + IPI_SINGLE] = "IPI_SEND:single",
	[IID_NAME_IPI_SEND + IPI_MULTI] = "IPI_SEND:multi",
	[IID_NAME_IPI_SEND + IPI_RESCHED] = "IPI_SEND:resched",
	[IID_NAME_RUNNING] = "RUNNING",
	[IID_NAME_WAITING] = "WAITING",
	[IID_NAME_PREEMPTED] = "PREEMPTED",
	[IID_NAME_REQUEST_BEGIN] = "REQUEST_BEGIN",
	[IID_NAME_REQUEST_SET] = "REQUEST_SET",
	[IID_NAME_REQUEST_UNSET] = "REQUEST_UNSET",
	[IID_NAME_REQUEST_END] = "REQUEST_END",
	[IID_NAME_REQUEST_TASK_ENQUEUE] = "REQUEST_TASK_ENQUEUE",
	[IID_NAME_REQUEST_TASK_DEQUEUE] = "REQUEST_TASK_DEQUEUE",
	[IID_NAME_REQUEST_TASK_COMPLETE] = "REQUEST_TASK_COMPLETE",
	[IID_NAME_CUDA_MEMCPY + CUDA_MEMCPY_UNKN] = "memcpy:???",
	[IID_NAME_CUDA_MEMCPY + CUDA_MEMCPY_HTOD] = "memcpy:HtoD",
	[IID_NAME_CUDA_MEMCPY + CUDA_MEMCPY_DTOH] = "memcpy:DtoH",
	[IID_NAME_CUDA_MEMCPY + CUDA_MEMCPY_HTOA] = "memcpy:HtoA",
	[IID_NAME_CUDA_MEMCPY + CUDA_MEMCPY_ATOH] = "memcpy:AtoH",
	[IID_NAME_CUDA_MEMCPY + CUDA_MEMCPY_ATOA] = "memcpy:AtoA",
	[IID_NAME_CUDA_MEMCPY + CUDA_MEMCPY_ATOD] = "memcpy:AtoD",
	[IID_NAME_CUDA_MEMCPY + CUDA_MEMCPY_DTOA] = "memcpy:DtoA",
	[IID_NAME_CUDA_MEMCPY + CUDA_MEMCPY_DTOD] = "memcpy:DtoD",
	[IID_NAME_CUDA_MEMCPY + CUDA_MEMCPY_HTOH] = "memcpy:HtoH",
	[IID_NAME_CUDA_MEMCPY + CUDA_MEMCPY_PTOP] = "memcpy:PtoP",
	[IID_NAME_CUDA_MEMSET + CUDA_MEM_UNKN] = "memset:???",
	[IID_NAME_CUDA_MEMSET + CUDA_MEM_PAGEABLE] = "memset:pageable",
	[IID_NAME_CUDA_MEMSET + CUDA_MEM_PINNED] = "memset:pinned",
	[IID_NAME_CUDA_MEMSET + CUDA_MEM_DEVICE] = "memset:device",
	[IID_NAME_CUDA_MEMSET + CUDA_MEM_ARRAY] = "memset:array",
	[IID_NAME_CUDA_MEMSET + CUDA_MEM_MANAGED] = "memset:managed",
	[IID_NAME_CUDA_MEMSET + CUDA_MEM_DEVICE_STATIC] = "memset:device_static",
	[IID_NAME_CUDA_MEMSET + CUDA_MEM_MANAGED_STATIC] = "memset:managed_static",
	[IID_NAME_CUDA_SYNC + CUDA_SYNC_UNKN] = "sync:???",
	[IID_NAME_CUDA_SYNC + CUDA_SYNC_EVENT_SYNC] = "sync:event_sync",
	[IID_NAME_CUDA_SYNC + CUDA_SYNC_STREAM_WAIT_EVENT] = "sync:stream_wait_event",
	[IID_NAME_CUDA_SYNC + CUDA_SYNC_STREAM_SYNC] = "sync:stream_sync",
	[IID_NAME_CUDA_SYNC + CUDA_SYNC_CONTEXT_SYNC] = "sync:context_sync",

	[IID_ANNK_CPU] = "cpu",
	[IID_ANNK_NUMA_NODE] = "numa_node",
	[IID_ANNK_SWITCH_TO] = "switch_to",
	[IID_ANNK_SWITCH_TO_TID] = "switch_to_tid",
	[IID_ANNK_SWITCH_TO_PID] = "switch_to_pid",
	[IID_ANNK_SWITCH_FROM] = "switch_from",
	[IID_ANNK_SWITCH_FROM_TID] = "switch_from_tid",
	[IID_ANNK_SWITCH_FROM_PID] = "switch_from_pid",
	[IID_ANNK_RENAMED_TO] = "renamed_to",
	[IID_ANNK_WAKER_CPU] = "waker_cpu",
	[IID_ANNK_WAKER_NUMA_NODE] = "waker_numa_node",
	[IID_ANNK_WAKING_DELAY_US] = "waking_delay_us",
	[IID_ANNK_COMPOUND_DELAY_US] = "compound_delay_us",
	[IID_ANNK_COMPOUND_CHAIN_LEN] = "compound_chain_len",
	[IID_ANNK_WAKER] = "waker",
	[IID_ANNK_WAKER_TID] = "waker_tid",
	[IID_ANNK_WAKER_PID] = "waker_pid",
	[IID_ANNK_WAKING_REASON] = "waking_reason",
	[IID_ANNK_OFFCPU_REASON] = "offcpu_reason",
	[IID_ANNK_OFFCPU_DUR_US] = "offcpu_dur_us",
	[IID_ANNK_WAKEE] = "wakee",
	[IID_ANNK_WAKEE_TID] = "wakee_tid",
	[IID_ANNK_WAKEE_PID] = "wakee_pid",
	[IID_ANNK_FORKED_INTO] = "forked_into",
	[IID_ANNK_FORKED_INTO_TID] = "forked_into_tid",
	[IID_ANNK_FORKED_INTO_PID] = "forked_into_pid",
	[IID_ANNK_FORKED_FROM] = "forked_from",
	[IID_ANNK_FORKED_FROM_TID] = "forked_from_tid",
	[IID_ANNK_FORKED_FROM_PID] = "forked_from_pid",
	[IID_ANNK_FILENAME] = "filename",
	[IID_ANNK_TID_CHANGED_FROM] = "tid_changed_from",
	[IID_ANNK_OLD_NAME] = "old_name",
	[IID_ANNK_NEW_NAME] = "new_name",
	[IID_ANNK_ACTION] = "action",
	[IID_ANNK_IRQ] = "irq",
	[IID_ANNK_SENDER_CPU] = "sender_cpu",
	[IID_ANNK_TARGET_CPU] = "target_cpu",
	[IID_ANNK_IPI_DELAY_US] = "ipi_delay_us",
	[IID_ANNK_REQ_NAME] = "req_name",
	[IID_ANNK_REQ_ID] = "req_id",
	[IID_ANNK_REQ_LATENCY_US] = "req_latency_us",
	[IID_ANNK_SCX_LAYER_ID] = "scx_layer_id",
	[IID_ANNK_SCX_DSQ_ID] = "scx_dsq_id",
	[IID_ANNK_REQ_TASK_ID] = "task_id",
	[IID_ANNK_REQ_WAIT_TIME_NS] = "wait_time_ns",
	[IID_ANNK_CUDA_DEVICE_ID] = "device_id",
	[IID_ANNK_CUDA_STREAM_ID] = "stream_id",
	[IID_ANNK_CUDA_BLOCK_X] = "block_x",
	[IID_ANNK_CUDA_BLOCK_Y] = "block_y",
	[IID_ANNK_CUDA_BLOCK_Z] = "block_z",
	[IID_ANNK_CUDA_GRID_X] = "grid_x",
	[IID_ANNK_CUDA_GRID_Y] = "grid_y",
	[IID_ANNK_CUDA_GRID_Z] = "grid_z",
	[IID_ANNK_CUDA_KIND] = "kind",
	[IID_ANNK_CUDA_BYTE_CNT] = "byte_cnt",
	[IID_ANNK_CUDA_SRC_KIND] = "src_kind",
	[IID_ANNK_CUDA_DST_KIND] = "dst_kind",
	[IID_ANNK_CUDA_CONTEXT_ID] = "context_id",
	[IID_ANNK_CUDA_EVENT_ID] = "event_id",
	[IID_ANNK_CUDA_MANGLED_NAME] = "mangled_name",
	[IID_ANNK_CUDA_GPU_DELAY_US] = "gpu_delay_us",
	[IID_ANNK_PYTRACE_FILE] = "file",
	[IID_ANNK_PYTRACE_LINENO] = "lineno",

	[IID_ANNV_SOFTIRQ_ACTION + HI_SOFTIRQ] = "hi",
	[IID_ANNV_SOFTIRQ_ACTION + TIMER_SOFTIRQ] = "timer",
	[IID_ANNV_SOFTIRQ_ACTION + NET_TX_SOFTIRQ] = "net-tx",
	[IID_ANNV_SOFTIRQ_ACTION + NET_RX_SOFTIRQ] = "net-rx",
	[IID_ANNV_SOFTIRQ_ACTION + BLOCK_SOFTIRQ] = "block",
	[IID_ANNV_SOFTIRQ_ACTION + IRQ_POLL_SOFTIRQ] = "irq-poll",
	[IID_ANNV_SOFTIRQ_ACTION + TASKLET_SOFTIRQ] = "tasklet",
	[IID_ANNV_SOFTIRQ_ACTION + SCHED_SOFTIRQ] = "sched",
	[IID_ANNV_SOFTIRQ_ACTION + HRTIMER_SOFTIRQ] = "hrtimer",
	[IID_ANNV_SOFTIRQ_ACTION + RCU_SOFTIRQ] = "rcu",

	[IID_ANNV_WAKING_REASON + WREASON_UNKNOWN] = "unknown",
	[IID_ANNV_WAKING_REASON + WREASON_WOKEN] = "woken",
	[IID_ANNV_WAKING_REASON + WREASON_WOKEN_NEW] = "woken_new",
	[IID_ANNV_WAKING_REASON + WREASON_PREEMPTED] = "preempted",
	[IID_ANNV_WAKING_REASON + WREASON_INVALID] = "???",

	[IID_ANNV_CUDA_MEMCPY_KIND + CUDA_MEMCPY_UNKN] = "???",
	[IID_ANNV_CUDA_MEMCPY_KIND + CUDA_MEMCPY_HTOD] = "HtoD",
	[IID_ANNV_CUDA_MEMCPY_KIND + CUDA_MEMCPY_DTOH] = "DtoH",
	[IID_ANNV_CUDA_MEMCPY_KIND + CUDA_MEMCPY_HTOA] = "HtoA",
	[IID_ANNV_CUDA_MEMCPY_KIND + CUDA_MEMCPY_ATOH] = "AtoH",
	[IID_ANNV_CUDA_MEMCPY_KIND + CUDA_MEMCPY_ATOA] = "AtoA",
	[IID_ANNV_CUDA_MEMCPY_KIND + CUDA_MEMCPY_ATOD] = "AtoD",
	[IID_ANNV_CUDA_MEMCPY_KIND + CUDA_MEMCPY_DTOA] = "DtoA",
	[IID_ANNV_CUDA_MEMCPY_KIND + CUDA_MEMCPY_DTOD] = "DtoD",
	[IID_ANNV_CUDA_MEMCPY_KIND + CUDA_MEMCPY_HTOH] = "HtoH",
	[IID_ANNV_CUDA_MEMCPY_KIND + CUDA_MEMCPY_PTOP] = "PtoP",

	[IID_ANNV_CUDA_MEMORY_KIND + CUDA_MEM_UNKN] = "???",
	[IID_ANNV_CUDA_MEMORY_KIND + CUDA_MEM_PAGEABLE] = "pageable",
	[IID_ANNV_CUDA_MEMORY_KIND + CUDA_MEM_PINNED] = "pinned",
	[IID_ANNV_CUDA_MEMORY_KIND + CUDA_MEM_DEVICE] = "device",
	[IID_ANNV_CUDA_MEMORY_KIND + CUDA_MEM_ARRAY] = "array",
	[IID_ANNV_CUDA_MEMORY_KIND + CUDA_MEM_MANAGED] = "managed",
	[IID_ANNV_CUDA_MEMORY_KIND + CUDA_MEM_DEVICE_STATIC] = "device_static",
	[IID_ANNV_CUDA_MEMORY_KIND + CUDA_MEM_MANAGED_STATIC] = "managed_static",

	[IID_ANNV_CUDA_SYNC_TYPE + CUDA_SYNC_UNKN] = "???",
	[IID_ANNV_CUDA_SYNC_TYPE + CUDA_SYNC_EVENT_SYNC] = "event_sync",
	[IID_ANNV_CUDA_SYNC_TYPE + CUDA_SYNC_STREAM_WAIT_EVENT] = "stream_wait_event",
	[IID_ANNV_CUDA_SYNC_TYPE + CUDA_SYNC_STREAM_SYNC] = "stream_sync",
	[IID_ANNV_CUDA_SYNC_TYPE + CUDA_SYNC_CONTEXT_SYNC] = "context_sync",

	[IID_ANNV_OFFCPU_BLOCKED] = "blocked",
	[IID_ANNV_OFFCPU_PREEMPTED] = "preempted",
};

const char *pb_static_str(enum pb_static_iid iid)
{
	if (iid < 0 || iid >= ARRAY_SIZE(pb_static_strs) || !pb_static_strs[iid]) {
		eprintf("Missing string value mapping for IID #%d!\n", iid);
		exit(1);
	}

	return pb_static_strs[iid];
}

void ids_reset(struct pb_id_set *ids)
{
	ids->cnt = 0;
}

void ids_append_id(struct pb_id_set *ids, u64 id)
{
	if (ids->cnt == ids->cap) {
		int new_cap = ids->cnt < 8 ? 8 : ids->cnt * 4 / 3;
		ids->ids = realloc(ids->ids, new_cap * sizeof(*ids->ids));
		ids->cap = new_cap;
	}
	ids->ids[ids->cnt] = id;
	ids->cnt += 1;
}

void anns_reset(struct pb_anns *anns)
{
	anns->cnt = 0;
}

struct pb_ann_val *anns_add_val(struct pb_anns *anns, pb_iid key_iid, const char *key)
{
	struct pb_ann *ann;

	if (anns->cnt == ARRAY_SIZE(anns->anns)) {
		eprintf("Annotations overflow!\n");
		exit(1);
	}

	ann = &anns->anns[anns->cnt];
	anns->cnt++;

	ann->name = key;
	ann->name_iid = key_iid;

	return &ann->val;
}

void anns_add_str(struct pb_anns *anns, pb_iid key_iid, const char *key,
			 pb_iid value_iid, const char *value)
{
	struct pb_ann_val *val = anns_add_val(anns, key_iid, key);

	if (value_iid && !env.pb_disable_interns) {
		val->kind = PB_ANN_STR_IID;
		val->val_str_iid = value_iid;
	} else {
		val->kind = PB_ANN_STR;
		val->val_str = value;
	}
}

void anns_add_uint(struct pb_anns *anns, pb_iid key_iid, const char *key, uint64_t value)
{
	struct pb_ann_val *val = anns_add_val(anns, key_iid, key);

	val->kind = PB_ANN_UINT;
	val->val_int = value;
}

void anns_add_int(struct pb_anns *anns, pb_iid key_iid, const char *key, int64_t value)
{
	struct pb_ann_val *val = anns_add_val(anns, key_iid, key);

	val->kind = PB_ANN_INT;
	val->val_int = value;
}

void anns_add_double(struct pb_anns *anns, pb_iid key_iid, const char *key, double value)
{
	struct pb_ann_val *val = anns_add_val(anns, key_iid, key);

	val->kind = PB_ANN_DOUBLE;
	val->val_double = value;
}

void reset_str_iids(struct pb_str_iids *iids)
{
	iids->cnt = 0;
}

void append_str_iid(struct pb_str_iids *iids, int iid, const char *s)
{
	if (iids->cnt == iids->cap) {
		int new_cap = iids->cnt < 1024 ? 1024 : iids->cnt * 4 / 3;
		iids->iids = realloc(iids->iids, new_cap * sizeof(*iids->iids));
		iids->strs = realloc(iids->strs, new_cap * sizeof(*iids->strs));
		iids->cap = new_cap;
	}
	iids->iids[iids->cnt] = iid;
	iids->strs[iids->cnt] = s;
	iids->cnt += 1;
}

void append_mapping_iid(struct pb_mapping_iids *iids, int iid, u64 start, u64 end, u64 offset)
{
	if (iids->cnt == iids->cap) {
		int new_cap = iids->cnt < 256 ? 256 : iids->cnt * 4 / 3;
		iids->mappings = realloc(iids->mappings, new_cap * sizeof(*iids->mappings));
		iids->cap = new_cap;
	}
	iids->mappings[iids->cnt].iid = iid;
	iids->mappings[iids->cnt].start = start;
	iids->mappings[iids->cnt].end = end;
	iids->mappings[iids->cnt].start_offset = offset;
	iids->cnt += 1;
}

void append_frame_iid(struct pb_frame_iids *iids, int iid, int mapping_iid, int fname_iid, u64 rel_pc)
{
	if (iids->cnt == iids->cap) {
		int new_cap = iids->cnt < 256 ? 256 : iids->cnt * 4 / 3;
		iids->frames = realloc(iids->frames, new_cap * sizeof(*iids->frames));
		iids->cap = new_cap;
	}
	iids->frames[iids->cnt].iid = iid;
	iids->frames[iids->cnt].mapping_id = mapping_iid;
	iids->frames[iids->cnt].function_name_id = fname_iid;
	iids->frames[iids->cnt].rel_pc = rel_pc;
	iids->cnt += 1;
}

void append_callstack_frame_iid(struct pb_callstack_iids *iids, int iid, int frame_iid)
{
	struct pb_callstack *cs = NULL;

	if (iids->cnt > 0 && iids->callstacks[iids->cnt - 1].iid == iid)
		cs = &iids->callstacks[iids->cnt - 1];

	if (!cs) {
		if (iids->cnt == iids->cap) {
			int new_cap = iids->cnt < 32 ? 32 : iids->cnt * 4 / 3;
			iids->callstacks = realloc(iids->callstacks, new_cap * sizeof(*iids->callstacks));
			iids->cap = new_cap;
		}
		iids->callstacks[iids->cnt].iid = iid;
		iids->callstacks[iids->cnt].frame_cnt = 0;
		iids->callstacks[iids->cnt].frame_ids = NULL;
		cs = &iids->callstacks[iids->cnt];

		iids->cnt += 1;
	}

	cs->frame_ids = realloc(cs->frame_ids, (cs->frame_cnt + 1) * sizeof(*cs->frame_ids));
	cs->frame_ids[cs->frame_cnt] = frame_iid;
	cs->frame_cnt++;
}

/*
 * Trace timestamps are emitted relative to the session start (see emit.c),
 * i.e. the trace timeline starts at 0 in the default BOOTTIME domain. Pair
 * that origin with the wall-clock time at session start so Perfetto can
 * render absolute timestamps. env.sess_start_ts already accounts for a
 * --replay-start offset, so the mapping stays correct for replay sub-windows.
 */
static void emit_clock_snapshot(struct wpb_writer *writer)
{
	wpb_emit_clock_snapshot(writer, ktime_to_realtime_ns(env.sess_start_ts));
}

/*
 * Look up a persisted WEXTRA_METADATA "key=value" pair by key, returning a
 * pointer to the value (NUL-terminated suffix) or NULL if absent.
 */
static const char *meta_lookup(struct wprof_data_hdr *hdr, const char *key)
{
	size_t klen = strlen(key);

	for (u64 i = 0; i < hdr->extra_cnt; i++) {
		struct wprof_extra_param *e = wevent_extra_param(hdr, i);
		if (e->kind != WEXTRA_METADATA)
			continue;
		const char *kv = wevent_str(hdr, e->stroff);
		if (strncmp(kv, key, klen) == 0 && kv[klen] == '=')
			return kv + klen + 1;
	}
	return NULL;
}

/*
 * Emit user-supplied metadata (-M pairs) plus the human-readable capture time
 * as Perfetto trace attributes. These surface in the UI Overview and the
 * trace_processor `metadata` table. hostname, kernel and arch are skipped
 * here as they are emitted via SystemInfo (system_name / system_release /
 * system_machine) instead.
 */
static void emit_metadata(struct wpb_writer *writer, struct wprof_data_hdr *hdr)
{
	const char *kernel = meta_lookup(hdr, "kernel");
	const char *hostname = meta_lookup(hdr, "hostname");
	const char *arch = meta_lookup(hdr, "arch");
	struct wpb_str hostname_str = wpb_cstr(hostname);
	struct wpb_str kernel_str = wpb_cstr(kernel);
	struct wpb_str arch_str = wpb_cstr(arch);
	uint32_t num_cpus = env.stats ? env.stats->cpu_cnt : 0;

	/*
	 * Perfetto's Utsname has no hostname/nodename field, so stash the
	 * hostname in `sysname` (normally the OS name) to surface it as
	 * system_name in the UI Overview; `machine` carries the architecture.
	 */
	wpb_emit_system_info(writer, &hostname_str, &kernel_str, &arch_str, num_cpus);

	/*
	 * Surface our capture UUID as Perfetto's trace_uuid so the UI/trace_processor
	 * "Trace ID" matches our `uuid=` metadata exactly. trace_processor renders the
	 * UUID as the big-endian 128-bit value (msb<<64 | lsb), so the first 8 string
	 * bytes map to msb (big-endian) and the last 8 to lsb (big-endian).
	 */
	const char *uuid = meta_lookup(hdr, "uuid");
	if (uuid) {
		unsigned int u[16];
		if (sscanf(uuid, "%2x%2x%2x%2x-%2x%2x-%2x%2x-%2x%2x-%2x%2x%2x%2x%2x%2x",
			   &u[0], &u[1], &u[2], &u[3], &u[4], &u[5], &u[6], &u[7],
			   &u[8], &u[9], &u[10], &u[11], &u[12], &u[13], &u[14], &u[15]) == 16) {
			int64_t msb = 0, lsb = 0;
			for (int i = 0; i < 8; i++)
				msb = (msb << 8) | (u[i] & 0xff);
			for (int i = 0; i < 8; i++)
				lsb = (lsb << 8) | (u[8 + i] & 0xff);
			wpb_emit_trace_uuid(writer, msb, lsb);
		}
	}

	struct wpb_attr *attrs = calloc(hdr->extra_cnt + 1, sizeof(*attrs));
	size_t attr_cnt = 0;

	for (u64 i = 0; i < hdr->extra_cnt; i++) {
		struct wprof_extra_param *e = wevent_extra_param(hdr, i);
		if (e->kind != WEXTRA_METADATA)
			continue;
		const char *kv = wevent_str(hdr, e->stroff);
		const char *eq = strchr(kv, '=');
		size_t key_len = eq ? (size_t)(eq - kv) : strlen(kv);
		const char *val = eq ? eq + 1 : "";
		if ((key_len == 8 && strncmp(kv, "hostname", 8) == 0) ||
		    (key_len == 6 && strncmp(kv, "kernel", 6) == 0) ||
		    (key_len == 4 && strncmp(kv, "arch", 4) == 0))
			continue;
		attrs[attr_cnt++] = (struct wpb_attr) {
			.key = wpb_strn(kv, key_len),
			.val = wpb_cstr(val),
		};
	}

	const char *ts = fmt_timestamp_ns(ktime_to_realtime_ns(env.sess_start_ts));
	attrs[attr_cnt++] = (struct wpb_attr) {
		.key = wpb_cstr("capture_time"),
		.val = wpb_cstr(ts),
	};

	wpb_emit_trace_attributes(writer, attrs, attr_cnt);
	free(attrs);
}

static void wpb_fill_static_interns(struct wpb_intern *interns, int start_id, int end_id)
{
	for (int id = start_id; id < end_id; id++) {
		const char *s = pb_static_str(id);
		interns[id - start_id] = (struct wpb_intern) {
			.iid = id,
			.s = s,
			.len = strlen(s),
		};
	}
}

int init_pb_trace(struct wpb_writer *writer, struct wprof_data_hdr *hdr)
{
	emit_clock_snapshot(writer);
	emit_metadata(writer, hdr);

	/*
	 * Emit fake instant event to establish strict zero timestamp; anchor it on
	 * the session track so that track sorts to the top of the timeline.
	 */
	struct wpb_intern cats[CAT_END_IID - CAT_START_IID];
	struct wpb_intern names[NAME_END_IID - NAME_START_IID];
	struct wpb_intern ann_names[ANNK_END_IID - ANNK_START_IID];
	struct wpb_intern ann_values[ANNV_END_IID - ANNV_START_IID];

	wpb_fill_static_interns(cats, CAT_START_IID, CAT_END_IID);
	wpb_fill_static_interns(names, NAME_START_IID, NAME_END_IID);
	wpb_fill_static_interns(ann_names, ANNK_START_IID, ANNK_END_IID);
	wpb_fill_static_interns(ann_values, ANNV_START_IID, ANNV_END_IID);

	struct wpb_interned_data start_data = {
		.event_categories = { .entries = cats, .cnt = ARRAY_SIZE(cats) },
		.event_names = { .entries = names, .cnt = ARRAY_SIZE(names) },
		.debug_annotation_names = { .entries = ann_names, .cnt = ARRAY_SIZE(ann_names) },
		.debug_annotation_string_values = { .entries = ann_values, .cnt = ARRAY_SIZE(ann_values) },
	};
	wpb_emit_trace_start(writer, session_track_uuid(), &start_data);

	if (env.pb_debug_interns) {
		struct { const char *name; int start, end; } ranges[] = {
			{"category", CAT_START_IID, CAT_END_IID},
			{"event_name", NAME_START_IID, NAME_END_IID},
			{"ann_name", ANNK_START_IID, ANNK_END_IID},
			{"ann_value", ANNV_START_IID, ANNV_END_IID},
		};

		for (int k = 0; k < ARRAY_SIZE(ranges); k++)
			for (int i = ranges[k].start; i < ranges[k].end; i++)
				eprintf("% 3d: %-20s [%s]\n", i, pb_static_strs[i] ?: "??????", ranges[k].name);
	}

	return 0;
}

pb_iid str_iid_for(struct str_iid_domain *d, const char *s, bool *new_iid, const char **out_str)
{
	long iid;
	char *sdup;
	struct hashmap_entry *entry;

	hashmap__for_each_key_entry(d->str_iids, entry, (long)s) {
		iid = entry->value;
		if (new_iid)
			*new_iid = false;
		if (out_str)
			*out_str = entry->pkey;
		return iid;
	}

	sdup = strdup(s);
	iid = d->next_str_iid++;

	hashmap__set(d->str_iids, sdup, iid, NULL, NULL);

	if (env.pb_debug_interns)
		eprintf("%03ld: %-20s [%s]\n", iid, sdup, d->domain_desc);
	if (new_iid)
		*new_iid = true;
	if (out_str)
		*out_str = sdup;

	return iid;
}

/*
 * FTRACE EVENT BUFFERING
 */
void ftrace_buffer_init(struct ftrace_event_buffer *buf)
{
	buf->events = NULL;
	buf->cnt = 0;
	buf->cap = 0;
}

void ftrace_buffer_reset(struct ftrace_event_buffer *buf)
{
	buf->cnt = 0;
}

void ftrace_buffer_free(struct ftrace_event_buffer *buf)
{
	free(buf->events);
	buf->events = NULL;
	buf->cnt = 0;
	buf->cap = 0;
}

struct wpb_ftrace_event *ftrace_buffer_add(struct ftrace_event_buffer *buf)
{
	if (buf->cnt >= buf->cap) {
		int new_cap = buf->cnt < 64 ? 64 : buf->cnt * 4 / 3;
		if (new_cap > MAX_FTRACE_EVENTS_PER_BUNDLE)
			new_cap = MAX_FTRACE_EVENTS_PER_BUNDLE;
		buf->events = realloc(buf->events, new_cap * sizeof(*buf->events));
		buf->cap = new_cap;
	}
	memset(&buf->events[buf->cnt], 0, sizeof(*buf->events));
	return &buf->events[buf->cnt++];
}
