/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __WEVENT_H_
#define __WEVENT_H_

#include "wprof_types.h"
#include "wprof.h"

/*
 * Persisted event structures (wevent_*).
 *
 * These are compact versions of wprof_* structures optimized for storage:
 * - Strings replaced with offsets into a shared string pool
 * - Task info replaced with task_id; references into thread table
 * - PMU counter values replaced with ctrs_id references into values table
 */

/* Task (thread) info entry */
struct wevent_task {
	u32 tid;
	u32 pid;
	u32 flags;
	u32 comm_stroff;	/* offset into string pool */
	u32 pcomm_stroff;	/* offset into string pool */
};

/* PMU counter definition */
struct wevent_pmu_def {
	u32 perf_type;
	u32 name_stroff;	/* offset into string pool */
	u64 config;
	u64 config1;
	u64 config2;
};

/* Full persisted event - header followed by type-specific data */
struct wevent {
	u16 sz;				/* includes header size */
	u16 flags;
	enum event_kind kind;
	u32 task_id;
	u32 cpu;
	u32 numa_node;
	u64 ts;

	union {
		struct wevent_switch {
			u32 next_task_id;
			u32 waker_task_id;
			u32 pmu_vals_id;
			u32 offcpu_stack_id;
			enum waking_flags waking_flags;
			u64 waking_ts;
			u32 prev_task_state;
			u32 last_next_task_state;
			u32 prev_prio;
			u32 next_prio;
			u32 waker_cpu;
			u32 waker_numa_node;
			u32 next_task_scx_layer_id; /* sched-ext specific */
			u32 next_task_scx_dsq_id; /* sched-ext specific */
		} swtch;

		struct wevent_timer {
			u32 timer_stack_id;
		} timer;

		struct wevent_waking {
			u32 wakee_task_id;
			u32 waker_stack_id;
		} waking;

		struct wevent_wakeup_new {
			u32 wakee_task_id;
			u32 waker_stack_id;
		} wakeup_new;

		struct wevent_hardirq {
			u64 hardirq_ts;
			int irq;
			u32 name_stroff;
			u32 pmu_vals_id;
		} hardirq;

		struct wevent_softirq {
			u64 softirq_ts;
			int vec_nr;
			u32 pmu_vals_id;
		} softirq;

		struct wevent_wq_info {
			u64 wq_ts;
			u32 desc_stroff;
			u32 pmu_vals_id;
		} wq;

		struct wevent_fork {
			u32 child_task_id;
		} fork;

		struct wevent_exec {
			u32 old_tid;
			u32 filename_stroff;
		} exec;

		struct wevent_task_rename {
			u32 new_comm_stroff;
		} rename;

		struct wevent_task_exit {
		} task_exit;

		struct wevent_task_free {
		} task_free;

		struct wevent_ipi_send {
			u64 ipi_id;		/* 0 if unknown */
			enum wprof_ipi_kind kind;
			int target_cpu;		/* -1, if multicast IPI */
		} ipi_send;

		struct wevent_ipi_info {
			u64 ipi_ts;
			u64 send_ts;		/* 0, if unknown origination timestamp */
			u64 ipi_id;		/* 0, if unknown */
			enum wprof_ipi_kind kind;
			int send_cpu;		/* -1, if multicast IPI or unknown */
			u32 pmu_vals_id;
		} ipi;

		struct wevent_req_ctx {
			u64 req_ts;
			u64 req_id;
			enum wprof_req_event_kind req_event; /* START, END, SET, UNSET, CLEAR */
			u32 req_name_stroff;
		} req;

		struct wevent_req_task_ctx {
			enum wprof_req_event_kind req_task_event; /* ENQUEUE/DEQUEUE/STATS */
			u64 req_id;
			u64 req_task_id;
			u64 enqueue_ts;
			u64 wait_time_ns;
			u64 run_time_ns;
		} req_task;

		struct wevent_scx_dsq {
			u64 scx_dsq_insert_ts;
			u64 scx_dsq_id;
			u32 scx_layer_id;
			enum scx_dsq_insert_type scx_dsq_insert_type;
		} scx_dsq;

		/* CUDA activity events (from CUPTI) */
		struct wevent_cuda_api { /* host-side CUDA API call */
			u64 end_ts;
			u32 task_id;
			u32 corr_id;
			u32 cbid;
			u32 ret_val;
			u32 cuda_stack_id; /* comes from EV_CUDA_CALL (BPF-side) */
			u8 kind;
		} cuda_api;

		struct wevent_cuda_kernel {
			u64 end_ts;
			u32 name_stroff;
			u32 corr_id;
			u32 device_id;
			u32 ctx_id;
			u32 stream_id;
			u32 grid_x, grid_y, grid_z;
			u32 block_x, block_y, block_z;
		} cuda_kernel;

		struct wevent_cuda_memcpy {
			u64 end_ts;
			u64 byte_cnt;
			u32 corr_id;
			u32 device_id;
			u32 ctx_id;
			u32 stream_id;
			u8 copy_kind;
			u8 src_kind;
			u8 dst_kind;
		} cuda_memcpy;

		struct wevent_cuda_memset {
			u64 end_ts;
			u64 byte_cnt;
			u32 corr_id;
			u32 device_id;
			u32 ctx_id;
			u32 stream_id;
			u32 value;
			u8 mem_kind;
		} cuda_memset;

		struct wevent_cuda_sync {
			u64 end_ts;
			u32 corr_id;
			u32 stream_id;
			u32 ctx_id;
			u32 event_id;
			u8 sync_type;
		} cuda_sync;
	};
};

#define WEVENT_SZ(kind) offsetofend(struct wevent, kind)

/*
 * Get the fixed size of a wevent (not including trailing stack traces).
 * Returns 0 for unknown event kinds.
 */
static inline size_t wevent_fixed_sz(const struct wevent *e)
{
	switch (e->kind) {
	case EV_SWITCH:		return WEVENT_SZ(swtch);
	case EV_TIMER:		return WEVENT_SZ(timer);
	case EV_WAKING:		return WEVENT_SZ(waking);
	case EV_WAKEUP_NEW:	return WEVENT_SZ(wakeup_new);
	case EV_HARDIRQ_EXIT:	return WEVENT_SZ(hardirq);
	case EV_SOFTIRQ_EXIT:	return WEVENT_SZ(softirq);
	case EV_WQ_END:		return WEVENT_SZ(wq);
	case EV_FORK:		return WEVENT_SZ(fork);
	case EV_EXEC:		return WEVENT_SZ(exec);
	case EV_TASK_RENAME:	return WEVENT_SZ(rename);
	case EV_TASK_EXIT:	return WEVENT_SZ(task_exit);
	case EV_TASK_FREE:	return WEVENT_SZ(task_free);
	case EV_IPI_SEND:	return WEVENT_SZ(ipi_send);
	case EV_IPI_EXIT:	return WEVENT_SZ(ipi);
	case EV_REQ_EVENT:	return WEVENT_SZ(req);
	case EV_REQ_TASK_EVENT:	return WEVENT_SZ(req_task);
	case EV_SCX_DSQ_END:	return WEVENT_SZ(scx_dsq);
	case EV_CUDA_KERNEL:	return WEVENT_SZ(cuda_kernel);
	case EV_CUDA_MEMCPY:	return WEVENT_SZ(cuda_memcpy);
	case EV_CUDA_MEMSET:	return WEVENT_SZ(cuda_memset);
	case EV_CUDA_SYNC:	return WEVENT_SZ(cuda_sync);
	case EV_CUDA_API:	return WEVENT_SZ(cuda_api);

	case EV_CUDA_CALL:	return 0; /* CUDA_CALL is "merged" into CUDA_API */
	default:		return 0;
	}
}

static inline const char *wevent_kind_name(enum event_kind kind)
{
	switch (kind) {
	case EV_SWITCH:		return "switch";
	case EV_TIMER:		return "timer";
	case EV_WAKING:		return "waking";
	case EV_WAKEUP_NEW:	return "wakeup_new";
	case EV_HARDIRQ_EXIT:	return "hardirq";
	case EV_SOFTIRQ_EXIT:	return "softirq";
	case EV_WQ_END:		return "wq";
	case EV_FORK:		return "fork";
	case EV_EXEC:		return "exec";
	case EV_TASK_RENAME:	return "task_rename";
	case EV_TASK_EXIT:	return "task_exit";
	case EV_TASK_FREE:	return "task_free";
	case EV_IPI_SEND:	return "ipi_send";
	case EV_IPI_EXIT:	return "ipi_exit";
	case EV_REQ_EVENT:	return "req_event";
	case EV_REQ_TASK_EVENT:	return "req_task_event";
	case EV_SCX_DSQ_END:	return "scx_dsq_end";
	case EV_CUDA_CALL:	return "cuda_call";
	case EV_CUDA_KERNEL:	return "cuda_kernel";
	case EV_CUDA_MEMCPY:	return "cuda_memcpy";
	case EV_CUDA_MEMSET:	return "cuda_memset";
	case EV_CUDA_SYNC:	return "cuda_sync";
	case EV_CUDA_API:	return "cuda_api";
	default:		return "unknown";
	}
}

#endif /* __WEVENT_H_ */
