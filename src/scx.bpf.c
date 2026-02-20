// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2025 Meta Platforms, Inc. */
/*
 * SCX (sched_ext) specific BPF functionality for wprof.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "wprof.h"
#include "wprof.bpf.h"

extern const volatile bool capture_scx;
extern const volatile bool capture_scx_layer_id;

/*
 * Partial definition of scx_layered's task_ctx – we only need the first
 * three fields (pid, last_cpu, layer_id).  The real struct is much larger
 * but BPF task-local-storage lookups return a pointer we can read from.
 */
struct scx_task_ctx {
	int pid;
	int last_cpu;
	u32 layer_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct scx_task_ctx);
} scx_task_ctxs SEC(".maps");

/* handlers for tracking DSQ insertions - modeled after scxtop's on_insert() */
static int on_dsq_insert(struct task_struct *p, u64 dsq, enum scx_dsq_insert_type insert_type)
{
	struct task_state *scur;

	if (!capture_scx)
		return 0;

	scur = task_state(p->pid);
	if (!scur)
		return 0;

	scur->scx_dsq.scx_dsq_insert_ts = bpf_ktime_get_ns();
	scur->scx_dsq.scx_dsq_id = dsq;
	/* read layer_id from scx_layered's task_ctx if available */
	scur->scx_dsq.scx_layer_id = -1;
	if (capture_scx_layer_id) {
		struct scx_task_ctx *sctx = bpf_task_storage_get(&scx_task_ctxs, p, NULL, 0);

		if (sctx)
			scur->scx_dsq.scx_layer_id = sctx->layer_id;
	}
	scur->scx_dsq.scx_dsq_insert_type = insert_type;

	return 0;
}

SEC("?fentry/scx_bpf_dsq_insert")
int BPF_PROG(wprof_dsq_insert, struct task_struct *p, u64 dsq)
{
	return on_dsq_insert(p, dsq, SCX_DSQ_INSERT);
}

SEC("?fentry/scx_bpf_dispatch")
int BPF_PROG(wprof_dispatch, struct task_struct *p, u64 dsq)
{
	return on_dsq_insert(p, dsq, SCX_DSQ_DISPATCH);
}

SEC("?fentry/scx_bpf_dsq_insert_vtime")
int BPF_PROG(wprof_dsq_insert_vtime, struct task_struct *p, u64 dsq, u64 slice_ns, u64 vtime)
{
	return on_dsq_insert(p, dsq, SCX_DSQ_INSERT_VTIME);
}

SEC("?fentry/scx_bpf_dispatch_vtime")
int BPF_PROG(wprof_dispatch_vtime, struct task_struct *p, u64 dsq, u64 slice_ns, u64 vtime)
{
	return on_dsq_insert(p, dsq, SCX_DSQ_DISPATCH_VTIME);
}

__hidden int handle_dsq(u64 now_ts, struct task_struct *task, struct task_state *s)
{
	if (s->scx_dsq.scx_dsq_insert_ts == 0) /* we never recorded matching start, ignore */
		return 0;

	emit_scx_dsq_event(now_ts, task, s);

	s->scx_dsq.scx_dsq_insert_ts = 0;

	return 0;
}

static int on_dsq_move(struct task_struct *p, u64 dsq, enum scx_dsq_insert_type insert_type)
{
	struct task_state *scur;
	u64 now_ts;

	if (!capture_scx)
		return 0;

	scur = task_state(p->pid);
	if (!scur)
		return 0;

	now_ts = bpf_ktime_get_ns();
	/* record data for previous dsq for this task */
	handle_dsq(now_ts, p, scur);

	scur->scx_dsq.scx_dsq_insert_ts = now_ts;
	scur->scx_dsq.scx_dsq_id = dsq;
	/* read layer_id from scx_layered's task_ctx if available */
	scur->scx_dsq.scx_layer_id = -1;
	if (capture_scx_layer_id) {
		struct scx_task_ctx *sctx = bpf_task_storage_get(&scx_task_ctxs, p, NULL, 0);

		if (sctx)
			scur->scx_dsq.scx_layer_id = sctx->layer_id;
	}
	scur->scx_dsq.scx_dsq_insert_type = insert_type;

	return 0;
}

SEC("?fentry/scx_bpf_dsq_move")
int BPF_PROG(wprof_dsq_move, void *it__iter,
	     struct task_struct *p, u64 dsq_id, u64 enq_flags)
{
	return on_dsq_move(p, dsq_id, SCX_DSQ_MOVE);
}

SEC("?fentry/scx_bpf_dispatch_from_dsq")
int BPF_PROG(wprof_dispatch_from_dsq, void *it__iter,
	     struct task_struct *p, u64 dsq_id, u64 enq_flags)
{
	return on_dsq_move(p, dsq_id, SCX_DSQ_DISPATCH_FROM_DSQ);
}

SEC("?fentry/scx_bpf_dsq_move_vtime")
int BPF_PROG(wprof_dsq_move_vtime, void *it__iter,
	     struct task_struct *p, u64 dsq_id, u64 enq_flags)
{
	return on_dsq_move(p, dsq_id, SCX_DSQ_MOVE_VTIME);
}

SEC("?fentry/scx_bpf_dispatch_vtime_from_dsq")
int BPF_PROG(wprof_dispatch_vtime_from_dsq, void *it__iter,
	     struct task_struct *p, u64 dsq_id, u64 enq_flags)
{
	return on_dsq_move(p, dsq_id, SCX_DSQ_DISPATCH_VTIME_FROM_DSQ);
}
