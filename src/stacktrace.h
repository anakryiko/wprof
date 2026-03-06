/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __STACKTRACE_H_
#define __STACKTRACE_H_

#include <stddef.h>
#include "env.h"
#include "pysym.h"

#define DEBUG_SYMBOLIZATION 0

struct stack_trace_index {
	struct stack_trace *strace;
	int orig_idx;
	int pid;
	int start_frame_idx;
	int frame_cnt;
	int callstack_iid;
	int kframe_cnt;
	bool combine;
	int mapped_frame_idx;
	int mapped_frame_cnt;
};

struct stack_frame_index {
	int pid;
	int orig_idx;
	int orig_pid;
	u64 addr;
	const struct blaze_sym *sym;
	int frame_cnt;
	/* if sym has no inlined frames */
	int frame_iid;
	/* if sym has inlined frames */
	int *frame_iids;
};

static inline int stack_trace_sz(const struct stack_trace *tr)
{
	return offsetof(struct stack_trace, addrs) +
	       (tr->kstack_sz < 0 ? 0 : tr->kstack_sz) +
	       (tr->ustack_sz < 0 ? 0 : tr->ustack_sz);
}

static inline size_t bpf_event_pmu_vals_sz(const struct wprof_event *e)
{
	if (!(e->flags & EF_PMU_VALS))
		return 0;
	int pmu_cnt = env.data_hdr ? env.data_hdr->pmu_def_real_cnt : env.pmu_real_cnt;
	return pmu_cnt * sizeof(u64);
}

static inline const u64 *bpf_event_pmu_vals(const struct wprof_event *e)
{
	if (!(e->flags & EF_PMU_VALS))
		return NULL;
	return (const u64 *)((void *)e + e->sz);
}

static inline size_t bpf_event_stack_traces_sz(const struct wprof_event *e)
{
	enum stack_trace_kind st_mask = e->flags & EF_STACK_TRACE_MSK;
	size_t total = 0;

	if (!st_mask)
		return 0;

	const struct stack_trace *tr = (void *)e + e->sz + bpf_event_pmu_vals_sz(e);
	while (st_mask) {
		size_t sz = stack_trace_sz(tr);
		total += sz;
		st_mask &= ~tr->kind;
		tr = (const void *)tr + sz;
	}
	return total;
}

static inline const void *bpf_event_pystack(const struct wprof_event *e)
{
	if (!(e->flags & EF_PYSTACK))
		return NULL;
	return (void *)e + e->sz + bpf_event_pmu_vals_sz(e) + bpf_event_stack_traces_sz(e);
}

u32 bpf_event_stack_id(const struct wprof_event *e, enum stack_trace_kind kind);
u32 bpf_event_any_stack_id(const struct wprof_event *e);

static inline u32 bpf_event_pystack_id(const struct wprof_event *e)
{
	const struct pystack_msg *pymsg = bpf_event_pystack(e);

	if (!pymsg)
		return 0;
	return pymsg->pystack_id;
}

int process_stack_traces(struct worker_state *workers, int worker_cnt, FILE *stacks_file);
int generate_stack_traces(struct worker_state *w);

const char *format_stack_frame(struct wprof_data_hdr *hdr, const struct wprof_stack_frame *f,
			       char *buf, size_t buf_sz, bool include_offset);

void mark_stack_trace_used(struct worker_state *w, int stack_id);

#if DEBUG_SYMBOLIZATION
void debug_dump_stack_traces(struct worker_state *w);
#endif

#endif /* __STACKTRACE_H_ */
