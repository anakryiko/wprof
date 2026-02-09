/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __STACKTRACE_H_
#define __STACKTRACE_H_

#include <stddef.h>
#include "env.h"

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

u32 bpf_event_stack_id(const struct wprof_event *e, enum stack_trace_kind kind);

int process_stack_traces(struct worker_state *workers, int worker_cnt, FILE *stacks_file);
int generate_stack_traces(struct worker_state *w);

void mark_stack_trace_used(struct worker_state *w, int stack_id);

#if DEBUG_SYMBOLIZATION
void debug_dump_stack_traces(struct worker_state *w);
#endif

#endif /* __STACKTRACE_H_ */
