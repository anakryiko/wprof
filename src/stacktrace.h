/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __STACKTRACE_H_
#define __STACKTRACE_H_

#include <stddef.h>
#include "utils.h"
#include "wprof.h"
#include "env.h"
#include "pb_common.h"
#include "pb_encode.h"
#include "perfetto_trace.pb.h"

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
	       (tr->kstack_sz < 0 ? tr->kstack_sz : 0) +
	       (tr->ustack_sz < 0 ? tr->ustack_sz : 0);
}

int process_stack_traces(struct worker_state *w);
int event_stack_trace_id(struct worker_state *w, const struct wprof_event *e,
			 enum stack_trace_kind kind);
int generate_stack_traces(struct worker_state *w);

#endif /* __STACKTRACE_H_ */
