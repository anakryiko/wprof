// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Meta Platforms, Inc. */
#include "wevent.h"
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include "hashmap.h"
#include "utils.h"
#include "protobuf.h"
#include "wprof.h"
#include "data.h"
#include "env.h"
#include "stacktrace.h"
#include "cuda_data.h"
#include "wprof_cupti.h"
#include "demangle.h"

static const char *event_kind_str_map[] = {
	/* BPF-produced events */
	[EV_TIMER] = "TIMER",
	[EV_PMU_EVENT] = "PMU_EVENT",
	[EV_SWITCH] = "SWITCH",
	[EV_WAKEUP_NEW] = "WAKEUP_NEW",
	//[EV_WAKEUP] = "WAKEUP",
	[EV_WAKING] = "WAKING",
	[EV_HARDIRQ_EXIT] = "HARDIRQ_EXIT",
	[EV_SOFTIRQ_EXIT] = "SOFTIRQ_EXIT",
	[EV_WQ_END] = "WQ_END",
	[EV_FORK] = "FORK",
	[EV_EXEC] = "EXEC",
	[EV_TASK_RENAME] = "TASK_RENAME",
	[EV_TASK_EXIT] = "TASK_EXIT",
	[EV_TASK_FREE] = "TASK_FREE",
	[EV_IPI_SEND] = "IPI_SEND",
	[EV_IPI_EXIT] = "IPI_EXIT",
	[EV_REQ_EVENT] = "REQ_EVENT",
	[EV_SCX_DSQ_END] = "SCX_DSQ_END",
	[EV_CUDA_CALL] = "CUDA_CALL",

	/* CUDA/CUPTI-produced events */
	[EV_CUDA_KERNEL] = "CUDA_KERNEL",
	[EV_CUDA_MEMCPY] = "CUDA_MEMCPY",
	[EV_CUDA_MEMSET] = "CUDA_MEMSET",
	[EV_CUDA_SYNC] = "CUDA_SYNC",
	[EV_CUDA_API] = "CUDA_API",

	/* Python function tracing events */
	[EV_PYTRACE_ENTRY] = "PYTRACE_ENTRY",
	[EV_PYTRACE_EXIT] = "PYTRACE_EXIT",

	/* PyTorch RecordFunction events */
	[EV_PYTORCH_ENTRY] = "PYTORCH_ENTRY",
	[EV_PYTORCH_EXIT] = "PYTORCH_EXIT",
};

const char *event_kind_str(enum event_kind kind)
{
	if (kind >= 0 && kind < ARRAY_SIZE(event_kind_str_map))
		return event_kind_str_map[kind] ?: "UNKNOWN";
	return "UNKNOWN";
}

struct wprof_tsidx_ent *wdata_tsidx_lookup(struct wprof_data_hdr *hdr, u64 start_ts)
{
	struct wprof_tsidx_ent *idx;
	int l, r, m;

	if (env.no_tsidx || hdr->tsidx_cnt == 0)
		return NULL;

	idx = wdata_tsidx_ent(hdr, 0);

	/*
	 * No checkpoint at/before start_ts -> scan from the first event. Each
	 * checkpoint is the first event of its timestamp and checkpoint ts values
	 * strictly increase, so ts <= start_ts safely lands on (or just before)
	 * the window without risk of skipping equal-ts events.
	 */
	if (ts_after(idx[0].ts, start_ts))
		return NULL;

	/*
	 * Loop invariant: idx[l].ts <= start_ts, which idx[0] satisfies (checked
	 * above). Find the rightmost such entry; tie-break to the right so we
	 * converge (see find_linfo() in the kernel's bpf/log.c).
	 */
	l = 0;
	r = hdr->tsidx_cnt - 1;
	while (l < r) {
		m = l + (r - l + 1) / 2;
		if (ts_before_or_at(idx[m].ts, start_ts))
			l = m;
		else
			r = m - 1;
	}

	return &idx[l];
}

int process_events(struct worker_state *w, handle_event_fn *handlers, size_t handler_cnt)
{
	struct wevent_record *rec;
	const struct wevent *e;
	handle_event_fn handler;
	int err;

	wevent_for_each_event(rec, w->dump_hdr, env.sess_start_ts, env.sess_end_ts) {
		e = rec->e;

		if (e->kind >= handler_cnt || !(handler = handlers[e->kind]))
			BUG("unhandled event at offset %zu kind %s (%d)\n",
			    (void *)e - (void *)w->dump_hdr, event_kind_str(e->kind), e->kind);

		err = handler(w, rec->e);
		if (err) {
			eprintf("Failed to process event at offset %zu (kind %s %d): %d\n",
				(void *)rec->e - (void *)w->dump_hdr,
				event_kind_str(rec->e->kind), rec->e->kind, err);
			return err; /* YEAH, I know about all the clean up, whatever */
		}
	}

	return 0;
}
