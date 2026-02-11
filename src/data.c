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
};

const char *event_kind_str(enum event_kind kind)
{
	if (kind >= 0 && kind < ARRAY_SIZE(event_kind_str_map))
		return event_kind_str_map[kind] ?: "UNKNOWN";
	return "UNKNOWN";
}

int process_events(struct worker_state *w, handle_event_fn *handlers, size_t handler_cnt)
{
	struct wevent_record *rec;
	const struct wevent *e;
	handle_event_fn handler;
	int err;

	wevent_for_each_event(rec, w->dump_hdr) {
		e = rec->e;

		if (!is_ts_in_range(e->ts))
			continue;

		if (e->kind >= handler_cnt || !(handler = handlers[e->kind])) {
			eprintf("UNHANDLED EVENT #%d KIND %s (%d)\n",
				rec->idx, event_kind_str(e->kind), e->kind);
			exit(1);
			return 0;
		}

		err = handler(w, rec->e);
		if (err) {
			eprintf("Failed to process event #%d (kind %s %d, offset %zu): %d\n",
				rec->idx, event_kind_str(rec->e->kind), rec->e->kind,
				(void *)rec->e - (void *)w->dump_hdr, err);
			return err; /* YEAH, I know about all the clean up, whatever */
		}
	}

	return 0;
}
