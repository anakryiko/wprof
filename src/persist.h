/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __PERSIST_H_
#define __PERSIST_H_

#include "wprof_types.h"
#include "wprof.h"
#include "cuda_data.h"
#include "wevent.h"
#include "pmu.h"

struct strset;
struct hashmap;

struct thread_table {
	struct hashmap *lookup;		/* hash(tid, pid, comm, pcomm) -> task_id */
	struct wevent_task *entries;
	u32 count;
	u32 capacity;
};

struct pmu_vals_table {
	FILE *dump;			/* file-backed storage for PMU values */
	u32 count;
	int pmu_cnt;			/* number of counters per entry */
};

struct persist_state {
	struct strset *strs;
	struct thread_table threads;
	struct pmu_vals_table pmu_vals;
	struct wevent_pmu_def *pmu_defs;
	int pmu_def_cnt;
	struct hashmap *tid_cache;	/* (host_pid, ns_tid) -> tid_cache_value for CUDA TID resolution */
	struct hashmap *thread_states;	/* host TID -> cuda_thread_state (corr_id, stack_id) */
};

int persist_state_init(struct persist_state *ps, int pmu_cnt);
void persist_state_free(struct persist_state *ps);

int persist_task_id(struct persist_state *ps, const struct wprof_thread *task);
int persist_pmu_vals_id(struct persist_state *ps, const struct perf_counters *ctrs);
int persist_stroff(struct persist_state *ps, const char *str);
int persist_add_pmu_def(struct persist_state *ps, const struct pmu_event *ev);
int persist_bpf_event(struct persist_state *ps, const struct wprof_event *e, struct wevent *dst);
int persist_cuda_event(struct persist_state *ps, const struct wcuda_event *e, struct wevent *dst,
		       int host_pid, const char *proc_name, const char *cuda_strs);

#endif /* __PERSIST_H_ */
