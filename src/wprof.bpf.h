/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __WPROF_BPF_H_
#define __WPROF_BPF_H_

#ifndef E2BIG
#define E2BIG		7
#endif
#ifndef ENODATA
#define ENODATA		61
#endif

#define __cleanup(callback) __attribute__((cleanup(callback)))

#define TASK_RUNNING 0

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

struct task_state {
	u64 waking_ts;
	u32 waking_flags;
	u32 waker_cpu;
	u32 waker_numa_node;
	u32 last_task_state;
	struct wprof_thread waker_task;
	u64 softirq_ts;
	u64 hardirq_ts;
	u64 wq_ts;
	char wq_name[WORKER_DESC_LEN];
	struct perf_counters hardirq_ctrs;
	struct perf_counters softirq_ctrs;
	struct perf_counters wq_ctrs;
	/* SCX-related fields, used by scx.bpf.c */
	struct wprof_scx_dsq scx_dsq;
};

__hidden int glob_match(const char *pat, size_t pat_sz, const char *str, size_t str_sz);
__hidden struct task_state *task_state(int pid);
__hidden int handle_dsq(u64 now_ts, struct task_struct *task, struct task_state *s);
__hidden void emit_scx_dsq_event(u64 end_ts, struct task_struct *task, struct task_state *s);

#endif /* __WPROF_BPF_H_ */
