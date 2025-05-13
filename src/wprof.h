/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __WPROF_BPF_H_
#define __WPROF_BPF_H_

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef WORKER_DESC_LEN
#define WORKER_DESC_LEN 32
#endif

#define TASK_COMM_FULL_LEN (2 * TASK_COMM_LEN + 4)

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 128
#endif

#define MAX_PERF_COUNTERS 6

#ifndef PF_WQ_WORKER
#define PF_WQ_WORKER 0x00000020
#endif
#ifndef PF_KTHREAD
#define PF_KTHREAD 0x00200000
#endif

enum wprof_filt_mode {
	FILT_ALLOW_PID = 0x01,
	FILT_ALLOW_TID = 0x02,
	FILT_ALLOW_PNAME = 0x04,
	FILT_ALLOW_TNAME = 0x08,
};

struct wprof_stats {
	u64 rb_drops;
	u64 task_state_drops;
	u64 rb_misses;
};

enum task_status {
	STATUS_UNKNOWN,
	STATUS_ON_CPU,
	STATUS_OFF_CPU,
	STATUS_IRQ,
};

enum event_kind {
	EV_INVALID,

	EV_TIMER,
	EV_SWITCH_FROM,
	EV_SWITCH_TO,
	EV_WAKEUP_NEW,
	EV_WAKEUP,
	EV_WAKING,
	EV_HARDIRQ_EXIT,
	EV_SOFTIRQ_EXIT,
	EV_WQ_END,
	EV_FORK,
	EV_EXEC,
	EV_TASK_RENAME,
	EV_TASK_EXIT,
	EV_TASK_FREE,
};

struct stack_trace {
	int stack_id;
	int kstack_sz;
	int ustack_sz;;
	u64 addrs[MAX_STACK_DEPTH * 2];
};

struct wprof_task {
	u32 tid;
	u32 pid;
	u32 flags;
	char comm[TASK_COMM_FULL_LEN];
	char pcomm[TASK_COMM_LEN];
};

struct perf_counters {
	u64 val[MAX_PERF_COUNTERS];
};

enum waking_flags {
	WF_UNKNOWN,
	WF_WOKEN,
	WF_WOKEN_NEW,
	WF_PREEMPTED,
};

enum event_flags {
	EF_NONE = 0x00,
	EF_STACK_TRACE = 0x01,
};

struct wprof_event {
	u32 sz; /* fixed part size */
	u32 flags;
	enum event_kind kind;
	u32 cpu;
	u32 numa_node;
	u64 ts;
	struct wprof_task task;

	union {
		struct wprof_switch_from {
			struct wprof_task next;
			struct perf_counters ctrs;
		} swtch_from;
		struct wprof_switch_to {
			struct wprof_task prev;
			struct wprof_task waking;
			u64 waking_ts;
			u32 waking_cpu;
			u32 waking_numa_node;
			enum waking_flags waking_flags;
			struct perf_counters ctrs;
		} swtch_to;
		struct wprof_timer {
		} timer;
		struct wprof_hardirq {
			u64 hardirq_ts;
			int irq;
			char name[WORKER_DESC_LEN + TASK_COMM_LEN];
			struct perf_counters ctrs;
		} hardirq;
		struct wprof_softirq {
			u64 softirq_ts;
			int vec_nr;
			struct perf_counters ctrs;
		} softirq;
		struct wprof_wq_info {
			u64 wq_ts;
			char desc[WORKER_DESC_LEN];
			struct perf_counters ctrs;
		} wq;
		struct wprof_task_rename {
			char new_comm[TASK_COMM_LEN];
		} rename;
		struct wprof_fork {
			struct wprof_task child;
		} fork;
		struct wprof_exec {
			int old_tid;
			char filename[WORKER_DESC_LEN - 4];
		} exec;
	};
};

#ifndef offsetofend
#define offsetofend(TYPE, MEMBER) (offsetof(TYPE, MEMBER) + sizeof((((TYPE *)0)->MEMBER)))
#endif

#define EV_SZ(kind) offsetofend(struct wprof_event, kind)

#endif /* __WPROF_BPF_H_ */
