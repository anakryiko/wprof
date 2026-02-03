/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __WPROF_H_
#define __WPROF_H_

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef WORKER_DESC_LEN
#define WORKER_DESC_LEN 32
#endif

#define FILEPATH_LEN 64
#define REQ_NAME_LEN 64

#define TASK_COMM_FULL_LEN (2 * TASK_COMM_LEN + 4)

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 128
#endif

#define MAX_PMU_COUNTERS 8

#ifndef PF_WQ_WORKER
#define PF_WQ_WORKER 0x00000020
#endif
#ifndef PF_KTHREAD
#define PF_KTHREAD 0x00200000
#endif

#ifndef TASK_RUNNING
#define TASK_RUNNING 0
#endif

#define WPROF_GLOB_SZ 32
struct glob_str { char pat[WPROF_GLOB_SZ]; };

enum wprof_filt_mode {
	FILT_ALLOW_PID = 0x01,
	FILT_ALLOW_TID = 0x02,
	FILT_ALLOW_PNAME = 0x04,
	FILT_ALLOW_TNAME = 0x08,

	FILT_ALLOW_IDLE = 0x10,
	FILT_ALLOW_KTHREAD = 0x20,

	FILT_DENY_PID = FILT_ALLOW_PID << 16,
	FILT_DENY_TID = FILT_ALLOW_TID << 16,
	FILT_DENY_PNAME = FILT_ALLOW_PNAME << 16,
	FILT_DENY_TNAME = FILT_ALLOW_TNAME << 16,
	FILT_DENY_IDLE = FILT_ALLOW_IDLE << 16,
	FILT_DENY_KTHREAD = FILT_ALLOW_KTHREAD << 16,
};

struct wprof_stats {
	u64 rb_handled;
	u64 rb_drops;
	u64 rb_rescues;
	u64 rb_misses;
	u64 task_state_drops;
	u64 req_state_drops;
};

enum event_kind {
	EV_INVALID = 0,

	EV_TIMER = 1,
	EV_SWITCH = 2,
	EV_WAKEUP_NEW = 3,
	EV_WAKEUP = 4,
	EV_WAKING = 5,
	EV_HARDIRQ_EXIT = 6,
	EV_SOFTIRQ_EXIT = 7,
	EV_WQ_END = 8,
	EV_FORK = 9,
	EV_EXEC = 10,
	EV_TASK_RENAME = 11,
	EV_TASK_EXIT = 12,
	EV_TASK_FREE = 13,
	EV_IPI_SEND = 14,
	EV_IPI_EXIT = 15,
	EV_REQ_EVENT = 16,
	EV_REQ_TASK_EVENT = 17,
	EV_SCX_DSQ_END = 18,
	EV_CUDA_CALL = 19,
};

enum stack_trace_kind {
	ST_NONE = 0,

	ST_TIMER		= 1 << 0, /* regular interval timer event */
	ST_OFFCPU		= 1 << 1, /* context switch out (thread going off-CPU) */
	ST_WAKER		= 1 << 2, /* thread being marked runnable, waker-side stack trace */
	ST_CUDA			= 1 << 3, /* CUDA API calls */

	__ST_LAST,
	ST_ANY = (__ST_LAST - 1) * 2 - 1,
	ST_ALL = ST_ANY,		  /* alias */

	ST_DEFAULT = ST_TIMER | ST_OFFCPU,

	ST_ERR = -1LL,
	ST_UNSET = -1LL,
};

struct stack_trace {
	int stack_id;
	enum stack_trace_kind kind;
	int pid;
	short kstack_sz;
	short ustack_sz;;
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
	u64 val[MAX_PMU_COUNTERS];
};

enum waking_flags {
	WF_UNKNOWN,
	WF_WOKEN,
	WF_WOKEN_NEW,
	WF_PREEMPTED,
};

enum event_flags {
	EF_NONE = 0x00,
	EF_STACK_TRACE_MSK = ST_ALL, /* bit mask of all captured stack traces */
};

enum wprof_ipi_kind {
	IPI_INVALID = 0,

	IPI_SINGLE,
	IPI_MULTI,
	IPI_RESCHED,

	NR_IPIS,
};

enum wprof_req_event_kind {
	REQ_BEGIN = 10,
	REQ_SET = 11,
	REQ_UNSET = 12,
	REQ_END = 13,
	REQ_CLEAR = 14,

	REQ_TASK_ENQUEUE = 15,
	REQ_TASK_DEQUEUE = 16,
	REQ_TASK_STATS = 17,
};

enum scx_dsq_insert_type {
	SCX_DSQ_INSERT = 0,
	SCX_DSQ_INSERT_VTIME = 1,
	SCX_DSQ_DISPATCH = 2,
	SCX_DSQ_DISPATCH_VTIME = 3,
	SCX_DSQ_MOVE = 4,
	SCX_DSQ_MOVE_VTIME = 5,
	SCX_DSQ_DISPATCH_FROM_DSQ = 6,
	SCX_DSQ_DISPATCH_VTIME_FROM_DSQ = 7,
};

struct wprof_event {
	u16 sz; /* fixed part size */
	u16 flags;
	enum event_kind kind;
	u64 ts;

	u32 cpu;
	u32 numa_node;
	struct wprof_task task;

	char __wprof_data[0]; /* marker field */

	union {
		struct wprof_switch {
			struct wprof_task next;
			struct wprof_task waker;
			struct perf_counters ctrs;
			u64 waking_ts;
			u32 prev_task_state;
			u32 last_next_task_state;
			u32 prev_prio;
			u32 next_prio;
			u32 waker_cpu;
			u32 waker_numa_node;
			enum waking_flags waking_flags;
			int next_task_scx_layer_id; /* sched-ext specific */
			int next_task_scx_dsq_id; /* sched-ext specific */
		} swtch;
		struct wprof_timer {
		} timer;
		struct wprof_waking {
			struct wprof_task wakee;
		} waking;
		struct wprof_wakeup_new {
			struct wprof_task wakee;
		} wakeup_new;
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
			char filename[FILEPATH_LEN];
		} exec;
		struct wprof_ipi_send {
			u64 ipi_id; /* 0, if unknown */
			enum wprof_ipi_kind kind;
			int target_cpu; /* -1, if multicast IPI */
		} ipi_send;
		struct wprof_ipi_info {
			u64 ipi_ts;
			u64 send_ts; /* 0, if unknown origination timestamp */
			u64 ipi_id; /* 0, if unknown */
			enum wprof_ipi_kind kind;
			int send_cpu; /* -1, if multicast IPI or unknown */
			struct perf_counters ctrs;
		} ipi;
		struct wprof_req_ctx {
			u64 req_ts; /* request start timestamp */
			u64 req_id;
			enum wprof_req_event_kind req_event; /* lifecycle event (START, END, SET, UNSET, CLEAR) */
			char req_name[REQ_NAME_LEN];
		} req;
		struct wprof_req_task_ctx {
			enum wprof_req_event_kind req_task_event; /* ENQUEUE/DEQUEUE/STATS */
			u64 req_id;
			u64 task_id;
			u64 enqueue_ts;
			u64 wait_time_ns;
			u64 run_time_ns;
		} req_task;
		struct wprof_scx_dsq {
			u64 scx_dsq_insert_ts;
			u64 scx_dsq_id;
			u32 scx_layer_id;
			enum scx_dsq_insert_type scx_dsq_insert_type;
		} scx_dsq;
		struct wprof_cuda_call {
			int domain;
			int cbid;
			u32 corr_id;
		} cuda_call;
	};
};

#ifndef offsetofend
#define offsetofend(TYPE, MEMBER) (offsetof(TYPE, MEMBER) + sizeof((((TYPE *)0)->MEMBER)))
#endif

#define EV_SZ(kind) offsetofend(struct wprof_event, kind)

#endif /* __WPROF_H_ */
