/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __ENV_H_
#define __ENV_H_

#include "utils.h"
#include "protobuf.h"
#include "wprof.h"

#define DEFAULT_RINGBUF_SZ (32 * 1024 * 1024)
#define DEFAULT_TASK_STATE_SZ (32 * 1024)

struct env {
	bool verbose;
	bool bpf_stats;
	bool libbpf_logs;
	bool breakout_counters;
	bool stack_traces;
	bool replay;
	int freq;
	int dur_ms;

	int ringbuf_sz;
	int task_state_sz;
	int ringbuf_cnt;

	u64 sess_start_ts;
	u64 sess_end_ts;

	char *data_path;
	char *trace_path;

	bool pb_debug_interns;
	bool pb_disable_interns;

	int counter_cnt;
	int counter_ids[MAX_PERF_COUNTERS];

	/* FILTERING */
	char **allow_pnames;
	int allow_pname_cnt;

	char **allow_tnames;
	int allow_tname_cnt;

	int *allow_pids;
	int allow_pid_cnt;

	int *allow_tids;
	int allow_tid_cnt;

	int *allow_cpus;
	int allow_cpu_cnt;
};

extern struct env env;
extern const struct argp argp;

struct perf_counter_def {
	const char *alias;
	int perf_type;
	int perf_cfg;
	double mul;
	const char *trace_name;
	u32 trace_name_iid;
};

extern const struct perf_counter_def perf_counter_defs[];

struct worker_state {
	struct str_iid_domain name_iids;

	FILE *trace;
	pb_ostream_t stream;

	FILE *dump;
	void *dump_mem;
	size_t dump_sz;
	struct wprof_data_hdr *dump_hdr;

	struct stack_frame_index *sframe_idx;
	size_t sframe_cap, sframe_cnt;
	struct stack_trace_index *strace_idx;
	size_t strace_cap, strace_cnt;
	struct stack_trace_iids strace_iids;
	struct str_iid_domain fname_iids;
	size_t next_stack_trace_id;

	/* stats */
	u64 rb_handled_cnt;
	u64 rb_handled_sz;
	u64 rb_ignored_cnt;
	u64 rb_ignored_sz;
} __attribute__((aligned(64)));

#define WPROF_DATA_MAJOR 1
#define WPROF_DATA_MINOR 0
#define WPROF_DATA_FLAG_INCOMPLETE 0xffffffffffffffffULL

struct wprof_data_hdr {
	char magic[6]; /* "WPROF\0" */
	u16 hdr_sz;
	u64 flags;
	int version_major;
	int version_minor;
	u64 events_off, events_sz;
	u64 stacks_off, stacks_sz;
} __attribute__((aligned(8)));

#endif /* __ENV_H_ */
