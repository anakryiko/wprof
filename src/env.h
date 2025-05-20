/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __ENV_H_
#define __ENV_H_

#include "utils.h"
#include "protobuf.h"
#include "wprof.h"
#include "data.h"

#define DEFAULT_RINGBUF_SZ (32 * 1024 * 1024)
#define DEFAULT_TASK_STATE_SZ (32 * 1024)

struct env {
	bool verbose;
	bool stats;
	bool libbpf_logs;
	bool breakout_counters;
	bool stack_traces;
	bool replay;
	int freq;
	int dur_ms;

	int ringbuf_sz;
	int task_state_sz;
	int ringbuf_cnt;

	/* feature selector */
	bool capture_ipi;
	bool capture_numa;

	u64 actual_start_ts;
	u64 sess_start_ts;
	u64 sess_end_ts;

	char *data_path;
	char *trace_path;

	bool pb_debug_interns;
	bool pb_disable_interns;

	int counter_cnt;
	int counter_ids[MAX_PERF_COUNTERS];

	/* FILTERING */
	char **allow_pnames, **deny_pnames;
	int allow_pname_cnt, deny_pname_cnt;

	char **allow_tnames, **deny_tnames;
	int allow_tname_cnt, deny_tname_cnt;

	int *allow_pids, *deny_pids;
	int allow_pid_cnt, deny_pid_cnt;

	int *allow_tids, *deny_tids;
	int allow_tid_cnt, deny_tid_cnt;

	bool allow_idle, deny_idle;
	bool allow_kthread, deny_kthread;
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

	/* stats */
	u64 rb_handled_cnt;
	u64 rb_handled_sz;
	u64 rb_ignored_cnt;
	u64 rb_ignored_sz;
} __attribute__((aligned(64)));

#endif /* __ENV_H_ */
