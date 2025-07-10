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

#define DEFAULT_TIMER_FREQ_HZ 100
#define DEFAULT_DURATION_MS 1000
#define DEFAULT_CAPTURE_STACK_TRACES FALSE
#define DEFAULT_CAPTURE_IPIS FALSE
#define DEFAULT_CAPTURE_REQUESTS FALSE

struct env {
	bool verbose;
	bool debug;
	bool stats;
	bool libbpf_logs;
	bool breakout_counters;
	bool replay;
	bool replay_info;
	bool symbolize_frugally;

	/* data collection configuration */
	u64 ktime_start_ns;
	u64 realtime_start_ns;
	u64 duration_ns;

	/* for replay only, mutually exclusive with duration_ns */
	s64 replay_start_offset_ns;
	s64 replay_end_offset_ns;

	enum tristate capture_stack_traces;
	enum tristate capture_ipis;
	enum tristate capture_requests;

	int timer_freq_hz;

	int counter_cnt;
	int counter_ids[MAX_PERF_COUNTERS];
	int counter_pos[MAX_PERF_COUNTERS];

	int ringbuf_sz;
	int task_state_sz;
	int ringbuf_cnt;

	/* feature selector */
	bool emit_numa;
	bool emit_tidpid;
	bool emit_timer_ticks;

	u64 actual_start_ts;
	u64 sess_start_ts;
	u64 sess_end_ts;

	char *data_path;
	char *trace_path;

	bool pb_debug_interns;
	bool pb_disable_interns;

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

	/* EXPERIMENTAL (request tracking) */
	char **req_paths;
	int req_path_cnt;
	int *req_pids;
	int req_pid_cnt;
	bool req_global_discovery;

	struct hashmap *req_binaries;
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
	char *dump_path;
	void *dump_mem;
	size_t dump_sz;
	struct wprof_data_hdr *dump_hdr;
	struct ring_buffer *rb_manager;

	/* stats */
	u64 rb_handled_cnt;
	u64 rb_handled_sz;
	u64 rb_ignored_cnt;
	u64 rb_ignored_sz;
} __attribute__((aligned(64)));

#endif /* __ENV_H_ */
