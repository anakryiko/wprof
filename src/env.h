/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __ENV_H_
#define __ENV_H_

#include "utils.h"
#include "protobuf.h"
#include "wprof.h"
#include "data.h"
#include "cuda.h"

#define WPROF_VERSION "0.3-dev"

#define DEFAULT_RINGBUF_SZ (16 * 1024 * 1024)
#define DEFAULT_TASK_STATE_SZ (32 * 1024)

#define DEFAULT_TIMER_FREQ_HZ 100
#define DEFAULT_DURATION_MS 1000
#define DEFAULT_REQUESTED_STACK_TRACES ST_NONE
#define DEFAULT_CAPTURE_IPIS FALSE
#define DEFAULT_CAPTURE_REQUESTS FALSE
#define DEFAULT_CAPTURE_SCX_LAYER_INFO FALSE
#define DEFAULT_CAPTURE_CUDA FALSE

extern bool env_verbose;
extern int env_debug_level;
extern enum log_subset env_log_set;

enum cuda_discover_strategy {
	CUDA_DISCOVER_NONE, /* no automatic discovery */
	CUDA_DISCOVER_SMI,  /* use nvidia-smi (default) */
	CUDA_DISCOVER_PROC, /* find processes with libcupti.so */
};

struct env {
	bool verbose;
	int debug_level;
	enum log_subset log_set;
	bool stats;
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

	enum stack_trace_kind requested_stack_traces;

	/* data capture features */
	enum tristate capture_ipis;
	enum tristate capture_requests;
	enum tristate capture_req_experimental; /* experimental extra request-related events */
	enum tristate capture_scx_layer_info;
	enum tristate capture_cuda;

	/* trace visualization features */
	bool emit_sched_view;
	bool emit_numa;
	bool emit_tidpid;
	bool emit_timer_ticks;
	bool emit_req_extras;
	bool emit_sched_extras;

	int timer_freq_hz;

	int pmu_event_cnt;
	struct pmu_event pmu_events[MAX_PMU_COUNTERS];

	int ringbuf_sz;
	int task_state_sz;
	size_t ringbuf_cnt;

	u64 actual_start_ts;
	u64 sess_start_ts;
	u64 sess_end_ts;

	char *data_path;
	char *trace_path;

	bool pb_debug_interns;
	bool pb_disable_interns;
	bool keep_workdir;

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

	/* EXPERIMENTAL (CUDA tracking) */
	int *cuda_pids;
	int cuda_pid_cnt;
	enum cuda_discover_strategy cuda_discovery;

	struct cuda_tracee *cudas;
	int cuda_cnt;
	bool cudas_deactivated;
	bool cudas_retracted;

	/* persisted data header, set after merge or before replay */
	struct wprof_data_hdr *data_hdr;
};

extern struct env env;
extern const struct argp argp;

static inline bool cfg_get_capture_ipis(const struct wprof_data_cfg *cfg) { return cfg->capture_ipis; }
static inline void cfg_set_capture_ipis(struct wprof_data_cfg *cfg, bool val) { cfg->capture_ipis = val; }

static inline bool cfg_get_capture_reqs(const struct wprof_data_cfg *cfg) { return cfg->capture_requests; }
static inline void cfg_set_capture_reqs(struct wprof_data_cfg *cfg, bool val) { cfg->capture_requests = val; }

static inline bool cfg_get_capture_req_experimental(const struct wprof_data_cfg *cfg) { return cfg->capture_req_experimental; }
static inline void cfg_set_capture_req_experimental(struct wprof_data_cfg *cfg, bool val) { cfg->capture_req_experimental = val; }

static inline bool cfg_get_capture_scx_layer_info(const struct wprof_data_cfg *cfg) { return cfg->capture_scx_layer_info; }
static inline void cfg_set_capture_scx_layer_info(struct wprof_data_cfg *cfg, bool val) { cfg->capture_scx_layer_info = val; }

static inline bool cfg_get_capture_cuda(const struct wprof_data_cfg *cfg) { return cfg->capture_cuda; }
static inline void cfg_set_capture_cuda(struct wprof_data_cfg *cfg, bool val) { cfg->capture_cuda = val; }

struct capture_feature {
	const char *name;
	const char *header;
	enum tristate default_val;
	size_t env_flag_off;
	bool (*cfg_get_flag)(const struct wprof_data_cfg *cfg);
	void (*cfg_set_flag)(struct wprof_data_cfg *cfg, bool val);
};

extern const struct capture_feature capture_features[];
extern const int capture_feature_cnt;

struct worker_state {
	int worker_id;
	struct str_iid_domain name_iids;

	FILE *trace;
	pb_ostream_t stream;

	FILE *dump;
	char *dump_path;
	void *dump_mem;
	size_t dump_sz;
	struct wprof_data_hdr *dump_hdr;
	struct ring_buffer *rb_manager;

	/* stack trace usage markers */
	u64 *stacks_used; /* bitmask */
	u64 *frames_used; /* bitmask */

	/* ftrace event buffering per-CPU */
	struct ftrace_cpu_bundle *ftrace_bundles;
	int ftrace_bundle_cnt;

	/* stats */
	u64 rb_handled_cnt;
	u64 rb_handled_sz;
	u64 rb_ignored_cnt;
	u64 rb_ignored_sz;
} __attribute__((aligned(64)));

#endif /* __ENV_H_ */
