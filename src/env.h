/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __ENV_H_
#define __ENV_H_

#include "utils.h"
#include "protobuf.h"
#include "wprof.h"
#include "data.h"
#include "cuda.h"
#include "pytrace.h"
#include "requests.h"
#include "utrace_cfg.h"

#define WPROF_VERSION "0.4"

#define DEFAULT_RINGBUF_SZ (16 * 1024 * 1024)
#define DEFAULT_TASK_STATE_SZ (32 * 1024)

#define DEFAULT_TIMER_FREQ_HZ 100
#define DEFAULT_DURATION_MS 1000
#define DEFAULT_REQUESTED_STACK_TRACES ST_NONE
#define DEFAULT_CAPTURE_IPIS FALSE
#define DEFAULT_CAPTURE_REQUESTS FALSE
#define DEFAULT_CAPTURE_SCX FALSE
#define DEFAULT_CAPTURE_CUDA FALSE
#define DEFAULT_CAPTURE_PYSTACKS FALSE
#define DEFAULT_CAPTURE_PYTRACE FALSE
#define DEFAULT_CAPTURE_TORCH_PROFILER FALSE
#define DEFAULT_CAPTURE_UTRACE FALSE
#define DEFAULT_CAPTURE_SOFTIRQ TRUE
#define DEFAULT_CAPTURE_HARDIRQ TRUE

extern bool env_verbose;
extern int env_debug_level;
extern enum log_subset env_log_set;

enum cuda_discover_strategy {
	CUDA_DISCOVER_NONE, /* no automatic discovery */
	CUDA_DISCOVER_SMI,  /* use nvidia-smi (default) */
	CUDA_DISCOVER_PROC, /* find processes with libcupti.so */
};

enum pystacks_discover_strategy {
	PYSTACKS_DISCOVER_NONE,      /* no automatic discovery */
	PYSTACKS_DISCOVER_PROC,      /* find Python processes via /proc scan (default) */
	PYSTACKS_DISCOVER_NV_SMI, /* use nvidia-smi to find GPU Python processes */
};

enum pytrace_discover_strategy {
	PYTRACE_DISCOVER_NONE,		/* no automatic discovery */
	PYTRACE_DISCOVER_PROC,		/* find Python processes via /proc scan (default) */
	PYTRACE_DISCOVER_NV_SMI,	/* use nvidia-smi to find GPU Python processes */
};

struct wprof_bpf;
struct req_list_cfg;

struct env {
	bool verbose;
	int debug_level;
	enum log_subset log_set;
	bool emit_stats;
	bool record;
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
	enum tristate capture_scx;
	enum tristate capture_cuda;
	enum tristate capture_pystacks;
	enum tristate capture_pytrace;
	enum tristate capture_pytorch;
	enum tristate capture_utrace;
	enum tristate capture_softirq;
	enum tristate capture_hardirq;

	/* trace visualization features */
	bool emit_sched_view;
	bool emit_numa;
	bool emit_tidpid;
	bool emit_timer_ticks;
	bool emit_sched_extras;
	bool emit_pystacks_only;
	bool emit_req_split;
	bool emit_req_embed;
	bool emit_embed_stacks;

	int timer_freq_hz;
	u64 timer_period_ns;	/* derived from timer_freq_hz */

	struct wprof_bpf *skel;
	const struct wprof_stats *stats;

	int pmu_real_cnt;
	struct pmu_event *pmu_reals;
	int pmu_deriv_cnt;
	struct pmu_event *pmu_derivs;
	int pmu_unresolved_cnt;
	struct pmu_event *pmu_unresolveds;

	/* request listing */
	bool req_list;
	struct req_list_cfg *req_list_cfg;

	int ringbuf_sz;
	int task_state_sz;
	size_t ringbuf_cnt;
	size_t num_cpus;

	u64 actual_start_ts;
	u64 sess_start_ts;
	u64 sess_end_ts;

	char *data_path;
	char *trace_path;
	char *json_path;
	bool output_sealed;

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

	/* EXPERIMENTAL (Python stacks) */
	int *pystacks_pids;
	int pystacks_pid_cnt;
	enum pystacks_discover_strategy pystacks_discovery;

	/* EXPERIMENTAL (Python function tracing) */
	int *pytrace_pids;
	int pytrace_pid_cnt;
	enum pytrace_discover_strategy pytrace_discovery;

	struct pytrace_tracee *pytraces;
	int pytrace_cnt;
	bool pytraces_deactivated;
	bool pytraces_retracted;

	/* nvidia-smi PID discovery (lazy, shared across features) */
	int *nv_smi_pids;
	int nv_smi_pid_cnt;
	bool nv_smi_discovered;

	/* user-defined tracing (utrace) */
	struct utrace_cfg *utrace_cfgs;
	int utrace_cfg_cnt;

	/* user-defined metadata (key=value pairs) */
	char **metadata;
	int metadata_cnt;

	/* persisted data header, set after merge or before replay */
	struct wprof_data_hdr *data_hdr;
};

extern struct env env;

static inline bool is_ts_in_range(u64 ts)
{
	if ((long long)(ts - env.sess_start_ts) < 0)
		return false;
	if ((long long)(ts - env.sess_end_ts) >= 0)
		return false;
	return true;
}

extern const struct argp argp;

struct capture_feature {
	const char *name;
	const char *header;
	const char *json_key;
	enum tristate default_val;
	size_t env_flag_off;
	u64 cfg_bit;
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

	/* request filtering for trace output */
	struct req_allowlist req_allowlist;

	/* stats */
	u64 rb_handled_cnt;
	u64 rb_handled_sz;
	u64 rb_ignored_cnt;
	u64 rb_ignored_sz;
} __attribute__((aligned(64)));

#endif /* __ENV_H_ */
