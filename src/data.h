/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __DATA_H_
#define __DATA_H_

#include "wprof_types.h"
#include "wprof.h"
#include "wevent.h"
#include "pmu.h"

#define WPROF_DATA_MAJOR 2
#define WPROF_DATA_MINOR 2
#define WPROF_DATA_FLAG_INCOMPLETE 0xffffffffffffffffULL

enum cfg_feature_bit {
	CFG_CAPTURE_IPIS	= 0x001,
	CFG_CAPTURE_REQUESTS	= 0x002,
	CFG_CAPTURE_SCX		= 0x004,
	CFG_CAPTURE_CUDA	= 0x008,
	CFG_CAPTURE_PYSTACKS	= 0x010,
	CFG_CAPTURE_PYTRACE	= 0x020,
	CFG_CAPTURE_PYTORCH	= 0x040,
	CFG_CAPTURE_UTRACE	= 0x080,
	CFG_CAPTURE_SOFTIRQ	= 0x100,
	CFG_CAPTURE_HARDIRQ	= 0x200,
};

struct wprof_data_cfg {
	u64 ktime_start_ns;
	u64 realtime_start_ns;
	u64 duration_ns;

	u64 capture_features;

	enum stack_trace_kind captured_stack_traces;

	int timer_freq_hz;
};

enum wprof_extra_param_kind {
	WEXTRA_INVALID = 0,
	WEXTRA_FILTER_PID_ALLOW,
	WEXTRA_FILTER_PID_DENY,
	WEXTRA_FILTER_TID_ALLOW,
	WEXTRA_FILTER_TID_DENY,
	WEXTRA_FILTER_PNAME_ALLOW,
	WEXTRA_FILTER_PNAME_DENY,
	WEXTRA_FILTER_TNAME_ALLOW,
	WEXTRA_FILTER_TNAME_DENY,
	WEXTRA_FILTER_IDLE_ALLOW,
	WEXTRA_FILTER_IDLE_DENY,
	WEXTRA_FILTER_KTHREAD_ALLOW,
	WEXTRA_FILTER_KTHREAD_DENY,
	WEXTRA_UTRACE_DEF,
	WEXTRA_METADATA,
	WEXTRA_STATS,
};

static inline const char *extra_param_kind_name(enum wprof_extra_param_kind kind)
{
	switch (kind) {
	case WEXTRA_FILTER_PID_ALLOW:	return "--pid";
	case WEXTRA_FILTER_PID_DENY:	return "--no-pid";
	case WEXTRA_FILTER_TID_ALLOW:	return "--tid";
	case WEXTRA_FILTER_TID_DENY:	return "--no-tid";
	case WEXTRA_FILTER_PNAME_ALLOW:	return "--process-name";
	case WEXTRA_FILTER_PNAME_DENY:	return "--no-process-name";
	case WEXTRA_FILTER_TNAME_ALLOW:	return "--thread-name";
	case WEXTRA_FILTER_TNAME_DENY:	return "--no-thread-name";
	case WEXTRA_FILTER_IDLE_ALLOW:	return "--idle";
	case WEXTRA_FILTER_IDLE_DENY:	return "--no-idle";
	case WEXTRA_FILTER_KTHREAD_ALLOW: return "--kthread";
	case WEXTRA_FILTER_KTHREAD_DENY: return "--no-kthread";
	case WEXTRA_UTRACE_DEF:		return "--utrace";
	case WEXTRA_METADATA:		return "--metadata";
	case WEXTRA_STATS:		return "--stats";
	default:			return "???";
	}
}

struct wprof_extra_param {
	enum wprof_extra_param_kind kind;
	u32 stroff;
};

/*
 * Stable enum: positions are append-only, never reorder.
 * WSTAT_INVALID (index 0) is the cumulative offset table.
 */
enum wprof_stat_id {
	WSTAT_INVALID = 0,

	/* BPF-side ringbuf stats (global + per-rb + per-cpu) */
	WSTAT_RB_HANDLED_CNT,
	WSTAT_RB_DROPS,
	WSTAT_RB_RESCUES,
	WSTAT_RB_MISSES,

	/* Userspace worker stats (global + per-rb); handled cnt is above with drops */
	WSTAT_RB_HANDLED_SZ,
	WSTAT_RB_IGNORED_CNT,
	WSTAT_RB_IGNORED_SZ,

	/* BPF-side resource stats (global + per-cpu) */
	WSTAT_TASK_STATE_DROPS,
	WSTAT_REQ_STATE_DROPS,
	WSTAT_PYSTACKS_ATTEMPTED,
	WSTAT_PYSTACKS_FOUND,

	/* Resource usage (global only) */
	WSTAT_RUSAGE_UTIME_US,
	WSTAT_RUSAGE_STIME_US,
	WSTAT_RUSAGE_MAXRSS_KB,
	WSTAT_RUSAGE_MAJFLT,
	WSTAT_RUSAGE_MINFLT,
	WSTAT_RUSAGE_INBLOCK,
	WSTAT_RUSAGE_OUBLOCK,
	WSTAT_RUSAGE_NVCSW,
	WSTAT_RUSAGE_NIVCSW,

	/* BPF program stats (total + prog_cnt entries each) */
	WSTAT_PROG_NAME,
	WSTAT_PROG_RUN_CNT,
	WSTAT_PROG_RUN_TIME_NS,
	WSTAT_PROG_RECURSION_MISSES,

	/* CUDA tracee stats (total + cuda_cnt entries each) */
	WSTAT_CUDA_NAME,
	WSTAT_CUDA_STATE,
	WSTAT_CUDA_REC_CNT,
	WSTAT_CUDA_DROP_CNT,
	WSTAT_CUDA_ERR_CNT,
	WSTAT_CUDA_IGNORE_CNT,
	WSTAT_CUDA_BUF_CNT,
	WSTAT_CUDA_DATA_SZ,

	/* PyTrace tracee stats (total + pytrace_cnt entries each) */
	WSTAT_PYTRACE_NAME,
	WSTAT_PYTRACE_STATE,
	WSTAT_PYTRACE_EVENT_CNT,
	WSTAT_PYTRACE_CODE_CACHE_CNT,

	__WSTAT_CNT,
};

/*
 * Self-describing stats blob. Persisted to blob pool via WEXTRA_STATS.
 *
 * stats[] is a concatenation of per-stat arrays. The first stat_cnt + 1 entries
 * form the cumulative end-offset table (WSTAT_INVALID's "data"):
 *   stats[0] = stat_cnt's (the offset table is `stat_cnt+1` u64s)
 *   stats[S] = cumulative end offset of stat S's data in stats[]
 *   stats[stat_cnt] = is total number of stats in stats[] array
 *
 * To find stat S: start = stats[S], count = stats[S] - stats[S-1].
 *
 * Per-stat arrays have variable length:
 *   - per-rb + per-cpu breakdown: [global, rb0..rbN, cpu0..cpuM];
 *   - per-rb breakdown: [global, rb0..rbN];
 *   - global-only stats: [global].
 */
struct wprof_stats {
	u32 sz;
	u32 stat_cnt;
	u64 flags;
	u32 cpu_cnt;
	u32 rb_cnt;
	u32 prog_cnt;
	u32 cuda_cnt;
	u32 pytrace_cnt;
	u32 ringbuf_sz;
	u32 task_state_sz;
	u32 reserved[53];
	u64 stats[];
} __attribute__((aligned(8)));

static inline u64 *wstats(const struct wprof_stats *s, enum wprof_stat_id id, size_t *cnt)
{
	if (!s || id >= s->stat_cnt) {
		if (cnt)
			*cnt = 0;
		return NULL;
	}

	if (cnt)
		*cnt = s->stats[id + 1] - s->stats[id];

	return (u64 *)&s->stats[s->stats[id]];
}

static inline u64 wstat(const struct wprof_stats *s, enum wprof_stat_id id, int idx)
{
	size_t cnt;
	const u64 *v = wstats(s, id, &cnt);
	if (!v || idx >= cnt)
		return 0;
	return v[idx];
}

struct wprof_data_hdr {
	char magic[6]; /* "WPROF\0" */
	u16 hdr_sz;
	u64 flags;
	int version_major;
	int version_minor;

	/* Events section */
	u64 events_off, events_sz, event_cnt;

	/* Thread info section */
	u64 threads_off, threads_sz, thread_cnt;

	/* PMU counter definitions section */
	u64 pmu_defs_off, pmu_defs_sz;
	u64 pmu_def_real_cnt, pmu_def_deriv_cnt;

	/* PMU counter values section */
	u64 pmu_vals_off, pmu_vals_sz, pmu_val_cnt;

	/* String pool section */
	u64 strs_off, strs_sz;

	/* Blob pool section (variable-sized binary data) */
	u64 blobs_off, blobs_sz;

	/* Symbolized stack traces section */
	u64 stacks_off, stacks_sz;

	/* Extra parameters section (persisted filters, etc.) */
	u64 extras_off, extras_sz, extra_cnt;

	struct wprof_data_cfg cfg;
} __attribute__((aligned(8)));

struct wprof_stacks_hdr {
	u64 frames_off; /* individual stack frames */
	u64 frame_mappings_off; /* stack -> frame mapping elements */
	u64 stacks_off; /* stack "pointers" */
	u64 strs_off; /* stacks-specific blob of strings (separate from main string pool) */

	u32 frame_cnt;
	u32 frame_mapping_cnt;
	u32 stack_cnt;
	u32 strs_sz;
} __attribute__((aligned(8)));

enum wprof_stack_frame_flags {
	WSF_UNSYMBOLIZED = 0x01,
	WSF_INLINED = 0x02,
	WSF_KERNEL = 0x04,
	WSF_PYTHON = 0x08,
};

struct wprof_stack_frame {
	u64 func_offset; /* or full address if symbolization failed */
	enum wprof_stack_frame_flags flags;
	u32 func_name_stroff;
	u32 src_path_stroff;
	u32 line_num;
	u64 addr;
} __attribute__((aligned(8)));

struct wprof_stack_trace {
	u32 frame_mapping_idx;
	u32 frame_mapping_cnt;
};

struct worker_state;
typedef int (*handle_event_fn)(struct worker_state *w, const struct wevent *e);
int process_events(struct worker_state *w, handle_event_fn *handlers, size_t handler_cnt);

const char *event_kind_str(enum event_kind kind);

/* ==================== ACCESSOR FUNCTIONS ==================== */

static inline struct wprof_stacks_hdr *wprof_stacks_hdr(struct wprof_data_hdr *hdr)
{
	if (hdr->stacks_sz == 0)
		return NULL;

	return (void *)hdr + hdr->hdr_sz + hdr->stacks_off;
}

static inline const char *wprof_stacks_str(struct wprof_data_hdr *hdr, u32 off)
{
	struct wprof_stacks_hdr *shdr = (void *)hdr + hdr->hdr_sz + hdr->stacks_off;
	return (void *)shdr + sizeof(*shdr) + shdr->strs_off + off;
}

static inline struct wprof_stack_frame *wprof_stacks_frame(struct wprof_data_hdr *hdr, u32 fr_idx)
{
	struct wprof_stacks_hdr *shdr = (void *)hdr + hdr->hdr_sz + hdr->stacks_off;
	return (void *)shdr + sizeof(*shdr) + shdr->frames_off + fr_idx * sizeof(struct wprof_stack_frame);
}

/*
 * TODO: rename wprof_stacks_* to wstack_* for symmetry with wevent_*.
 */
static inline struct wprof_stack_trace *wprof_stacks_trace(struct wprof_data_hdr *hdr, u32 tr_id)
{
	struct wprof_stacks_hdr *shdr = (void *)hdr + hdr->hdr_sz + hdr->stacks_off;
	return (void *)shdr + sizeof(*shdr) + shdr->stacks_off + tr_id * sizeof(struct wprof_stack_trace);
}

static inline u32 *wprof_stacks_frame_ids(struct wprof_data_hdr *hdr, struct wprof_stack_trace *t)
{
	struct wprof_stacks_hdr *shdr = (void *)hdr + hdr->hdr_sz + hdr->stacks_off;
	return (u32 *)((char *)shdr + sizeof(*shdr) + shdr->frame_mappings_off + t->frame_mapping_idx * sizeof(u32));
}

static inline const char *wevent_str(struct wprof_data_hdr *hdr, u32 off)
{
	return (void *)hdr + hdr->hdr_sz + hdr->strs_off + off;
}

static inline const void *wevent_blob(struct wprof_data_hdr *hdr, u32 off)
{
	return (void *)hdr + hdr->hdr_sz + hdr->blobs_off + off;
}

static inline struct wevent_task *wevent_task(struct wprof_data_hdr *hdr, u32 id)
{
	struct wevent_task *threads = (void *)hdr + hdr->hdr_sz + hdr->threads_off;
	return &threads[id];
}

static inline struct wprof_task wevent_resolve_task(struct wprof_data_hdr *hdr, u32 task_id)
{
	struct wevent_task *t = wevent_task(hdr, task_id);
	return (struct wprof_task) {
		.tid = t->tid,
		.pid = t->pid,
		.flags = t->flags,
		.comm = wevent_str(hdr, t->comm_stroff),
		.pcomm = wevent_str(hdr, t->pcomm_stroff),
	};
}

static inline struct wevent_pmu_def *wevent_pmu_def(const struct wprof_data_hdr *hdr, u32 idx)
{
	struct wevent_pmu_def *defs = (void *)hdr + hdr->hdr_sz + hdr->pmu_defs_off;
	return &defs[idx];
}

static inline u64 *wevent_pmu_vals(struct wprof_data_hdr *hdr, u32 id)
{
	if (id == 0)
		return NULL;

	u64 *vals = (void *)hdr + hdr->hdr_sz + hdr->pmu_vals_off;
	return &vals[id * hdr->pmu_def_real_cnt];
}

static inline struct wprof_extra_param *wevent_extra_param(struct wprof_data_hdr *hdr, u32 idx)
{
	struct wprof_extra_param *extras = (void *)hdr + hdr->hdr_sz + hdr->extras_off;
	return &extras[idx];
}

static inline void wevent_pmu_to_event(struct wprof_data_hdr *hdr, u32 idx, struct pmu_event *ev)
{
	struct wevent_pmu_def *def = wevent_pmu_def(hdr, idx);

	memset(ev, 0, sizeof(*ev));
	ev->perf_type = def->perf_type;
	ev->config = def->config;
	ev->config1 = def->config1;
	ev->config2 = def->config2;
	snprintf(ev->name, sizeof(ev->name), "%s", wevent_str(hdr, def->name_stroff));
}


/* ==================== BPF EVENT (wprof_event) ITERATOR ==================== */
struct bpf_event_record {
	struct wprof_event *e;
	int idx;
};

struct bpf_event_iter {
	void *next;
	void *last;
	int next_idx;
	struct bpf_event_record rec;
};

static inline struct bpf_event_iter bpf_event_iter_new(void *data, size_t data_sz)
{
	return (struct bpf_event_iter) {
		.next = data,
		.last = data + data_sz,
	};
}

static inline struct bpf_event_record *bpf_event_iter_next(struct bpf_event_iter *it)
{
	if (it->next >= it->last)
		return NULL;

	it->rec.e = it->next;
	it->rec.idx = it->next_idx;

	it->next += it->rec.e->sz;
	it->next_idx += 1;

	return &it->rec;
}

#define for_each_bpf_event(rec, data, data_sz) for (				\
	struct bpf_event_iter it = bpf_event_iter_new(data, data_sz);		\
	(rec = bpf_event_iter_next(&it));					\
)

/* ==================== WEVENT ITERATOR ==================== */

struct wevent_record {
	struct wevent *e;
	int idx;
};

struct wevent_iter {
	void *next;
	void *last;
	int next_idx;
	struct wevent_record rec;
};

static inline struct wevent_iter wevent_iter_new(void *data)
{
	struct wprof_data_hdr *hdr = data;

	return (struct wevent_iter) {
		.next = data + hdr->hdr_sz + hdr->events_off,
		.last = data + hdr->hdr_sz + hdr->events_off + hdr->events_sz,
	};
}

static inline struct wevent_record *wevent_iter_next(struct wevent_iter *it)
{
	if (it->next >= it->last)
		return NULL;

	it->rec.e = it->next;
	it->rec.idx = it->next_idx;

	it->next += it->rec.e->sz;
	it->next_idx += 1;

	return &it->rec;
}

#define wevent_for_each_event(rec, data) for (					\
	struct wevent_iter it = wevent_iter_new(data);				\
	(rec = wevent_iter_next(&it));						\
)

/* ==================== STACK FRAME ITERATOR ==================== */

struct wprof_stack_frame_record {
	struct wprof_stack_frame *f;
	int idx;
};

struct wprof_stack_frame_iter {
	void *next;
	void *last;
	int next_idx;
	struct wprof_stack_frame_record rec;
};

static inline struct wprof_stack_frame_iter wprof_stack_frame_iter_new(void *data, int from_id)
{
	struct wprof_data_hdr *hdr = data;

	if (hdr->stacks_sz == 0) {
		return (struct wprof_stack_frame_iter) {
			.next = NULL,
			.last = NULL,
		};
	}

	struct wprof_stacks_hdr *shdr = data + hdr->hdr_sz + hdr->stacks_off;
	return (struct wprof_stack_frame_iter) {
		/* we skip first dummy frame */
		.next_idx = from_id == 0 ? 1 : from_id,
		.next = (void *)shdr + sizeof(*shdr) + shdr->frames_off + (from_id == 0 ? 1 : from_id) * sizeof(struct wprof_stack_frame),
		.last = (void *)shdr + sizeof(*shdr) + shdr->frames_off + shdr->frame_cnt * sizeof(struct wprof_stack_frame),
	};
}

static inline struct wprof_stack_frame_record *wprof_stack_frame_iter_next(struct wprof_stack_frame_iter *it)
{
	if (it->next >= it->last)
		return NULL;

	it->rec.f = it->next;
	it->rec.idx = it->next_idx;

	it->next += sizeof(struct wprof_stack_frame);
	it->next_idx += 1;

	return &it->rec;
}

#define wprof_for_each_stack_frame(rec, data, from_id) for (				\
	struct wprof_stack_frame_iter it = wprof_stack_frame_iter_new(data, from_id);	\
	(rec = wprof_stack_frame_iter_next(&it));					\
)

/* ==================== STACK TRACE ITERATOR ==================== */

struct wprof_stack_trace_record {
	struct wprof_stack_trace *t;
	int idx;
	u32 *frame_ids;
	size_t frame_cnt;
};

struct wprof_stack_trace_iter {
	const struct wprof_stacks_hdr *shdr;
	void *next;
	void *last;
	int next_idx;
	struct wprof_stack_trace_record rec;
};

static inline struct wprof_stack_trace_iter wprof_stack_trace_iter_new(void *data, int from_id)
{
	struct wprof_data_hdr *hdr = data;

	if (hdr->stacks_sz == 0) {
		return (struct wprof_stack_trace_iter) {
			.shdr = NULL,
			.next = NULL,
			.last = NULL,
		};
	}

	struct wprof_stacks_hdr *shdr = data + hdr->hdr_sz + hdr->stacks_off;
	return (struct wprof_stack_trace_iter) {
		.shdr = shdr,
		.next_idx = from_id == 0 ? 1 : from_id, /* we skip first dummy trace */
		.next = (void *)shdr + sizeof(*shdr) + shdr->stacks_off + (from_id == 0 ? 1 : from_id) * sizeof(struct wprof_stack_trace),
		.last = (void *)shdr + sizeof(*shdr) + shdr->stacks_off + shdr->stack_cnt * sizeof(struct wprof_stack_trace),
	};
}

static inline struct wprof_stack_trace_record *wprof_stack_trace_iter_next(struct wprof_stack_trace_iter *it)
{
	if (it->next >= it->last)
		return NULL;

	it->rec.t = it->next;
	it->rec.idx = it->next_idx;
	it->rec.frame_ids = (void *)it->shdr + sizeof(*it->shdr) + it->shdr->frame_mappings_off +
			    it->rec.t->frame_mapping_idx * sizeof(u32);
	it->rec.frame_cnt = it->rec.t->frame_mapping_cnt;

	it->next += sizeof(struct wprof_stack_trace);
	it->next_idx += 1;

	return &it->rec;
}

#define wprof_for_each_stack_trace(rec, data, from_id) for (				\
	struct wprof_stack_trace_iter it = wprof_stack_trace_iter_new(data, from_id);	\
	(rec = wprof_stack_trace_iter_next(&it));					\
)

#endif /* __DATA_H_ */
