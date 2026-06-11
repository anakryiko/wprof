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
	CFG_NO_SCHED		= 0x400, /* inverted (set = disabled) for backwards compat */
	CFG_NO_WAKEUP		= 0x800, /* inverted (set = disabled) for backwards compat */
	CFG_NO_TASK_LIFE	= 0x1000, /* inverted (set = disabled) for backwards compat */
	CFG_NO_WQ		= 0x2000, /* inverted (set = disabled) for backwards compat */
};

struct wprof_data_cfg {
	u64 ktime_start_ns;
	u64 realtime_start_ns;
	u64 duration_ns;

	u64 capture_features;

	enum stack_trace_kind captured_stack_traces;

	int timer_freq_hz;
};

/*
 * Persisted in data dumps, so values are explicit and stable: never renumber
 * existing entries; to retire one, drop it and leave its value as a hole.
 */
enum wprof_extra_param_kind {
	WEXTRA_INVALID			= 0,
	WEXTRA_FILTER_PID_ALLOW		= 1,
	WEXTRA_FILTER_PID_DENY		= 2,
	WEXTRA_FILTER_TID_ALLOW		= 3,
	WEXTRA_FILTER_TID_DENY		= 4,
	WEXTRA_FILTER_PNAME_ALLOW	= 5,
	WEXTRA_FILTER_PNAME_DENY	= 6,
	WEXTRA_FILTER_TNAME_ALLOW	= 7,
	WEXTRA_FILTER_TNAME_DENY	= 8,
	WEXTRA_FILTER_IDLE_ALLOW	= 9,
	WEXTRA_FILTER_IDLE_DENY		= 10,
	WEXTRA_FILTER_KTHREAD_ALLOW	= 11,
	WEXTRA_FILTER_KTHREAD_DENY	= 12,
	WEXTRA_UTRACE_DEF		= 13,
	WEXTRA_METADATA			= 14,
	WEXTRA_STATS			= 15,
	WEXTRA_PMU			= 16,
	WEXTRA_EMIT_NUMA		= 17,
	WEXTRA_EMIT_TIDPID		= 18,
	WEXTRA_EMIT_TIMER_TICKS		= 19,
	WEXTRA_EMIT_SCHED		= 20,
	WEXTRA_EMIT_SCHED_EXTRAS	= 21,
	WEXTRA_EMIT_PYSTACKS_ONLY	= 22,
	WEXTRA_EMIT_REQ_SPLIT		= 23,
	WEXTRA_EMIT_REQ_EMBED		= 24,
	WEXTRA_EMIT_EMBED_STACKS	= 25,
	WEXTRA_PREPARE_SPEC		= 26,
	WEXTRA_ACTIVATE_SPEC		= 27,
};

struct wprof_extra_param {
	enum wprof_extra_param_kind kind;
	union {
		u32 stroff;	/* offset into the string pool (filters, metadata, pmu, utrace) */
		u32 bloboff;	/* offset into the blob pool (stats) */
		u32 value;	/* on/off value for -e options */
	};
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

	/* PyTrace tracee stats (total + py_cnt entries each) */
	WSTAT_PYTRACE_NAME,
	WSTAT_PYTRACE_STATE,
	WSTAT_PYTRACE_EVENT_CNT,
	WSTAT_PYTRACE_CODE_CACHE_CNT,

	/*
	 * Per-real-PMU "active" fraction (time_running / time_enabled), stored as a double
	 * bit-cast into u64. 1.0 means the counter was always counting; lower values indicate
	 * kernel multiplexing. Index 0 unused; index 1+i is the i-th real PMU (parallel to
	 * pmu_defs[0..pmu_def_real_cnt-1]).
	 */
	WSTAT_PMU_ACTIVE_FRAC,

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
	u32 py_cnt;
	u32 ringbuf_sz;
	u32 task_state_sz;
	u32 pmu_cnt;
	u32 reserved[52];
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

struct wstack_hdr {
	u64 frames_off; /* individual stack frames */
	u64 frame_mappings_off; /* stack -> frame mapping elements */
	u64 stacks_off; /* stack "pointers" */
	u64 strs_off; /* stacks-specific blob of strings (separate from main string pool) */

	u32 frame_cnt;
	u32 frame_mapping_cnt;
	u32 stack_cnt;
	u32 strs_sz;
} __attribute__((aligned(8)));

enum wstack_frame_flags {
	WSF_UNSYMBOLIZED = 0x01,
	WSF_INLINED = 0x02,
	WSF_KERNEL = 0x04,
	WSF_PYTHON = 0x08,
};

struct wstack_frame {
	u64 func_offset; /* or full address if symbolization failed */
	enum wstack_frame_flags flags;
	u32 func_name_stroff;
	u32 src_path_stroff;
	u32 line_num;
	u64 addr;
} __attribute__((aligned(8)));

struct wstack_trace {
	u32 frame_mapping_idx;
	u32 frame_mapping_cnt;
};

struct worker_state;
typedef int (*handle_event_fn)(struct worker_state *w, const struct wevent *e);
int process_events(struct worker_state *w, handle_event_fn *handlers, size_t handler_cnt);

const char *event_kind_str(enum event_kind kind);

/* Render an extra param as its CLI form for display (value-aware for -e). */
const char *extra_param_str(struct wprof_data_hdr *hdr, const struct wprof_extra_param *e);

/* ==================== ACCESSOR FUNCTIONS ==================== */

static inline struct wstack_hdr *wstack_hdr(struct wprof_data_hdr *hdr)
{
	if (hdr->stacks_sz == 0)
		return NULL;

	return (void *)hdr + hdr->hdr_sz + hdr->stacks_off;
}

static inline const char *wstack_str(struct wprof_data_hdr *hdr, u32 off)
{
	struct wstack_hdr *shdr = (void *)hdr + hdr->hdr_sz + hdr->stacks_off;
	return (void *)shdr + sizeof(*shdr) + shdr->strs_off + off;
}

static inline struct wstack_frame *wstack_frame(struct wprof_data_hdr *hdr, u32 fr_idx)
{
	struct wstack_hdr *shdr = (void *)hdr + hdr->hdr_sz + hdr->stacks_off;
	return (void *)shdr + sizeof(*shdr) + shdr->frames_off + fr_idx * sizeof(struct wstack_frame);
}

static inline struct wstack_trace *wstack_trace(struct wprof_data_hdr *hdr, u32 tr_id)
{
	struct wstack_hdr *shdr = (void *)hdr + hdr->hdr_sz + hdr->stacks_off;
	return (void *)shdr + sizeof(*shdr) + shdr->stacks_off + tr_id * sizeof(struct wstack_trace);
}

static inline u32 *wstack_frame_ids(struct wprof_data_hdr *hdr, struct wstack_trace *t)
{
	struct wstack_hdr *shdr = (void *)hdr + hdr->hdr_sz + hdr->stacks_off;
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

struct wstack_frame_record {
	struct wstack_frame *f;
	int idx;
};

struct wstack_frame_iter {
	void *next;
	void *last;
	int next_idx;
	struct wstack_frame_record rec;
};

static inline struct wstack_frame_iter wstack_frame_iter_new(void *data, int from_id)
{
	struct wprof_data_hdr *hdr = data;

	if (hdr->stacks_sz == 0) {
		return (struct wstack_frame_iter) {
			.next = NULL,
			.last = NULL,
		};
	}

	struct wstack_hdr *shdr = data + hdr->hdr_sz + hdr->stacks_off;
	return (struct wstack_frame_iter) {
		/* we skip first dummy frame */
		.next_idx = from_id == 0 ? 1 : from_id,
		.next = (void *)shdr + sizeof(*shdr) + shdr->frames_off + (from_id == 0 ? 1 : from_id) * sizeof(struct wstack_frame),
		.last = (void *)shdr + sizeof(*shdr) + shdr->frames_off + shdr->frame_cnt * sizeof(struct wstack_frame),
	};
}

static inline struct wstack_frame_record *wstack_frame_iter_next(struct wstack_frame_iter *it)
{
	if (it->next >= it->last)
		return NULL;

	it->rec.f = it->next;
	it->rec.idx = it->next_idx;

	it->next += sizeof(struct wstack_frame);
	it->next_idx += 1;

	return &it->rec;
}

#define wstack_for_each_frame(rec, data, from_id) for (				\
	struct wstack_frame_iter it = wstack_frame_iter_new(data, from_id);	\
	(rec = wstack_frame_iter_next(&it));					\
)

/* ==================== STACK TRACE ITERATOR ==================== */

struct wstack_trace_record {
	struct wstack_trace *t;
	int idx;
	u32 *frame_ids;
	size_t frame_cnt;
};

struct wstack_trace_iter {
	const struct wstack_hdr *shdr;
	void *next;
	void *last;
	int next_idx;
	struct wstack_trace_record rec;
};

static inline struct wstack_trace_iter wstack_trace_iter_new(void *data, int from_id)
{
	struct wprof_data_hdr *hdr = data;

	if (hdr->stacks_sz == 0) {
		return (struct wstack_trace_iter) {
			.shdr = NULL,
			.next = NULL,
			.last = NULL,
		};
	}

	struct wstack_hdr *shdr = data + hdr->hdr_sz + hdr->stacks_off;
	return (struct wstack_trace_iter) {
		.shdr = shdr,
		.next_idx = from_id == 0 ? 1 : from_id, /* we skip first dummy trace */
		.next = (void *)shdr + sizeof(*shdr) + shdr->stacks_off + (from_id == 0 ? 1 : from_id) * sizeof(struct wstack_trace),
		.last = (void *)shdr + sizeof(*shdr) + shdr->stacks_off + shdr->stack_cnt * sizeof(struct wstack_trace),
	};
}

static inline struct wstack_trace_record *wstack_trace_iter_next(struct wstack_trace_iter *it)
{
	if (it->next >= it->last)
		return NULL;

	it->rec.t = it->next;
	it->rec.idx = it->next_idx;
	it->rec.frame_ids = (void *)it->shdr + sizeof(*it->shdr) + it->shdr->frame_mappings_off +
			    it->rec.t->frame_mapping_idx * sizeof(u32);
	it->rec.frame_cnt = it->rec.t->frame_mapping_cnt;

	it->next += sizeof(struct wstack_trace);
	it->next_idx += 1;

	return &it->rec;
}

#define wstack_for_each_trace(rec, data, from_id) for (				\
	struct wstack_trace_iter it = wstack_trace_iter_new(data, from_id);	\
	(rec = wstack_trace_iter_next(&it));					\
)

#endif /* __DATA_H_ */
