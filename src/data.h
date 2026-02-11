/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __DATA_H_
#define __DATA_H_

#include "wprof_types.h"
#include "wprof.h"
#include "wevent.h"
#include "pmu.h"

#define WPROF_DATA_MAJOR 2
#define WPROF_DATA_MINOR 0
#define WPROF_DATA_FLAG_INCOMPLETE 0xffffffffffffffffULL

struct wprof_data_cfg {
	u64 ktime_start_ns;
	u64 realtime_start_ns;
	u64 duration_ns;

	u64 capture_ipis : 1;
	u64 capture_requests : 1;
	u64 capture_scx_layer_info : 1;
	u64 capture_req_experimental : 1;
	u64 capture_cuda : 1;

	enum stack_trace_kind captured_stack_traces;

	int timer_freq_hz;
};

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

	/* Symbolized stack traces section */
	u64 stacks_off, stacks_sz;

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

static inline const char *wevent_str(struct wprof_data_hdr *hdr, u32 off)
{
	return (void *)hdr + hdr->hdr_sz + hdr->strs_off + off;
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
	size_t sz;
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

	it->rec.sz = *(size_t *)it->next;
	it->rec.e = it->next + sizeof(size_t);
	it->rec.idx = it->next_idx;

	it->next += sizeof(size_t) + it->rec.sz;
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
