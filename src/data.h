/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __DATA_H_
#define __DATA_H_

#include "utils.h"
#include "wprof.h"

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

struct wprof_stacks_hdr {
	u64 frames_off;
	u64 stack_frames_off;
	u64 stacks_off;
	u32 frame_cnt;
	u32 stack_frame_cnt;
	u32 stack_cnt;
	u32 strs_off;
	u32 strs_sz;
} __attribute__((aligned(8)));

enum wprof_stack_frame_flags {
	WSF_UNSYMBOLIZED = 0x01,
	WSF_INLINED = 0x02,
};

struct wprof_stack_frame {
	u64 func_offset; /* or full address if symbolization failed */
	enum wprof_stack_frame_flags flags;
	u32 func_name_stroff;
	u32 src_path_stroff;
	u32 line_num;
} __attribute__((aligned(8)));

struct wprof_stack_trace_hdr {
	u32 frame_idx;
	u32 frame_cnt;
};

/* WPROF_EVENT ITERATOR */
struct wprof_event_record {
	size_t sz;
	struct wprof_event *e;
	int idx;
};

struct wprof_event_iter {
	void *next;
	void *last;
	int next_idx;
	struct wprof_event_record rec;
};

static inline struct wprof_event_iter wprof_event_iter_new(void *data)
{
	struct wprof_data_hdr *hdr = data;

	return (struct wprof_event_iter) {
		.next = data + sizeof(struct wprof_data_hdr) + hdr->events_off,
		.last = data + sizeof(struct wprof_data_hdr) + hdr->events_off + hdr->events_sz,
	};
}

static inline struct wprof_event_record *wprof_event_iter_next(struct wprof_event_iter *it)
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

#define wprof_for_each_event(rec, data) for (						\
	struct wprof_event_iter it = wprof_event_iter_new(data);			\
	(rec = wprof_event_iter_next(&it));						\
)

/* WPROF_STACK_FRAME ITERATOR */
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

static inline struct wprof_stack_frame_iter wprof_stack_frame_iter_new(void *data)
{
	struct wprof_data_hdr *hdr = data;

	if (hdr->stacks_sz == 0) {
		return (struct wprof_stack_frame_iter) {
			.next = NULL,
			.last = NULL,
		};
	}

	struct wprof_stacks_hdr *shdr = data + sizeof(*hdr) + hdr->stacks_off;
	return (struct wprof_stack_frame_iter) {
		.next = (void *)shdr + sizeof(*shdr) + shdr->frames_off,
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

#define wprof_for_each_stack_frame(rec, data) for (					\
	struct wprof_stack_frame_iter it = wprof_stack_frame_iter_new(data);		\
	(rec = wprof_stack_frame_iter_next(&it));					\
)

#endif /* __DATA_H_ */
