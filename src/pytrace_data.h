/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __PYTRACE_DATA_H_
#define __PYTRACE_DATA_H_

#include "wprof_types.h"

#define WPYTRACE_DATA_FLAG_INCOMPLETE 0xffffffffffffffffULL

struct wpytrace_data_hdr {
	char magic[8];
	u16 hdr_sz;
	u16 padding;
	u64 flags;		/* WPYTRACE_DATA_FLAG_INCOMPLETE during recording, cleared on finalization */
	u64 sess_start_ns;
	u64 sess_end_ns;
	u64 events_off;
	u64 events_sz;
	u64 event_cnt;
	u64 strs_off;
	u64 strs_sz;
	u64 code_map_off;
	u64 code_map_sz;
	u64 code_map_cnt;
} __attribute__((aligned(8)));

/* Raw event recorded in the hot path */
struct wpytrace_event {
	u64 ts;
	u64 code_key;
	u32 tid;
	u8  what;		/* PyTrace_CALL=0, PyTrace_RETURN=3 */
	u8  pad[3];
};

/* Code object map entry: maps code_key -> string offsets */
struct wpytrace_code_entry {
	u64 code_key;
	u32 func_name_off;
	u32 file_name_off;
	u32 lineno;
	u32 padding;
};

static inline const char *wpytrace_str(struct wpytrace_data_hdr *hdr, u32 off)
{
	return (void *)hdr + hdr->hdr_sz + hdr->strs_off + off;
}

/* WPYTRACE_EVENT ITERATOR */
struct wpytrace_event_record {
	struct wpytrace_event *e;
	int idx;
};

struct wpytrace_event_iter {
	void *next;
	void *last;
	int next_idx;
	struct wpytrace_event_record rec;
};

static inline struct wpytrace_event_iter wpytrace_event_iter_new(void *data)
{
	struct wpytrace_data_hdr *hdr = data;

	return (struct wpytrace_event_iter) {
		.next = data + hdr->hdr_sz + hdr->events_off,
		.last = data + hdr->hdr_sz + hdr->events_off + hdr->events_sz,
	};
}

static inline struct wpytrace_event_record *wpytrace_event_iter_next(struct wpytrace_event_iter *it)
{
	if (it->next >= it->last)
		return NULL;

	it->rec.e = it->next;
	it->rec.idx = it->next_idx;

	it->next += sizeof(struct wpytrace_event);
	it->next_idx += 1;

	return &it->rec;
}

#define wpytrace_for_each_event(rec, data) for (						\
	struct wpytrace_event_iter it = wpytrace_event_iter_new(data);			\
	(rec = wpytrace_event_iter_next(&it));						\
)

#endif /* __PYTRACE_DATA_H_ */
