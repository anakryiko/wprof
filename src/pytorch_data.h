/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __PYTORCH_DATA_H_
#define __PYTORCH_DATA_H_

#include "wprof_types.h"

#define WPYTORCH_DATA_FLAG_INCOMPLETE 0xffffffffffffffffULL

/* RecordFunction what values */
enum wpytorch_what {
	WPYTORCH_ENTRY = 20,
	WPYTORCH_EXIT  = 21,
};

struct wpytorch_data_hdr {
	char magic[6]; /* "WPYTO\0" */
	u16 hdr_sz;
	u64 flags;		/* WPYTORCH_DATA_FLAG_INCOMPLETE during recording, cleared on finalization */
	u64 sess_start_ns;
	u64 sess_end_ns;
	u64 events_off;
	u64 events_sz;
	u64 event_cnt;
	u64 strs_off;
	u64 strs_sz;
} __attribute__((aligned(8)));

/*
 * RecordFunction (pytorch) event: an op entry/exit. Pytorch is the high-volume
 * stream, so the record is kept compact -- just a tid and the op name offset.
 */
struct wpytorch_event {
	u64 ts;
	u32 tid;
	u8  what:8;		/* WPYTORCH_ENTRY / WPYTORCH_EXIT */
	u32 name_off:24;	/* op name offset into the string table */
};

static inline const char *wpytorch_str(struct wpytorch_data_hdr *hdr, u32 off)
{
	return (void *)hdr + hdr->hdr_sz + hdr->strs_off + off;
}

/* WPYTORCH_EVENT ITERATOR */
struct wpytorch_event_record {
	struct wpytorch_event *e;
	int idx;
};

struct wpytorch_event_iter {
	void *next;
	void *last;
	int next_idx;
	struct wpytorch_event_record rec;
};

static inline struct wpytorch_event_iter wpytorch_event_iter_new(void *data)
{
	struct wpytorch_data_hdr *hdr = data;

	return (struct wpytorch_event_iter) {
		.next = data + hdr->hdr_sz + hdr->events_off,
		.last = data + hdr->hdr_sz + hdr->events_off + hdr->events_sz,
	};
}

static inline struct wpytorch_event_record *wpytorch_event_iter_next(struct wpytorch_event_iter *it)
{
	if (it->next >= it->last)
		return NULL;

	it->rec.e = it->next;
	it->rec.idx = it->next_idx;

	it->next += sizeof(struct wpytorch_event);
	it->next_idx += 1;

	return &it->rec;
}

#define wpytorch_for_each_event(rec, data) for (					\
	struct wpytorch_event_iter it = wpytorch_event_iter_new(data);			\
	(rec = wpytorch_event_iter_next(&it));						\
)

#endif /* __PYTORCH_DATA_H_ */
