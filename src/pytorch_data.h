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
	WPYTORCH_ENTRY_SEQ = 22,	/* ENTRY carrying autograd sequence info (seq_nr, rf_tid) */
};

struct wpytorch_data_hdr {
	char magic[6]; /* "WPYTO\0" */
	u16 hdr_sz;
	u64 flags;
	u64 sess_start_ns;
	u64 sess_end_ns;
	u64 strs_sz;		/* string pool immediately follows this header */
} __attribute__((aligned(8)));

/*
 * RecordFunction (pytorch) event: an op entry/exit. Pytorch is the high-volume
 * stream, so the record is kept compact -- just a tid and the op name offset.
 *
 * Records are variable-sized (see wpytorch_event_sz()): only WPYTORCH_ENTRY_SEQ
 * records carry the autograd fields after name_off, all others end right after
 * name_off. seq_nr and rf_tid must only be accessed if what is
 * WPYTORCH_ENTRY_SEQ.
 *
 * WPYTORCH_ENTRY_SEQ is the ENTRY of an op that has an autograd sequence number.
 * A forward op gets the recording thread's current sequence number; the backward
 * op of the autograd node it creates gets the same number plus the id of the
 * forward op's thread, which together pair the two up.
 *
 * Sequence number 0 is not recorded: threads that never create autograd nodes
 * stay at it, so it is mostly noise, at the cost of each thread's first node.
 *
 * Thread ids are RecordFunction's own: a process-wide counter starting at 1,
 * assigned on a thread's first use and never reused. Merge maps them to tasks.
 * Both are assumed to fit: 48 bits of sequence numbers outlast any process, and
 * thread ids stay far below 2^15.
 */
struct wpytorch_event {
	u64 ts;
	u32 tid;
	u8  what:8;		/* enum wpytorch_what */
	u32 name_off:24;	/* op name offset into the string table */

	/* WPYTORCH_ENTRY_SEQ only, packed into one u64 */
	u64 seq_nr:48;		/* autograd sequence number */
	s16 rf_tid;		/* forward op: recording thread's RecordFunction thread id;
				 * backward op: negated thread id of its forward op */
};

_Static_assert(sizeof(struct wpytorch_event) == 24, "seq_nr and rf_tid must pack into one u64");

#define WPYTORCH_EVENT_SEQ_SZ	sizeof(struct wpytorch_event)
#define WPYTORCH_EVENT_SZ	(WPYTORCH_EVENT_SEQ_SZ - sizeof(u64))

static inline size_t wpytorch_event_sz(const struct wpytorch_event *e)
{
	return e->what == WPYTORCH_ENTRY_SEQ ? WPYTORCH_EVENT_SEQ_SZ : WPYTORCH_EVENT_SZ;
}

static inline const char *wpytorch_str(struct wpytorch_data_hdr *hdr, u32 off)
{
	return (void *)hdr + hdr->hdr_sz + off;
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

static inline struct wpytorch_event_iter wpytorch_event_iter_new(void *data, size_t sz)
{
	return (struct wpytorch_event_iter) {
		.next = data,
		.last = data + sz,
	};
}

static inline struct wpytorch_event_record *wpytorch_event_iter_next(struct wpytorch_event_iter *it)
{
	if (it->next >= it->last)
		return NULL;

	it->rec.e = it->next;
	it->rec.idx = it->next_idx;

	it->next += wpytorch_event_sz(it->next);
	it->next_idx += 1;

	return &it->rec;
}

#define wpytorch_for_each_event(rec, data, sz) for (					\
	struct wpytorch_event_iter it = wpytorch_event_iter_new(data, sz);		\
	(rec = wpytorch_event_iter_next(&it));						\
)

#endif /* __PYTORCH_DATA_H_ */
