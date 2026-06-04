/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __WPB_H_
#define __WPB_H_

#include <stdint.h>
#include <sys/types.h>

struct wpb_writer;

typedef int (*wpb_write_fn)(void *ctx, const uint8_t *buf, size_t len);

struct wpb_writer *wpb_writer_new(wpb_write_fn write, void *ctx);
void wpb_writer_free(struct wpb_writer *writer);

struct wpb_str {
	uint64_t iid;
	const char *s;
	size_t len;
};

enum wpb_ann_kind {
	WPB_ANN_BOOL,
	WPB_ANN_UINT,
	WPB_ANN_INT,
	WPB_ANN_DOUBLE,
	WPB_ANN_PTR,
	WPB_ANN_STR,
	WPB_ANN_STR_IID,
};

struct wpb_annot {
	struct wpb_str name;
	uint8_t kind;
	union {
		uint8_t b;
		uint64_t u;
		int64_t i;
		double d;
		uint64_t ptr;
		struct wpb_str s;
	} val;
};

struct wpb_intern {
	uint64_t iid;
	const char *s;
	size_t len;
};

struct wpb_track_event {
	uint64_t ts;
	uint32_t trusted_packet_sequence_id;
	uint32_t sequence_flags;
	uint64_t track_uuid;
	int32_t event_type;
	struct wpb_str name;
	struct wpb_str category;
	const struct wpb_annot *annots;
	size_t annot_cnt;
	const uint64_t *flow_ids;
	size_t flow_cnt;
	const struct wpb_intern *interns;
	size_t intern_cnt;
	int64_t callstack_iid;
};

ssize_t wpb_emit_track_event(struct wpb_writer *writer,
			     const struct wpb_track_event *ev);

#endif /* __WPB_H_ */
