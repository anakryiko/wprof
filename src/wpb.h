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

#define WPB_SEQ_ID_THREADS 0x7
#define WPB_SEQ_ID_GENERIC 0x7

enum wpb_sequence_flags {
	WPB_SEQ_INCREMENTAL_STATE_CLEARED = 1,
};

enum wpb_track_event_type {
	WPB_TRACK_EVENT_SLICE_BEGIN = 1,
	WPB_TRACK_EVENT_SLICE_END = 2,
	WPB_TRACK_EVENT_INSTANT = 3,
	WPB_TRACK_EVENT_COUNTER = 4,
};

enum wpb_track_child_order {
	WPB_TRACK_CHILD_ORDER_LEXICOGRAPHIC = 1,
	WPB_TRACK_CHILD_ORDER_CHRONOLOGICAL = 2,
	WPB_TRACK_CHILD_ORDER_EXPLICIT = 3,
};

enum wpb_track_merge_behavior {
	WPB_TRACK_MERGE_BY_TRACK_NAME = 1,
	WPB_TRACK_MERGE_NONE = 2,
	WPB_TRACK_MERGE_BY_KEY = 3,
};

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

struct wpb_attr {
	struct wpb_str key;
	struct wpb_str val;
};

struct wpb_intern_set {
	const struct wpb_intern *entries;
	size_t cnt;
};

struct wpb_mapping {
	uint64_t iid;
	uint64_t start;
	uint64_t end;
	uint64_t start_offset;
};

struct wpb_frame {
	uint64_t iid;
	uint64_t function_name_id;
	uint64_t mapping_id;
	uint64_t rel_pc;
};

struct wpb_callstack {
	uint64_t iid;
	const int *frame_ids;
	size_t frame_cnt;
};

struct wpb_interned_data {
	uint64_t ts;
	uint32_t trusted_packet_sequence_id;
	struct wpb_intern_set event_categories;
	struct wpb_intern_set event_names;
	struct wpb_intern_set debug_annotation_names;
	struct wpb_intern_set debug_annotation_string_values;
	struct wpb_intern_set function_names;
	const struct wpb_mapping *mappings;
	size_t mapping_cnt;
	const struct wpb_frame *frames;
	size_t frame_cnt;
	const struct wpb_callstack *callstacks;
	size_t callstack_cnt;
};

enum wpb_track_descriptor_kind {
	WPB_TRACK_DESCRIPTOR_GENERIC,
	WPB_TRACK_DESCRIPTOR_PROCESS,
	WPB_TRACK_DESCRIPTOR_THREAD,
};

struct wpb_track_descriptor {
	uint32_t trusted_packet_sequence_id;
	uint8_t kind;
	uint64_t uuid;
	uint64_t parent_uuid;
	struct wpb_str name;
	int32_t process_pid;
	struct wpb_str process_name;
	int64_t thread_tid;
	int32_t thread_pid;
	struct wpb_str thread_name;
	int32_t child_ordering;
	int32_t sibling_order_rank;
	int32_t sibling_merge_behavior;
	uint8_t disallow_merging_with_system_tracks;
	uint8_t emit_disallow_merging_with_system_tracks;
	struct wpb_intern_set interned_strings;
};

enum wpb_ftrace_event_kind {
	WPB_FTRACE_SCHED_SWITCH,
	WPB_FTRACE_SCHED_WAKING,
	WPB_FTRACE_SCHED_WAKEUP_NEW,
};

struct wpb_ftrace_event {
	uint64_t timestamp;
	uint32_t pid;
	uint8_t kind;
	struct wpb_str prev_comm;
	int32_t prev_pid;
	int32_t prev_prio;
	int64_t prev_state;
	struct wpb_str next_comm;
	int32_t next_pid;
	int32_t next_prio;
	struct wpb_str comm;
	int32_t event_pid;
	int32_t prio;
	int32_t target_cpu;
};

ssize_t wpb_emit_track_event(struct wpb_writer *writer,
			     const struct wpb_track_event *ev);
ssize_t wpb_emit_clock_snapshot(struct wpb_writer *writer, uint64_t realtime_ts);
ssize_t wpb_emit_system_info(struct wpb_writer *writer, const struct wpb_str *hostname,
			     const struct wpb_str *kernel, const struct wpb_str *arch,
			     uint32_t num_cpus);
ssize_t wpb_emit_trace_attributes(struct wpb_writer *writer, const struct wpb_attr *attrs,
				  size_t attr_cnt);
ssize_t wpb_emit_interned_data(struct wpb_writer *writer, const struct wpb_interned_data *data);
ssize_t wpb_emit_trace_start(struct wpb_writer *writer, const struct wpb_interned_data *data);
ssize_t wpb_emit_track_descriptor(struct wpb_writer *writer,
				  const struct wpb_track_descriptor *desc);
ssize_t wpb_emit_ftrace_bundle(struct wpb_writer *writer, uint32_t cpu,
			       const struct wpb_ftrace_event *events, size_t event_cnt);

#endif /* __WPB_H_ */
