/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __CUDA_DATA_H_
#define __CUDA_DATA_H_

#include "wprof_types.h"

#define WCUDA_DATA_MAJOR 1
#define WCUDA_DATA_MINOR 0
#define WCUDA_DATA_FLAG_INCOMPLETE 0xffffffffffffffffULL

struct wcuda_data_cfg {
	int dummy;
};

struct wcuda_data_hdr {
	char magic[6]; /* "WCUDA\0" */
	u16 hdr_sz;
	u64 flags;
	int version_major;
	int version_minor;
	u64 sess_start_ns;
	u64 sess_end_ns;
	u64 events_off, events_sz, event_cnt;
	u64 strs_off, strs_sz;
	struct wcuda_data_cfg cfg;
} __attribute__((aligned(8)));

enum wcuda_event_kind {
	WCK_INVALID = 0,
	/* Currently this needs to be non-overlapping with enum event_kind */
	WCK_CUDA_KERNEL = 50,
	WCK_CUDA_MEMCPY = 51,
	WCK_CUDA_API = 52,
};

enum wcuda_cuda_api_kind {
	WCUDA_CUDA_API_UNKNOWN = 0,
	WCUDA_CUDA_API_DRIVER = 1,
	WCUDA_CUDA_API_RUNTIME = 2,
};

/* intentionally kept compatible in the first 8 bytes with wprof_event */
struct wcuda_event {
	u16 sz;
	u16 flags;
	enum wcuda_event_kind kind;
	u64 ts;

	char __wcuda_data[0]; /* marker field */
	union {
		struct wcuda_cuda_kernel {
			u64 end_ts;
			u32 name_off;
			u32 corr_id;
			u32 device_id;
			u32 ctx_id;
			u32 stream_id;
			u32 grid_x, grid_y, grid_z;
			u32 block_x, block_y, block_z;
		} cuda_kernel;
		struct wcuda_cuda_memcpy {
			u64 end_ts;
			u64 byte_cnt;
			u32 corr_id;
			u32 device_id;
			u32 ctx_id;
			u32 stream_id;
			u8 copy_kind;
			u8 src_kind;
			u8 dst_kind;
		} cuda_memcpy;
		struct wcuda_cuda_api {
			u64 end_ts;
			enum wcuda_cuda_api_kind kind;
			u32 corr_id;
			u32 cbid;
			u32 tid;
			u32 ret_val;
		} cuda_api;
	};
};

static inline const char *wcuda_str(struct wcuda_data_hdr *hdr, u32 off)
{
	return (void *)hdr + hdr->hdr_sz + hdr->strs_off + off;
}

/* WCUDA_EVENT ITERATOR */
struct wcuda_event_record {
	struct wcuda_event *e;
	int idx;
};

struct wcuda_event_iter {
	void *next;
	void *last;
	int next_idx;
	struct wcuda_event_record rec;
};

static inline struct wcuda_event_iter wcuda_event_iter_new(void *data)
{
	struct wcuda_data_hdr *hdr = data;

	return (struct wcuda_event_iter) {
		.next = data + sizeof(struct wcuda_data_hdr) + hdr->events_off,
		.last = data + sizeof(struct wcuda_data_hdr) + hdr->events_off + hdr->events_sz,
	};
}

static inline struct wcuda_event_record *wcuda_event_iter_next(struct wcuda_event_iter *it)
{
	if (it->next >= it->last)
		return NULL;

	it->rec.e = it->next;
	it->rec.idx = it->next_idx;

	it->next += it->rec.e->sz;
	it->next_idx += 1;

	return &it->rec;
}

#define wcuda_for_each_event(rec, data) for (						\
	struct wcuda_event_iter it = wcuda_event_iter_new(data);			\
	(rec = wcuda_event_iter_next(&it));						\
)


#endif /* __CUDA_DATA_H_ */
