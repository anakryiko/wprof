/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __FLIGHTREC_H_
#define __FLIGHTREC_H_

#include <stdio.h>

#include "wprof_types.h"

enum fr_chunk_src {
	FR_SRC_BPF_RB,		/* BPF ringbuf worker */
	FR_SRC_CUDA,		/* injectee CUDA event stream */
	FR_SRC_PYTRACE,		/* injectee PyTrace event stream */
	FR_SRC_PYTORCH,		/* injectee PyTorch event stream */
};

struct fr_chunk {
	char *path;
	FILE *f;		/* wprof's write handle (BPF chunks); NULL for injectee chunks (tracee writes) */
	u64 end_ts;      /* max event ts written to this chunk */
	u64 byte_sz;
	u64 event_cnt;
	enum fr_chunk_src src;
	int src_idx;		/* FR_SRC_BPF_RB: ringbuf index; injectee sources: env.injectees[] index */
	int seq;
	struct fr_chunk *next;   /* link for the intrusive handoff list */
	void *mmap;
};

/* Hand a completed chunk to the flight-recorder thread (any producer thread). */
void fr_handoff(struct fr_chunk *c);
/* Directory where rotated chunk files live; NULL outside flight-recorder mode. */
const char *fr_workdir(void);

#endif /* __FLIGHTREC_H_ */
