/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __EMIT_H_
#define __EMIT_H_

#include "utils.h"
#include "wprof.h"
#include "env.h"
#include "pb_common.h"
#include "pb_encode.h"
#include "perfetto_trace.pb.h"

int init_emit(struct worker_state *w);
int process_event(struct worker_state *w, struct wprof_event *e, size_t size);

#endif /* __EMIT_H_ */
