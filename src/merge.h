/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __MERGE_H_
#define __MERGE_H_

#include "env.h"

int wprof_init_data(FILE *dump);
int wprof_load_data_dump(struct worker_state *w);
int wprof_merge_data(int workdir_fd, struct worker_state *workers);

#endif /* __MERGE_H_ */
