/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __UTRACE_H_
#define __UTRACE_H_

struct wprof_bpf;
struct bpf_state;

int utrace_setup_autoload(struct wprof_bpf *skel);
int utrace_setup(struct bpf_state *st, struct wprof_bpf *skel);

#endif /* __UTRACE_H_ */
