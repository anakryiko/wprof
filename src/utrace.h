/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __UTRACE_H_
#define __UTRACE_H_

struct wprof_bpf;
struct bpf_state;
struct utrace_cfg;

/* set of utrace probes resolved, attached, and detached together */
struct utrace_session {
	struct utrace_cfg *cfgs;	/* dynamically sized */
	int cfg_cnt;
};

int utrace_setup(struct wprof_bpf *skel);
int utrace_attach(struct bpf_state *st, struct wprof_bpf *skel);

#endif /* __UTRACE_H_ */
