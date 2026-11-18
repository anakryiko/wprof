/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __UTRACE_H_
#define __UTRACE_H_

struct wprof_bpf;
struct bpf_state;
struct bpf_program;
struct utrace_cfg;

/* BPF programs that utrace probes attach through, one per attach flavor */
struct utrace_progs {
	struct bpf_program *ut_uprobe;
	struct bpf_program *ut_uret;
	struct bpf_program *ut_usdt;
	struct bpf_program *ut_kprobe;
	struct bpf_program *ut_kmulti;
	struct bpf_program *ut_kret;
	struct bpf_program *ut_kretmulti;
	struct bpf_program *ut_tp;
	struct bpf_program *ut_raw_tp;
	struct bpf_program *ut_bpf_entry;	/* fentry clone template */
	struct bpf_program *ut_bpf_exit;	/* fexit clone template */
};

/* set of utrace probes resolved, attached, and detached together */
struct utrace_session {
	struct utrace_cfg *cfgs;	/* dynamically sized */
	int cfg_cnt;
	struct utrace_progs progs;	/* programs the probes attach through */
};

int utrace_setup(struct wprof_bpf *skel);
int utrace_attach(struct bpf_state *st, struct wprof_bpf *skel);

int utrace_resolve(struct utrace_session *sess);
void utrace_release_btfs(struct utrace_session *sess);
int utrace_attach_cfgs(struct bpf_state *st, struct utrace_session *sess, int map_fd);

#endif /* __UTRACE_H_ */
