// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Meta Platforms, Inc. */
#include "pystacks.h"
#include "env.h"
#include "utils.h"

#include "wprof.skel.h"

int pydisc_discover(struct wprof_bpf *skel);

int pystacks_init(struct wprof_bpf *skel)
{
	int cnt = pydisc_discover(skel);
	if (cnt < 0) {
		eprintf("Python process discovery failed: %d\n", cnt);
		return cnt;
	}

	if (cnt == 0) {
		vprintf("No Python processes found, pystacks capture disabled\n");
		return 0;
	}

	/* configure pystacks BPF program */
	skel->bss->pystacks_prog_cfg.stack_max_len = 127;
	skel->bss->pystacks_prog_cfg.read_leaf_frame = true;
	skel->bss->pystacks_prog_cfg.enable_py_src_lines = true;

	/* enable pystacks capture in timer/offcpu handlers */
	skel->bss->capture_pystacks = true;

	return 0;
}
