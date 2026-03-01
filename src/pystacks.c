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

	return 0;
}
