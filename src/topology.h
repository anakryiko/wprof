/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __TOPOLOGY_H_
#define __TOPOLOGY_H_

#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <time.h>

#include "utils.h"

/* CPU TOPOLOGY HELPERS */
enum cpu_topo_kind {
	/* order matters */
	TOPO_L1,
	TOPO_L2,
	TOPO_L3,
	TOPO_NUMA,
	TOPO_COMMON, /* fake grouping of all CPUs into one large group */

	__NR_TOPO_KIND,
	__TOPO_KIND_FIRST = 0,
	__TOPO_KIND_LAST = __NR_TOPO_KIND - 1,
};

struct cpu_topo {
	int cpu;
	int group;
	int rnd;
	u64 topo[__NR_TOPO_KIND];
};

int determine_cpu_topology(struct cpu_topo *topo, int cpu_cnt);

int setup_cpu_to_ringbuf_mapping(u32 *rb_cpu_mapping, int rb_cnt, int cpu_cnt);

#endif /* __UTILS_H_ */
