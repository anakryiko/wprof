// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include "topology.h"
#include "env.h"

/*
 * Cache Hierarchy Files
 *
 * /sys/devices/system/cpu/cpuX/cache/indexY/level - cache level (1, 2, 3)
 * /sys/devices/system/cpu/cpuX/cache/indexY/type - Data/Instruction/Unified
 * /sys/devices/system/cpu/cpuX/cache/indexY/shared_cpu_list - CPU list
 *
 * /sys/devices/system/node/nodeZ/cpulist - per-NUMA list of CPUs
 */

int determine_cpu_topology(struct cpu_topo *topo, int cpu_cnt)
{
	char path[PATH_MAX];
	bool *mask;
	int mask_sz, err;

	memset(topo, -1, sizeof(*topo) * cpu_cnt);

	for (int cpu = 0; cpu < cpu_cnt; cpu++) {
		topo[cpu].cpu = cpu;
		topo[cpu].rnd = rand();
		topo[cpu].topo[TOPO_COMMON] = 0;
	}

	/* NUMA */
	for (int node = 0; ; node++) {
		snprintf(path, sizeof(path), "/sys/devices/system/node/node%d/cpulist", node);

		if (access(path, F_OK) != 0)
			break;

		err = parse_cpu_mask_file(path, &mask, &mask_sz);
		if (err) {
			eprintf("Failed to parse CPU list from '%s': %d\n", path, err);
			continue;
		}

		for (int i = 0; i < mask_sz; i++) {
			if (mask[i])
				topo[i].topo[TOPO_NUMA] = node;
		}
	}

	/* CACHE HIERARCHY */
	for (int cpu = 0; cpu < cpu_cnt; cpu++) {
		if (topo[cpu].topo[TOPO_L3] != -1 &&
		    topo[cpu].topo[TOPO_L2] != -1 &&
		    topo[cpu].topo[TOPO_L1] != -1)
			continue;

		for (int cache = 0; ; cache++) {
			snprintf(path, sizeof(path),
				"/sys/devices/system/cpu/cpu%d/cache/index%d/type",
				cpu, cache);

			if (access(path, F_OK) != 0)
				break;

			char cache_type[64];
			err = parse_str_from_file(path, cache_type, sizeof(cache_type));
			if (err) {
				eprintf("Failed to parse cache type from '%s': %d\n", path, err);
				continue;
			}
			if (strcmp(cache_type, "Instruction") == 0)
				continue;

			snprintf(path, sizeof(path),
				"/sys/devices/system/cpu/cpu%d/cache/index%d/level",
				cpu, cache);

			int level;
			err = parse_int_from_file(path, "%d", &level);
			if (err) {
				eprintf("Failed to parse cache level from '%s': %d\n", path, err);
				continue;
			}

			if (level < 1 || level > 3)
				continue;


			snprintf(path, sizeof(path),
				"/sys/devices/system/cpu/cpu%d/cache/index%d/id",
				cpu, cache);
			u64 id;
			err = parse_int_from_file(path, "%llu", &id);
			if (err) {
				eprintf("Failed to parse cache id from '%s': %d\n", path, err);
				continue;
			}

			enum cpu_topo_kind kind = TOPO_L1 + level - 1;
			topo[cpu].topo[kind] = id;
		}
	}
	return 0;
}

/* Union-Find set, with membership counts */
struct ufset {
	int id;
	int cnt;
};

static void sets_init(struct ufset *sets, size_t set_sz)
{
	for (size_t i = 0; i < set_sz; i++) {
		sets[i].id = i;
		sets[i].cnt = 1;
	}
}

static int sets_find(struct ufset *sets, size_t set_sz, int id)
{
	if (sets[id].id == id)
		return id;

	sets[id].id = sets_find(sets, set_sz, sets[id].id);
	return sets[id].id;
}

static int sets_find_count(struct ufset *sets, size_t set_sz, int id)
{
	if (sets[id].id == id)
		return sets[id].cnt;

	sets[id].id = sets_find(sets, set_sz, sets[id].id);
	return sets[sets[id].id].cnt;
}

/* returns true if specified sets were disjoint originally */
static bool sets_union(struct ufset *sets, size_t set_sz, int a, int b)
{
	int sa = sets_find(sets, set_sz, a);
	int sb = sets_find(sets, set_sz, b);

	if (sa == sb)
		return false;

	sets[sa].id = sb;
	sets[sb].cnt += sets[sa].cnt;

	return true;
}

static int cpu_cmp_by_topo(const void *a, const void *b)
{
	const struct cpu_topo *x = a, *y = b;

	for (int k = __TOPO_KIND_LAST; k >= __TOPO_KIND_FIRST; k--) {
		if (x->topo[k] != y->topo[k])
			return x->topo[k] < y->topo[k] ? -1 : 1;
	}

	return x->cpu < y->cpu ? -1 : 1;
}

static int cpu_cmp_by_id(const void *a, const void *b)
{
	const struct cpu_topo *x = a, *y = b;

	return x->cpu < y->cpu ? -1 : 1;
}

static void print_cpu_grouping(struct cpu_topo *topo, struct ufset *sets, int cpu_cnt)
{
	qsort(topo, cpu_cnt, sizeof(*topo), cpu_cmp_by_id);

	for (int i = 0; i < cpu_cnt; i++) {
		printf("CPU #%d -> GROUP %d SET %d MEMBER_CNT %d\n", i, topo[i].group,
		       sets_find(sets, cpu_cnt, i), sets_find_count(sets, cpu_cnt, i));
	}

	qsort(topo, cpu_cnt, sizeof(*topo), cpu_cmp_by_topo);
}

static void topo_regroup(struct cpu_topo *topo, struct ufset *sets, int cpu_cnt)
{
	/* renumber groups into 0, 1, ... */
	int next_group_id = 0;
	for (int i = 0; i < cpu_cnt; i++) {
		int si = sets_find(sets, cpu_cnt, topo[i].cpu);
		topo[i].group = -1;
		for (int j = 0; j < i; j++) {
			if (sets_find(sets, cpu_cnt, topo[j].cpu) == si) {
				/* existing group */
				topo[i].group = topo[j].group;
				break;
			}
		}
		if (topo[i].group < 0) {
			/* new group */
			topo[i].group = next_group_id;
			next_group_id += 1;
		}
	}
}

int setup_cpu_to_ringbuf_mapping(u32 *rb_cpu_mapping, int rb_cnt, int cpu_cnt)
{
	struct cpu_topo *topo = NULL;
	struct ufset *sets = NULL, *last_sets = NULL;
	int err;

	topo = calloc(cpu_cnt, sizeof(*topo));
	err = determine_cpu_topology(topo, cpu_cnt);
	if (err) {
		eprintf("Failed to determine CPU topology, falling back to modulo-based ringbuf distribution strategy!\n");
		for (int i = 0; i < cpu_cnt; i++) {
			rb_cpu_mapping[i] = i % rb_cnt;
		}
		goto done;
	}

	qsort(topo, cpu_cnt, sizeof(*topo), cpu_cmp_by_topo);

	sets = calloc(cpu_cnt, sizeof(*sets));
	sets_init(sets, cpu_cnt);
	last_sets = calloc(cpu_cnt, sizeof(*sets));

	int set_cnt = cpu_cnt;
	int last_set_cnt = set_cnt;
	enum cpu_topo_kind k;
	for (k = __TOPO_KIND_FIRST; k <= __TOPO_KIND_LAST; k++) {
		/* remember sets state before next step, we might need to
		 * restore it for last randomization step
		 */
		memcpy(last_sets, sets, sizeof(*sets) * cpu_cnt);

		for (int i = 1; i < cpu_cnt; i++) {
			/* combine only CPUs that share the same "topology domain" */
			if (topo[i].topo[k] != topo[i - 1].topo[k])
				continue;

			int cnt1 = sets_find_count(sets, cpu_cnt, topo[i - 1].cpu);
			int cnt2 = sets_find_count(sets, cpu_cnt, topo[i].cpu);
			if (!sets_union(sets, cpu_cnt, topo[i - 1].cpu, topo[i].cpu))
				continue;

			set_cnt -= 1;

			if (env.debug) {
				printf("COMBINING CPU %d and CPU %d -> %d + %d = %d (%s)\n",
						topo[i - 1].cpu, topo[i].cpu,
						cnt1, cnt2, sets_find_count(sets, cpu_cnt, topo[i].cpu),
						k == TOPO_NUMA ? "NUMA" : (
						k == TOPO_L3 ? "L3" : (
						k == TOPO_L2 ? "L2" : (
						k == TOPO_L1 ? "L1" : "???"))));
			}
		}

		topo_regroup(topo, sets, cpu_cnt);

		if (last_set_cnt != set_cnt && env.debug)
			print_cpu_grouping(topo, sets, cpu_cnt);

		if (set_cnt == rb_cnt)
			goto assign;

		if (set_cnt < rb_cnt)
			goto balance;

		last_set_cnt = set_cnt;
	}
balance:
	/* restore last round's grouping info */
	memcpy(sets, last_sets, cpu_cnt * sizeof(*sets));
	set_cnt = last_set_cnt;

	/* restore original order of topology */
	qsort(topo, cpu_cnt, sizeof(*topo), cpu_cmp_by_id);

	/* keep picking random cpu (group) to merge, and find smallest
	 * eligible group within the same topology domain (k)
	 */
	while (set_cnt > rb_cnt) {
		int cpu = rand() % cpu_cnt;
		int best_cpu = -1, best_cnt = -1;

		for (int i = 0; i < cpu_cnt; i++) {
			if (sets_find(sets, cpu_cnt, i) == sets_find(sets, cpu_cnt, cpu))
				continue;
			if (topo[i].topo[k] != topo[cpu].topo[k])
				continue;

			int cnt = sets_find_count(sets, cpu_cnt, i);
			if (best_cpu < 0 || cnt < best_cnt) {
				best_cpu = i;
				best_cnt = cnt;
			}
		}

		/* we might have grouped entire domain */
		if (best_cpu < 0)
			continue;

		int cnt1 = sets_find_count(sets, cpu_cnt, cpu);
		int cnt2 = sets_find_count(sets, cpu_cnt, best_cpu);
		if (sets_union(sets, cpu_cnt, cpu, best_cpu)) {
			if (env.debug) {
				printf("COMBINING CPU %d and CPU %d -> %d + %d = %d (%s)\n",
						cpu, best_cpu,
						cnt1, cnt2, sets_find_count(sets, cpu_cnt, cpu),
						k == TOPO_NUMA ? "NUMA" : (
						k == TOPO_L3 ? "L3" : (
						k == TOPO_L2 ? "L2" : (
						k == TOPO_L1 ? "L1" : "???"))));
			}
			set_cnt -= 1;
		}
	}

	topo_regroup(topo, sets, cpu_cnt);
	if (env.debug)
		print_cpu_grouping(topo, sets, cpu_cnt);

assign:
	/* restore original order */
	qsort(topo, cpu_cnt, sizeof(*topo), cpu_cmp_by_id);
	for (int i = 0; i < cpu_cnt; i++)
		rb_cpu_mapping[i] = topo[i].group;

done:
	if (env.verbose) {
		printf("CPU topology and CPU-to-ringbuf mapping:\n");
		printf("========================================\n");
		for (int i = 0; i < cpu_cnt; i++) {
			printf("CPU #%3d (NUMA=%llu, L3=%llu, L2=%llu, L1=%llu) -> ringbuf #%d\n",
			       i,
			       topo[i].topo[TOPO_NUMA],
			       topo[i].topo[TOPO_L3],
			       topo[i].topo[TOPO_L2],
			       topo[i].topo[TOPO_L1],
			       rb_cpu_mapping[i]);
		}
	}

	free(topo);
	free(sets);
	free(last_sets);

	return 0;
}
