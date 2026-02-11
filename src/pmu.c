// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <linux/perf_event.h>

#include "pmu.h"
#include "utils.h"
#include "env.h"
#include "protobuf.h"

/*
 * Software event names.
 * These are kernel-provided software counters (PERF_TYPE_SOFTWARE).
 */
static const struct {
	const char *name;
	__u64 config;
} sw_events[] = {
	{ "cpu-clock", PERF_COUNT_SW_CPU_CLOCK },
	/*
	 * task-clock: measures CPU time consumed by the task, excluding time
	 * when the task is not scheduled. Useful for per-task CPU accounting.
	 */
	{ "task-clock", PERF_COUNT_SW_TASK_CLOCK },
	{ "page-faults", PERF_COUNT_SW_PAGE_FAULTS },
	{ "context-switches", PERF_COUNT_SW_CONTEXT_SWITCHES },
	{ "cpu-migrations", PERF_COUNT_SW_CPU_MIGRATIONS },
	{},
};

/*
 * Hardware cache events (PERF_TYPE_HW_CACHE).
 *
 * These use a special config format defined in linux/perf_event.h:
 *   config = cache_id | (cache_op_id << 8) | (cache_result_id << 16)
 *
 * cache_id values: PERF_COUNT_HW_CACHE_L1D, _L1I, _LL, _DTLB, _ITLB, _BPU, _NODE
 * cache_op_id values: PERF_COUNT_HW_CACHE_OP_READ, _WRITE, _PREFETCH
 * cache_result_id values: PERF_COUNT_HW_CACHE_RESULT_ACCESS, _MISS
 */
struct hw_cache_event {
	const char *name;
	int cache_id;    /* PERF_COUNT_HW_CACHE_* from linux/perf_event.h */
	int op_id;       /* PERF_COUNT_HW_CACHE_OP_* */
	int result_id;   /* PERF_COUNT_HW_CACHE_RESULT_* */
};

static const struct hw_cache_event hw_cache_events[] = {
	/* L1 Instruction cache */
	{ "L1-icache-loads", PERF_COUNT_HW_CACHE_L1I, PERF_COUNT_HW_CACHE_OP_READ, PERF_COUNT_HW_CACHE_RESULT_ACCESS },
	{ "L1-icache-load-misses", PERF_COUNT_HW_CACHE_L1I, PERF_COUNT_HW_CACHE_OP_READ, PERF_COUNT_HW_CACHE_RESULT_MISS },

	/* ITLB */
	{ "iTLB-loads", PERF_COUNT_HW_CACHE_ITLB, PERF_COUNT_HW_CACHE_OP_READ, PERF_COUNT_HW_CACHE_RESULT_ACCESS },
	{ "iTLB-load-misses", PERF_COUNT_HW_CACHE_ITLB, PERF_COUNT_HW_CACHE_OP_READ, PERF_COUNT_HW_CACHE_RESULT_MISS },

	/* Branch prediction */
	{ "branch-loads", PERF_COUNT_HW_CACHE_BPU, PERF_COUNT_HW_CACHE_OP_READ, PERF_COUNT_HW_CACHE_RESULT_ACCESS },
	{ "branch-load-misses", PERF_COUNT_HW_CACHE_BPU, PERF_COUNT_HW_CACHE_OP_READ, PERF_COUNT_HW_CACHE_RESULT_MISS },
	{},
};

/* Parse raw events: "r####" */
static int parse_raw_event(const char *spec, struct pmu_event *ev)
{
	char *endp;

	if (spec[0] != 'r')
		return -ENOENT;

	/* Parse hex value after 'r' */
	errno = 0;
	__u64 val = strtoull(spec + 1, &endp, 16);
	if (errno || *endp != '\0')
		return -EINVAL;

	ev->perf_type = PERF_TYPE_RAW;
	ev->config = val;
	snprintf(ev->name, sizeof(ev->name), "raw_0x%llx", val);

	return 0;
}

/* Parse software events: "sw:page-faults" */
static int parse_software_event(const char *spec, struct pmu_event *ev)
{
	if (strncmp(spec, "sw:", 3) != 0)
		return -ENOENT;

	const char *sw_name = spec + 3;

	/* Search software events */
	for (int i = 0; sw_events[i].name; i++) {
		if (strcmp(sw_name, sw_events[i].name) != 0)
			continue;

		ev->perf_type = PERF_TYPE_SOFTWARE;
		ev->config = sw_events[i].config;
		snprintf(ev->name, sizeof(ev->name), "sw_%s", sw_name);

		return 0;
	}

	return -ENOENT;
}

/*
 * Resolve PMU name to its perf_event_attr type value.
 *
 * Each PMU device in /sys/bus/event_source/devices/ has a 'type' file containing
 * the numeric type value to use in perf_event_attr.type when opening events for
 * that PMU. This allows accessing PMU-specific events beyond the standard
 * PERF_TYPE_HARDWARE/SOFTWARE types.
 *
 * For example:
 *   /sys/bus/event_source/devices/cpu/type -> 4 (PERF_TYPE_RAW)
 *   /sys/bus/event_source/devices/uncore_imc_0/type -> 10 (vendor-specific)
 */
int pmu_resolve_type(const char *pmu_name, __u32 *type)
{
	char path[256];
	FILE *f;
	int ret;

	snprintf(path, sizeof(path), "/sys/bus/event_source/devices/%s/type", pmu_name);

	f = fopen(path, "r");
	if (!f)
		return -errno;

	ret = fscanf(f, "%u", type);
	fclose(f);

	return ret == 1 ? 0 : -EINVAL;
}

/*
 * See a list of supported fields in /sys/devices/cpu/format/
 */
static int pmu_dev_field_mapping(const char *key, __u64 val, __u64 *config,
																 __u64 *config1, __u64 *config2)
{
	if (strcmp(key, "event") == 0) {
		*config |= val;
	} else if (strcmp(key, "umask") == 0) {
		*config |= (val << 8);
	} else if (strcmp(key, "edge") == 0) {
		*config |= (val << 18);
	} else if (strcmp(key, "pc") == 0) {
		*config |= (val << 19);
	} else if (strcmp(key, "inv") == 0) {
		*config |= (val << 23);
	} else if (strcmp(key, "cmask") == 0) {
		*config |= (val << 24);
	} else if (strcmp(key, "config1") == 0) {
		*config1 = val;
	} else if (strcmp(key, "config2") == 0) {
		*config2 = val;
	} else {
		return -EINVAL;
	}

	return 0;
}

/* Parse the format like "event=0x24,umask=0x01,name=foo" */
static int perf_event_parsing(char *attrs, __u64 *config, __u64 *config1,
															__u64 *config2, char *name, int max_len)
{
	char *saveptr, *token;
	int err = -ENOENT;

	*config = 0;
	*config1 = 0;
	*config2 = 0;

	for (token = strtok_r(attrs, ",", &saveptr); token; token = strtok_r(NULL, ",", &saveptr)) {
		int n;
		char key[64], val_s[64];
		if (sscanf(token, "%63[^=]=%63s%n", key, val_s, &n) != 2 || n != strlen(token))
			return -EINVAL;

		/* Handle name separately */
		if (strcmp(key, "name") == 0) {
			if (name && max_len)
				snprintf(name, max_len, "%s", val_s);
			err = 0;
			continue;
		}

		/* Parse numeric value */
		char *endptr;
		errno = 0;
		__u64 val = strtoull(val_s, &endptr, 0);
		if (errno || *endptr) {
			eprintf("invalid pmu value: %s=%s\n", key, val_s);
			return -EINVAL;
		}

		err = pmu_dev_field_mapping(key, val, config, config1, config2);
		if (err)
			return err;
	}

	return err;
}

/* Lookup event values from sysfs */
int pmu_resolve_symbolic_event(const char *pmu, const char *event_name,
															 __u64 *config, __u64 *config1, __u64 *config2)
{
	char path[256];
	char buf[256];
	FILE *f;

	snprintf(path, sizeof(path), "/sys/bus/event_source/devices/%s/events/%s", pmu, event_name);

	f = fopen(path, "r");
	if (!f)
		return -errno;

	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return -EINVAL;
	}
	fclose(f);

	/* Remove trailing newline */
	buf[strcspn(buf, "\n")] = '\0';

	return perf_event_parsing(buf, config, config1, config2, NULL, 0);
}

/*
 * Currently, we support a subset of hardware cache events.
 * See hw_cache_events.
 */
static int lookup_hw_cache_event(const char *name, struct pmu_event *ev)
{
	for (int i = 0; hw_cache_events[i].name; i++) {
		if (strcmp(name, hw_cache_events[i].name) != 0)
			continue;

		ev->perf_type = PERF_TYPE_HW_CACHE;
		ev->config = hw_cache_events[i].cache_id |
			     (hw_cache_events[i].op_id << 8) |
			     (hw_cache_events[i].result_id << 16);
		ev->config1 = 0;
		ev->config2 = 0;
		snprintf(ev->name, sizeof(ev->name), "%s", name);
		return 0;
	}
	return -ENOENT;
}

/*
 * Parse PMU-style event specification: "pmu/attrs/".
 * This is the perf-style format for specifying PMU events directly.
 *
 * Examples:
 *   cpu/event=0x3c/														- raw event code
 *   cpu/event=0x3c,umask=0x01,name=my_event/		- with name
 *   cpu/L1-icache-load-misses/									- symbolic event
 */
static int parse_pmu_style_event(const char *spec, struct pmu_event *ev)
{
	int err;
	char pmu_dev[32];
	char attrs[128];

	int n = sscanf(spec, "%31[^/]/%127[^/]/", pmu_dev, attrs);
	if (n != 2 || pmu_dev[0] == '\n' || attrs[0] == '\n')
		return -ENOENT;

	__u32 pmu_type;
	if ((err = pmu_resolve_type(pmu_dev, &pmu_type)) != 0)
		return err;

	ev->perf_type = pmu_type;

	err = pmu_resolve_symbolic_event(pmu_dev, attrs, &ev->config, &ev->config1, &ev->config2);
	if (err == 0) {
		snprintf(ev->name, sizeof(ev->name), "%s_%s", pmu_dev, attrs);
		return err;
	}

	err = lookup_hw_cache_event(attrs, ev);
	if (err == 0) {
		snprintf(ev->name, sizeof(ev->name), "%s", attrs);
		return err;
	}

	err = perf_event_parsing(attrs, &ev->config, &ev->config1, &ev->config2, ev->name, sizeof(ev->name));
	if (err == 0) {
		if (ev->name[0] == '\0') {
			snprintf(ev->name, sizeof(ev->name), "%s_0x%llx",
					pmu_dev, (__u64)ev->config);
		}
		return err;
	}

	return -ENOENT;
}

/*
 * Parse derived metric: "derived:name=numerator/denominator"
 * Stores names temporarily; indices resolved later by pmu_resolve_derived().
 */
static int parse_derived_event(const char *spec, struct pmu_event *ev)
{
	if (strncmp(spec, "derived:", 8) != 0)
		return -ENOENT;

	int n;
	/* Parse "name=numerator/denominator" after "derived:" prefix */
	char tmp1[64], tmp2[64];
	if (sscanf(spec + 8, "%63[^=]=%63[^/]/%63s%n", ev->name, tmp1, tmp2, &n) == 3 &&
			n == strlen(spec + 8)) {
		ev->num_name = strdup(tmp1);
		ev->denom_name = strdup(tmp2);
		ev->perf_type = PERF_TYPE_DERIVED;
		ev->config = UINT64_MAX;  /* unresolved numerator index */
		ev->config1 = UINT64_MAX; /* unresolved denominator index */
		return 0;
	} else {
		return -EINVAL;
	}
}

/*
 * parse_perf_counter() - Main entry point that tries all event format parsers.
 */
int parse_perf_counter(const char *spec, struct pmu_event *out)
{
	int err;

	/* Initialize output */
	memset(out, 0, sizeof(*out));

	err = parse_derived_event(spec, out);
	if (err == 0 || err != -ENOENT)
		return err;

	err = parse_raw_event(spec, out);
	if (err == 0 || err != -ENOENT)
		return err;

	err = parse_pmu_style_event(spec, out);
	if (err == 0 || err != -ENOENT)
		return err;

	err = parse_software_event(spec, out);
	if (err == 0 || err != -ENOENT)
		return err;

	err = lookup_hw_cache_event(spec, out);
	if (err == 0 || err != -ENOENT)
		return err;

	return -EINVAL;
}

void serialized_pmu_event(const struct pmu_event *ev, struct pmu_event_stored *stored)
{
	memset(stored, 0, sizeof(*stored));
	stored->perf_type = ev->perf_type;
	stored->config = ev->config;
	stored->config1 = ev->config1;
	stored->config2 = ev->config2;
	snprintf(stored->name, sizeof(stored->name), "%s", ev->name);
}

void deserialized_pmu_event(const struct pmu_event_stored *stored, struct pmu_event *ev)
{
	memset(ev, 0, sizeof(*ev));
	ev->perf_type = stored->perf_type;
	ev->config = stored->config;
	ev->config1 = stored->config1;
	ev->config2 = stored->config2;
	snprintf(ev->name, sizeof(ev->name), "%s", stored->name);
}

static int find_real_counter_by_name(const struct pmu_event *reals, int real_cnt, const char *name)
{
	for (int i = 0; i < real_cnt; i++) {
		if (strcmp(reals[i].name, name) == 0)
			return i;
	}
	return -1;
}

/*
 * Resolve derived metrics: convert numerator/denominator names to indices
 * into the reals array.
 */
int pmu_resolve_derived(struct pmu_event *reals, int real_cnt,
			struct pmu_event *derivs, int deriv_cnt)
{
	for (int i = 0; i < deriv_cnt; i++) {
		struct pmu_event *pmu = &derivs[i];

		/* we can have derived PMUs taked from recorded definition, fully resolved */
		if (!pmu->num_name)
			continue;

		int num_idx = find_real_counter_by_name(reals, real_cnt, pmu->num_name);
		if (num_idx < 0) {
			eprintf("derived metric '%s': numerator counter '%s' not found\n",
				pmu->name, pmu->num_name);
			return -ENOENT;
		}

		int denom_idx = find_real_counter_by_name(reals, real_cnt, pmu->denom_name);
		if (denom_idx < 0) {
			eprintf("derived metric '%s': denominator counter '%s' not found\n",
				pmu->name, pmu->denom_name);
			return -ENOENT;
		}

		pmu->config1 = num_idx;
		pmu->config2 = denom_idx;
	}

	return 0;
}

int pmu_resolve_replay_defs(struct wprof_data_hdr *hdr)
{
	/* Default replay behavior: load all stored counters unless we have explicit --pmu */
	if (env.pmu_real_cnt == -1 && env.pmu_deriv_cnt == -1 && env.pmu_unresolved_cnt == -1) {
		env.pmu_real_cnt = hdr->pmu_def_real_cnt;
		env.pmu_reals = calloc(env.pmu_real_cnt, sizeof(*env.pmu_reals));
		for (int i = 0; i < env.pmu_real_cnt; i++)
			wevent_pmu_to_event(hdr, i, &env.pmu_reals[i]);

		env.pmu_deriv_cnt = hdr->pmu_def_deriv_cnt;
		env.pmu_derivs = calloc(env.pmu_deriv_cnt, sizeof(*env.pmu_derivs));
		for (int i = 0; i < env.pmu_deriv_cnt; i++)
			wevent_pmu_to_event(hdr, hdr->pmu_def_real_cnt + i, &env.pmu_derivs[i]);

		env.pmu_unresolved_cnt = 0;
	}

	/* Resolve unresolved events against stored real or derived defs */
	for (int i = 0; i < env.pmu_unresolved_cnt; i++) {
		struct pmu_event *pmu = &env.pmu_unresolveds[i];
		bool resolved = false;

		for (int j = 0; j < hdr->pmu_def_real_cnt; j++) {
			struct wevent_pmu_def *def = wevent_pmu_def(hdr, j);
			if (strcmp(pmu->name, wevent_str(hdr, def->name_stroff)) != 0)
				continue;

			if (env.pmu_real_cnt >= MAX_REAL_PMU_COUNTERS) {
				eprintf("replay: too many real PMU counters (max %d)\n", MAX_REAL_PMU_COUNTERS);
				return -E2BIG;
			}

			env.pmu_reals = realloc(env.pmu_reals, (env.pmu_real_cnt + 1) * sizeof(*env.pmu_reals));
			wevent_pmu_to_event(hdr, j, &env.pmu_reals[env.pmu_real_cnt]);
			env.pmu_real_cnt += 1;
			resolved = true;
			break;
		}

		if (resolved)
			continue;

		for (int j = 0; j < hdr->pmu_def_deriv_cnt; j++) {
			struct wevent_pmu_def *def = wevent_pmu_def(hdr, hdr->pmu_def_real_cnt + j);
			if (strcmp(pmu->name, wevent_str(hdr, def->name_stroff)) != 0)
				continue;

			env.pmu_derivs = realloc(env.pmu_derivs, (env.pmu_deriv_cnt + 1) * sizeof(*env.pmu_derivs));
			wevent_pmu_to_event(hdr, hdr->pmu_def_real_cnt + j, &env.pmu_derivs[env.pmu_deriv_cnt]);
			env.pmu_deriv_cnt += 1;
			resolved = true;
			break;
		}

		if (!resolved) {
			eprintf("replay: counter '%s' not found in captured data\n", pmu->name);
			return -ENOENT;
		}
	}

	/* Resolve real event stored_idx against stored data */
	for (int i = 0; i < env.pmu_real_cnt; i++) {
		struct pmu_event *pmu = &env.pmu_reals[i];

		pmu->stored_idx = -1;

		for (int j = 0; j < hdr->pmu_def_real_cnt; j++) {
			struct wevent_pmu_def *def = wevent_pmu_def(hdr, j);
			if (strcmp(pmu->name, wevent_str(hdr, def->name_stroff)) != 0)
				continue;
			pmu->stored_idx = j;
			break;
		}

		if (pmu->stored_idx < 0) {
			eprintf("replay: counter '%s' requested, but wasn't captured\n", pmu->name);
			return -ENOENT;
		}
	}

	/* Resolve derived metric indices against reals */
	return pmu_resolve_derived(env.pmu_reals, env.pmu_real_cnt, env.pmu_derivs, env.pmu_deriv_cnt);
}
