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
#include "protobuf.h"

/*
 * These IDs are persisted in wprof.data files, so once assigned, we need to
 * preserve the order (i.e., we'll need to stub out events that we remove)
 */
const struct perf_counter_def perf_counter_defs[] = {
	{ "cpu-cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, 1e-3, "cpu_cycles_kilo", IID_ANNK_PERF_CPU_CYCLES },
	{ "cpu-insns", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS, 1e-3, "cpu_insns_kilo", IID_ANNK_PERF_CPU_INSNS },
	{ "cache-hits", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES, 1e-3, "cache_hits_kilo", IID_ANNK_PERF_CACHE_HITS },
	{ "cache-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES, 1e-3, "cache_misses_kilo", IID_ANNK_PERF_CACHE_MISSES },
	{ "stall-cycles-fe", PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_FRONTEND, 1e-3, "stalled_cycles_fe_kilo", IID_ANNK_PERF_STALL_CYCLES_FE },
	{ "stall-cycles-be", PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_BACKEND, 1e-3, "stalled_cycles_be_kilo", IID_ANNK_PERF_STALL_CYCLES_BE },
	{},
};

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

static int parse_predefined(const char *spec, struct pmu_event *ev)
{
	/* Search predefined counters */
	for (int i = 0; perf_counter_defs[i].alias; i++) {
		if (strcmp(spec, perf_counter_defs[i].alias) != 0)
			continue;

		ev->type = PMU_TYPE_PREDEFINED;
		ev->perf_type = perf_counter_defs[i].perf_type;
		ev->config = perf_counter_defs[i].perf_cfg;
		ev->multiplier = perf_counter_defs[i].mul;
		ev->predefined_idx = i;
		snprintf(ev->name, sizeof(ev->name), "%s",
			 perf_counter_defs[i].trace_name);

		return 0;
	}

	return -ENOENT;
}

static int parse_raw_event(const char *spec, struct pmu_event *ev)
{
	char *endp;

	if (spec[0] != 'r')
		return -ENOENT;

	/* Parse hex value after 'r' */
	errno = 0;
	unsigned long long val = strtoull(spec + 1, &endp, 16);
	if (errno || *endp != '\0')
		return -EINVAL;

	ev->type = PMU_TYPE_RAW;
	ev->perf_type = PERF_TYPE_RAW;
	ev->config = val;
	ev->multiplier = 1.0;
	ev->predefined_idx = -1;
	snprintf(ev->name, sizeof(ev->name), "raw_0x%llx", val);

	return 0;
}

static int parse_software_event(const char *spec, struct pmu_event *ev)
{
	if (strncmp(spec, "sw:", 3) != 0)
		return -ENOENT;

	const char *sw_name = spec + 3;

	/* Search software events */
	for (int i = 0; sw_events[i].name; i++) {
		if (strcmp(sw_name, sw_events[i].name) != 0)
			continue;

		ev->type = PMU_TYPE_SOFTWARE;
		ev->perf_type = PERF_TYPE_SOFTWARE;
		ev->config = sw_events[i].config;
		ev->multiplier = 1.0;
		ev->predefined_idx = -1;
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

	snprintf(path, sizeof(path),
		 "/sys/bus/event_source/devices/%s/type", pmu_name);

	f = fopen(path, "r");
	if (!f)
		return -errno;

	ret = fscanf(f, "%u", type);
	fclose(f);

	return ret == 1 ? 0 : -EINVAL;
}

int pmu_resolve_symbolic_event(const char *pmu, const char *event_name,
			       __u64 *config, __u64 *config1, __u64 *config2)
{
	char path[256];
	char buf[256];
	FILE *f;

	snprintf(path, sizeof(path),
		 "/sys/bus/event_source/devices/%s/events/%s", pmu, event_name);

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

	/* Parse the format like "event=0x24,umask=0x01" */
	*config = 0;
	*config1 = 0;
	*config2 = 0;

	char *saveptr;
	char *token = strtok_r(buf, ",", &saveptr);
	while (token) {
		char *eq = strchr(token, '=');
		if (!eq) {
			token = strtok_r(NULL, ",", &saveptr);
			continue;
		}

		*eq = '\0';
		const char *key = token;
		const char *val_str = eq + 1;

		char *endp;
		unsigned long long val = strtoull(val_str, &endp, 0);
		if (*endp != '\0' && *endp != ',') {
			token = strtok_r(NULL, ",", &saveptr);
			continue;
		}

		if (strcmp(key, "event") == 0) {
			*config |= val;
		} else if (strcmp(key, "umask") == 0) {
			*config |= (val << 8);
		} else if (strcmp(key, "edge") == 0) {
			*config |= (val << 18);
		} else if (strcmp(key, "inv") == 0) {
			*config |= (val << 23);
		} else if (strcmp(key, "cmask") == 0) {
			*config |= (val << 24);
		} else if (strcmp(key, "config1") == 0) {
			*config1 = val;
		} else if (strcmp(key, "config2") == 0) {
			*config2 = val;
		}
		/* Ignore unknown keys */

		token = strtok_r(NULL, ",", &saveptr);
	}

	return 0;
}

/*
 * Try to match a hardware cache event by name.
 * Returns 0 on success, -ENOENT if not found.
 */
static int lookup_hw_cache_event(const char *name, struct pmu_event *ev)
{
	for (int i = 0; hw_cache_events[i].name; i++) {
		if (strcmp(name, hw_cache_events[i].name) != 0)
			continue;

		ev->type = PMU_TYPE_PMU;  /* Treat as PMU for storage */
		ev->perf_type = PERF_TYPE_HW_CACHE;
		ev->config = hw_cache_events[i].cache_id |
			     (hw_cache_events[i].op_id << 8) |
			     (hw_cache_events[i].result_id << 16);
		ev->config1 = 0;
		ev->config2 = 0;
		ev->multiplier = 1.0;
		ev->predefined_idx = -1;
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
 *   cpu/event=0x3c/           - raw event code
 *   cpu/event=0x3c,umask=0x01,name=my_event/  - with name
 *   cpu/L1-icache-load-misses/  - symbolic event
 */
static int parse_pmu_style_event(const char *spec, struct pmu_event *ev)
{
	char pmu_name[64];
	char attrs[256];
	const char *slash1, *slash2;

	/* Parse pmu/attrs/ format */
	slash1 = strchr(spec, '/');
	if (!slash1)
		return -ENOENT;

	/* Find closing slash */
	slash2 = strrchr(spec, '/');
	if (!slash2 || slash2 == slash1)
		return -EINVAL;

	/* Extract PMU name */
	size_t pmu_len = slash1 - spec;
	if (pmu_len >= sizeof(pmu_name))
		return -EINVAL;
	memcpy(pmu_name, spec, pmu_len);
	pmu_name[pmu_len] = '\0';

	/* Extract attrs (between slashes) */
	size_t attrs_len = slash2 - slash1 - 1;
	if (attrs_len >= sizeof(attrs))
		return -EINVAL;
	memcpy(attrs, slash1 + 1, attrs_len);
	attrs[attrs_len] = '\0';

	/* Resolve PMU type */
	__u32 pmu_type;
	int err = pmu_resolve_type(pmu_name, &pmu_type);
	if (err)
		return err;

	ev->type = PMU_TYPE_PMU;
	ev->perf_type = pmu_type;
	/*
	 * Multiplier is 1.0 for PMU events since they report raw counts.
	 * Only predefined events (from perf_counter_defs) have custom
	 * multipliers, e.g., for converting cycles to MHz.
	 */
	ev->multiplier = 1.0;
	ev->predefined_idx = -1;

	/* Check if attrs contains '=' (key=value format) */
	if (strchr(attrs, '=')) {
		/* Parse key=value pairs */
		char attrs_copy[256];
		snprintf(attrs_copy, sizeof(attrs_copy), "%s", attrs);

		ev->config = 0;
		ev->config1 = 0;
		ev->config2 = 0;

		char *saveptr;
		char *token = strtok_r(attrs_copy, ",", &saveptr);
		while (token) {
			char *eq = strchr(token, '=');
			if (!eq) {
				token = strtok_r(NULL, ",", &saveptr);
				continue;
			}

			*eq = '\0';
			const char *key = token;
			const char *val_str = eq + 1;

			if (strcmp(key, "name") == 0) {
				if (strlen(val_str) >= sizeof(ev->name))
					return -ENAMETOOLONG;
				snprintf(ev->name, sizeof(ev->name), "%s", val_str);
			} else {
				char *endp;
				unsigned long long val = strtoull(val_str, &endp, 0);
				if (*endp != '\0') {
					token = strtok_r(NULL, ",", &saveptr);
					continue;
				}

				if (strcmp(key, "event") == 0) {
					ev->config |= val;
				} else if (strcmp(key, "umask") == 0) {
					ev->config |= (val << 8);
				} else if (strcmp(key, "edge") == 0) {
					ev->config |= (val << 18);
				} else if (strcmp(key, "inv") == 0) {
					ev->config |= (val << 23);
				} else if (strcmp(key, "cmask") == 0) {
					ev->config |= (val << 24);
				} else if (strcmp(key, "config") == 0) {
					ev->config = val;
				} else if (strcmp(key, "config1") == 0) {
					ev->config1 = val;
				} else if (strcmp(key, "config2") == 0) {
					ev->config2 = val;
				}
			}

			token = strtok_r(NULL, ",", &saveptr);
		}

		/* Generate name if not specified */
		if (ev->name[0] == '\0') {
			snprintf(ev->name, sizeof(ev->name), "%s_0x%llx",
				 pmu_name, (unsigned long long)ev->config);
		}
	} else {
		/* Symbolic event name - try hardware cache events first */
		err = lookup_hw_cache_event(attrs, ev);
		if (err == 0) {
			/* Found as hardware cache event */
			return 0;
		}

		/* Try sysfs resolution */
		err = pmu_resolve_symbolic_event(pmu_name, attrs,
						 &ev->config, &ev->config1, &ev->config2);
		if (err)
			return err;

		snprintf(ev->name, sizeof(ev->name), "%s_%s", pmu_name, attrs);
	}

	return 0;
}

/*
 * pmu_parse_event() - Main entry point that tries all event format parsers.
 * parse_pmu_style_event() - Parses only PMU-style events (cpu/xxx/).
 *
 * Naming: pmu_parse_event is the public API that tries all formats,
 * while parse_pmu_style_event is an internal helper for PMU-specific syntax.
 */
int pmu_parse_event(const char *spec, struct pmu_event *out)
{
	int err;

	/* Initialize output */
	memset(out, 0, sizeof(*out));
	out->multiplier = 1.0;
	out->predefined_idx = -1;

	/* Try each parser in order */

	/* 1. Predefined events */
	err = parse_predefined(spec, out);
	if (err == 0)
		return 0;
	if (err != -ENOENT)
		return err;

	/* 2. Raw events (r####) */
	err = parse_raw_event(spec, out);
	if (err == 0)
		return 0;
	if (err != -ENOENT)
		return err;

	/* 3. PMU events (pmu/xxx/) */
	err = parse_pmu_style_event(spec, out);
	if (err == 0)
		return 0;
	if (err != -ENOENT)
		return err;

	/* 4. Software events (sw:xxx) */
	err = parse_software_event(spec, out);
	if (err == 0)
		return 0;

	return -EINVAL;
}

void pmu_event_to_stored(const struct pmu_event *ev, struct pmu_event_stored *stored)
{
	memset(stored, 0, sizeof(*stored));
	stored->perf_type = ev->perf_type;
	stored->config = ev->config;
	stored->config1 = ev->config1;
	stored->config2 = ev->config2;
	snprintf(stored->name, sizeof(stored->name), "%s", ev->name);
	stored->multiplier = ev->multiplier;
}

void pmu_event_from_stored(const struct pmu_event_stored *stored, struct pmu_event *ev)
{
	memset(ev, 0, sizeof(*ev));
	ev->type = PMU_TYPE_PMU; /* Generic for restored events */
	ev->perf_type = stored->perf_type;
	ev->config = stored->config;
	ev->config1 = stored->config1;
	ev->config2 = stored->config2;
	snprintf(ev->name, sizeof(ev->name), "%s", stored->name);
	ev->multiplier = stored->multiplier;
	ev->predefined_idx = -1;
}

void pmu_generate_name(struct pmu_event *ev)
{
	if (ev->name[0] != '\0')
		return; /* Already has a name */

	switch (ev->type) {
	case PMU_TYPE_PREDEFINED:
		/* Should already have name from perf_counter_defs */
		break;
	case PMU_TYPE_RAW:
		snprintf(ev->name, sizeof(ev->name), "raw_0x%llx",
			 (unsigned long long)ev->config);
		break;
	case PMU_TYPE_PMU:
		snprintf(ev->name, sizeof(ev->name), "pmu_0x%llx",
			 (unsigned long long)ev->config);
		break;
	case PMU_TYPE_SOFTWARE:
		snprintf(ev->name, sizeof(ev->name), "sw_%llu",
			 (unsigned long long)ev->config);
		break;
	}
}

int parse_derived_metric(const char *spec, struct derived_metric *out)
{
	const char *eq, *slash;

	memset(out, 0, sizeof(*out));
	out->num_idx = -1;
	out->denom_idx = -1;

	/* Find '=' separator */
	eq = strchr(spec, '=');
	if (!eq || eq == spec)
		return -EINVAL;

	/* Find '/' separator in the formula */
	slash = strchr(eq + 1, '/');
	if (!slash || slash == eq + 1)
		return -EINVAL;

	/* Extract metric name */
	size_t name_len = eq - spec;
	if (name_len >= sizeof(out->name))
		return -EINVAL;
	memcpy(out->name, spec, name_len);
	out->name[name_len] = '\0';

	/* Extract numerator */
	size_t num_len = slash - (eq + 1);
	if (num_len >= sizeof(out->numerator))
		return -EINVAL;
	memcpy(out->numerator, eq + 1, num_len);
	out->numerator[num_len] = '\0';

	/* Extract denominator */
	const char *denom_start = slash + 1;
	size_t denom_len = strlen(denom_start);
	if (denom_len == 0 || denom_len >= sizeof(out->denominator))
		return -EINVAL;
	snprintf(out->denominator, sizeof(out->denominator), "%s", denom_start);

	return 0;
}
