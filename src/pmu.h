/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __PMU_H_
#define __PMU_H_

#include <stdbool.h>
#include <linux/perf_event.h>
#include "wprof_types.h"

#define MAX_PMU_COUNTERS 6
#define MAX_DERIVED_METRICS 4
#define PMU_NAME_LEN 64

struct perf_counter_def {
	const char *alias;
	int perf_type;
	int perf_cfg;
	double mul;
	const char *trace_name;
	u32 trace_name_iid;
};

extern const struct perf_counter_def perf_counter_defs[];

/* Event type for internal tracking of how the event was specified */
enum pmu_event_type {
	PMU_TYPE_PREDEFINED,   /* Existing hardware counters from perf_counter_defs */
	PMU_TYPE_RAW,          /* Raw hex event (r####) */
	PMU_TYPE_PMU,          /* Named PMU (cpu/xxx/) */
	PMU_TYPE_SOFTWARE,     /* Software events (sw:xxx) */
};

/*
 * Parsed PMU event specification.
 *
 * This struct extends perf_event_attr fields with wprof-specific metadata:
 * - Event type tracking for parsing/error reporting
 * - Human-readable name for trace output
 * - Scaling multiplier for display (e.g., cycles -> MHz)
 * - Index into legacy perf_counter_defs for backwards compatibility
 *
 * We don't use perf_event_attr directly because it doesn't include our
 * naming and multiplier fields, and we only need a subset of its fields.
 */
struct pmu_event {
	enum pmu_event_type type;

	/* perf_event_attr fields */
	__u32 perf_type;       /* PERF_TYPE_* */
	__u64 config;          /* event config */
	__u64 config1;         /* extended config */
	__u64 config2;         /* extended config */

	/* Output configuration */
	char name[PMU_NAME_LEN]; /* trace output name (user-specified or auto) */
	double multiplier;       /* scaling factor (default 1.0) */

	/* For predefined events, index into legacy perf_counter_defs */
	int predefined_idx;    /* -1 if not predefined */
};

/* Stored format for data persistence (fixed size) */
struct pmu_event_stored {
	__u32 perf_type;
	__u64 config;
	__u64 config1;
	__u64 config2;
	char name[PMU_NAME_LEN];
	double multiplier;
} __attribute__((aligned(8)));

/**
 * Derived metric - computed from ratio of two counters
 * Format: "name=numerator/denominator"
 */
struct derived_metric {
	char name[PMU_NAME_LEN];       /* Output metric name */
	char numerator[PMU_NAME_LEN];  /* Counter name for numerator */
	char denominator[PMU_NAME_LEN]; /* Counter name for denominator */
	int num_idx;                   /* Resolved index into pmu_events[] */
	int denom_idx;                 /* Resolved index into pmu_events[] */
};

/**
 * pmu_parse_event - Parse event specification string into pmu_event struct
 * @spec: Event specification string (e.g., "cpu-cycles", "r003c", "cpu/event=0x3c/")
 * @out: Output pmu_event struct
 *
 * Returns 0 on success, negative error code on failure.
 *
 * Supported formats:
 *   - Predefined: "cpu-cycles", "cache-misses", etc.
 *   - Raw: "r003c" (hex config after 'r')
 *   - PMU: "cpu/event=0x3c,umask=0x00/" or "cpu/L1-icache-load-misses/"
 *   - Software: "sw:page-faults", "sw:context-switches"
 */
int pmu_parse_event(const char *spec, struct pmu_event *out);

/**
 * pmu_resolve_type - Resolve PMU name to perf type
 * @pmu_name: PMU name (e.g., "cpu", "software")
 * @type: Output perf type
 *
 * Reads /sys/bus/event_source/devices/<pmu_name>/type
 * Returns 0 on success, negative error code on failure.
 */
int pmu_resolve_type(const char *pmu_name, __u32 *type);

/**
 * pmu_resolve_symbolic_event - Resolve symbolic event name to config value
 * @pmu: PMU name (e.g., "cpu")
 * @event_name: Symbolic event name (e.g., "L1-icache-load-misses")
 * @config: Output config value
 * @config1: Output config1 value
 * @config2: Output config2 value
 *
 * Reads /sys/bus/event_source/devices/<pmu>/events/<event_name>
 * Returns 0 on success, negative error code on failure.
 */
int pmu_resolve_symbolic_event(const char *pmu, const char *event_name,
			       __u64 *config, __u64 *config1, __u64 *config2);

/**
 * pmu_event_to_stored - Convert pmu_event to stored format for data persistence
 */
void pmu_event_to_stored(const struct pmu_event *ev, struct pmu_event_stored *stored);

/**
 * pmu_event_from_stored - Convert stored format back to pmu_event
 */
void pmu_event_from_stored(const struct pmu_event_stored *stored, struct pmu_event *ev);

/**
 * pmu_generate_name - Generate auto name for event if not user-specified
 * @ev: pmu_event to generate name for (modified in place)
 */
void pmu_generate_name(struct pmu_event *ev);

/**
 * parse_derived_metric - Parse derived metric specification
 * @spec: Metric specification (e.g., "ipc=instructions/cycles")
 * @out: Output derived_metric struct
 *
 * Returns 0 on success, negative error code on failure.
 */
int parse_derived_metric(const char *spec, struct derived_metric *out);

#endif /* __PMU_H_ */
