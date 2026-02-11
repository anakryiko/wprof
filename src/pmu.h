/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __PMU_H_
#define __PMU_H_

#include <stdbool.h>
#include <stdint.h>
#include <linux/perf_event.h>
#include "wprof_types.h"
#include "wprof.h"

#define PMU_NAME_LEN 64

/* Marker for derived metrics (not a real perf type) */
#define PERF_TYPE_DERIVED (UINT32_MAX - 1)

/* Marker for unresolved events (name-only, to be resolved during replay) */
#define PERF_TYPE_UNRESOLVED UINT32_MAX

/*
 * Parsed PMU event specification.
 *
 * perf_type values:
 * - PERF_TYPE_SOFTWARE (1): Software events (sw:xxx)
 * - PERF_TYPE_HW_CACHE (3): Hardware cache events
 * - PERF_TYPE_RAW (4): Raw hex events (r####)
 * - Dynamic types (from sysfs): Named PMU events (cpu/xxx/)
 * - PERF_TYPE_DERIVED (UINT32_MAX - 1): Derived metrics
 *
 * For derived events (after resolution):
 * - config1 = numerator counter index into pmu_reals[]
 * - config2 = denominator counter index into pmu_reals[]
 */
struct pmu_event {
	/* perf_event_attr fields (for derived: config1=num_idx, config2=denom_idx) */
	__u32 perf_type;       /* PERF_TYPE_* or dynamic PMU type */
	__u64 config;          /* event config */
	__u64 config1;         /* extended config (or numerator index for derived) */
	__u64 config2;         /* extended config (or denominator index for derived) */

	/* Output configuration */
	char name[PMU_NAME_LEN]; /* trace output name (user-specified or auto) */
	u32 name_iid;            /* pre-interned Perfetto annotation key IID */

	/* For replay: index into stored counter data (ctrs.val[]) */
	int stored_idx;        /* -1 if unset, resolved during replay */

	/* Temporary storage for derived metric parsing (cleared after resolution) */
	char *num_name;   /* numerator counter name */
	char *denom_name; /* denominator counter name */
};

/* Stored format for data persistence (fixed size) */
struct pmu_event_stored {
	__u32 perf_type;
	__u64 config;
	__u64 config1;
	__u64 config2;
	char name[PMU_NAME_LEN];
} __attribute__((aligned(8)));

/**
 * parse_perf_counter - Parse event specification string into pmu_event struct
 * @spec: Event specification string
 * @out: Output pmu_event struct
 *
 * Returns 0 on success, negative error code on failure.
 *
 * Supported formats:
 *   - Software: "sw:page-faults", "sw:context-switches"
 *   - Raw: "r003c" (hex config after 'r')
 *   - PMU: "cpu/event=0x3c,umask=0x00/" or "cpu/cpu-cycles/" (sysfs resolution)
 *   - Hardware cache: "L1-icache-loads", "iTLB-load-misses"
 *   - Derived: "derived:name=numerator/denominator" (requires resolution after parsing)
 */
int parse_perf_counter(const char *spec, struct pmu_event *out);

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
 * serialized_pmu_event - Convert pmu_event to stored format for data persistence
 */
void serialized_pmu_event(const struct pmu_event *ev, struct pmu_event_stored *stored);

/**
 * deserialized_pmu_event - Convert stored format back to pmu_event
 */
void deserialized_pmu_event(const struct pmu_event_stored *stored, struct pmu_event *ev);

/**
 * pmu_resolve_derived - Resolve derived metric indices
 * @reals: Array of real (hardware) pmu_events
 * @real_cnt: Number of real events
 * @derivs: Array of derived pmu_events
 * @deriv_cnt: Number of derived events
 *
 * For each derived event, resolves numerator/denominator names to indices
 * into the reals array and stores them in config/config1.
 *
 * Returns 0 on success, negative error code on failure.
 */
int pmu_resolve_derived(struct pmu_event *reals, int real_cnt,
			struct pmu_event *derivs, int deriv_cnt);

/**
 * pmu_collect_replay_defs - Collect and resolve PMU definitions for replay mode
 * @hdr: Data header from the stored capture
 *
 * If no --pmu was specified, loads all stored counters. Otherwise, resolves
 * unresolved (name-only) events against stored real/derived defs, pulls in
 * derived counter dependencies, and resolves all indices.
 *
 * Returns 0 on success, negative error code on failure.
 */
struct wprof_data_hdr;
int pmu_resolve_replay_defs(struct wprof_data_hdr *hdr);

#endif /* __PMU_H_ */
