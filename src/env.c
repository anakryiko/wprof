// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <argp.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "utils.h"
#include "wprof.h"
#include "env.h"

const char *argp_program_version = "wprof 0.0";
const char *argp_program_bug_address = "<andrii@kernel.org>";
const char argp_program_doc[] = "BPF-based wallcklock profiler.\n";

struct env env = {
	.data_path = "wprof.data",
	.freq = 100,
	.ringbuf_sz = DEFAULT_RINGBUF_SZ,
	.ringbuf_cnt = 1,
	.task_state_sz = DEFAULT_TASK_STATE_SZ,
	.stack_traces = true,
	.dur_ms = 1000,
};

enum {
	OPT_RINGBUF_SZ = 1000,
	OPT_TASK_STATE_SZ = 1001,
	OPT_BPF_STATS = 1003,
	OPT_LIBBPF_LOGS = 1004,
	OPT_BREAKOUT_COUNTERS = 1008,
	OPT_PB_DEBUG_INTERNS = 1009,
	OPT_PB_DISABLE_INTERNS = 1010,
	OPT_RINGBUF_CNT = 1011,
};

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "bpf-stats", OPT_BPF_STATS, NULL, 0, "Enable and print BPF runtime stats" },
	{ "libbpf-logs", OPT_LIBBPF_LOGS, NULL, 0, "Emit libbpf verbose logs" },

	{ "dur-ms", 'd', "DURATION", 0, "Limit running duration to given number of ms (default: 1000ms)" },
	{ "freq", 'f', "HZ", 0, "On-CPU timer interrupt frequency (default: 100Hz, i.e., every 10ms)" },

	{ "data", 'D', "FILE", 0, "Data dump path (defaults to 'wprof.data' in current directory)" },
	{ "trace", 'T', "FILE", 0, "Emit trace to specified file" },
	{ "replay", 'R', NULL, 0, "Re-process raw dump (no actual BPF data gathering)" },

	{ "stack-traces", 's', NULL, 0, "Capture stack traces" },
	{ "no-stack-traces", 'S', NULL, 0, "Don't capture stack traces" },

	{ "pid", 'p', "PID", 0, "PID filter (track only specified PIDs)" },
	{ "cpu", 'c', "CPU", 0, "CPU filter (track only specified CPUs)" },

	{ "ringbuf-size", OPT_RINGBUF_SZ, "SIZE", 0, "BPF ringbuf size (in KBs)" },
	{ "task-state-size", OPT_TASK_STATE_SZ, "SIZE", 0, "BPF task state map size (in threads)" },
	{ "ringbuf-cnt", OPT_RINGBUF_CNT, "N", 0, "Number of BPF ringbufs to use" },

	{ "cpu-counter", 'C', "NAME", 0, "Capture and emit specified perf/CPU/hardware counter (cpu-cycles, cpu-insns, cache-hits, cache-misses, stalled-cycles-fe, stallec-cycles-be)" },
	{ "breakout-counters", OPT_BREAKOUT_COUNTERS, NULL, 0, "Emit separate track for counters" },

	{ "pb-debug-interns", OPT_PB_DEBUG_INTERNS, NULL, 0, "Emit interned strings" },
	{ "pb-disable-interns", OPT_PB_DISABLE_INTERNS, NULL, 0, "Disable string interning for Perfetto traces" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	int err = 0;

	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case OPT_BPF_STATS:
		env.bpf_stats = true;
		break;
	case OPT_LIBBPF_LOGS:
		env.libbpf_logs = true;
		break;
	case 'd':
		errno = 0;
		env.dur_ms = strtol(arg, NULL, 0);
		if (errno || env.dur_ms < 0) {
			fprintf(stderr, "Invalid running duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'D':
		env.data_path = strdup(arg);
		break;
	case 'R':
		env.replay = true;
		break;
	case 'T':
		if (env.trace_path) {
			fprintf(stderr, "Only one trace file can be specified!\n");
			return -EINVAL;
		}
		env.trace_path = strdup(arg);
		break;
	case 's':
		env.stack_traces = true;
		break;
	case 'S':
		env.stack_traces = false;
		break;
	/* FILTERING */
	case 'p':
		err = append_num(&env.allow_pids, &env.allow_pid_cnt, arg);
		if (err)
			return err;
		break;
	case 'P':
		err = append_num(&env.allow_tids, &env.allow_tid_cnt, arg);
		if (err)
			return err;
		break;
	case 'n':
		if (arg[0] == '@') {
			err = append_str_file(&env.allow_pnames, &env.allow_pname_cnt, arg + 1);
			if (err)
				return err;
		} else if (append_str(&env.allow_pnames, &env.allow_pname_cnt, arg)) {
			return -ENOMEM;
		}
		break;
	case 'N':
		if (arg[0] == '@') {
			err = append_str_file(&env.allow_tnames, &env.allow_tname_cnt, arg + 1);
			if (err)
				return err;
		} else if (append_str(&env.allow_tnames, &env.allow_tname_cnt, arg)) {
			return -ENOMEM;
		}
		break;
	case 'c':
		err = append_num(&env.allow_cpus, &env.allow_cpu_cnt, arg);
		if (err)
			return err;
		break;
	/* TUNING */
	case 'f':
		errno = 0;
		env.freq = strtol(arg, NULL, 0);
		if (errno || env.freq <= 0) {
			fprintf(stderr, "Invalid frequency: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_RINGBUF_SZ:
		errno = 0;
		env.ringbuf_sz = strtol(arg, NULL, 0);
		if (errno || env.ringbuf_sz < 0) {
			fprintf(stderr, "Invalid ringbuf size: %s\n", arg);
			argp_usage(state);
		}
		env.ringbuf_sz = round_pow_of_2(env.ringbuf_sz * 1024);
		break;
	case OPT_TASK_STATE_SZ:
		errno = 0;
		env.task_state_sz = strtol(arg, NULL, 0);
		if (errno || env.task_state_sz < 0) {
			fprintf(stderr, "Invalid task state size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_RINGBUF_CNT:
		errno = 0;
		env.ringbuf_cnt = strtol(arg, NULL, 0);
		if (errno || env.ringbuf_cnt < 0) {
			fprintf(stderr, "Invalid ringbuf count: %s\n", arg);
			argp_usage(state);
		}
		env.ringbuf_cnt = round_pow_of_2(env.ringbuf_cnt);
		break;
	case 'C': {
		int counter_idx = -1;

		for (int i = 0; perf_counter_defs[i].alias; i++) {
			if (strcmp(arg, perf_counter_defs[i].alias) != 0)
				continue;

			counter_idx = i;
			break;
		}

		if (counter_idx < 0) {
			fprintf(stderr, "Unrecognized counter '%s'!\n", arg);
			argp_usage(state);
		}

		for (int i = 0; i < env.counter_cnt; i++) {
			if (env.counter_ids[i] == counter_idx) {
				counter_idx = -1;
				break;
			}
		}

		if (counter_idx >= 0) {
			if (env.counter_cnt >= MAX_PERF_COUNTERS) {
				fprintf(stderr, "Too many perf counters requested, only %d are currently supported!\n", MAX_PERF_COUNTERS);
				return -E2BIG;
			}
			env.counter_ids[env.counter_cnt++] = counter_idx;
		}
		break;
	}
	case OPT_BREAKOUT_COUNTERS:
		env.breakout_counters = true;
		break;
	case OPT_PB_DEBUG_INTERNS:
		env.pb_debug_interns = true;
		break;
	case OPT_PB_DISABLE_INTERNS:
		env.pb_disable_interns = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};
