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
	OPT_STATS = 1003,
	OPT_LIBBPF_LOGS = 1004,
	OPT_BREAKOUT_COUNTERS = 1008,
	OPT_PB_DEBUG_INTERNS = 1009,
	OPT_PB_DISABLE_INTERNS = 1010,
	OPT_RINGBUF_CNT = 1011,

	OPT_ALLOW_TID = 2000,
	OPT_DENY_TID = 2001,
	OPT_ALLOW_TNAME = 2002,
	OPT_DENY_TNAME = 2003,
	OPT_ALLOW_IDLE = 2004,
	OPT_DENY_IDLE = 2005,
	OPT_ALLOW_KTHREAD = 2006,
	OPT_DENY_KTHREAD = 2007,
};

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "stats", OPT_STATS, NULL, 0, "Print various wprof stats (BPF, resource usage, etc.)" },
	{ "libbpf-logs", OPT_LIBBPF_LOGS, NULL, 0, "Emit libbpf verbose logs" },

	{ "dur-ms", 'd', "DURATION", 0, "Limit running duration to given number of ms (default: 1000ms)" },
	{ "freq", 'f', "HZ", 0, "On-CPU timer interrupt frequency (default: 100Hz, i.e., every 10ms)" },

	{ "data", 'D', "FILE", 0, "Data dump path (defaults to 'wprof.data' in current directory)" },
	{ "trace", 'T', "FILE", 0, "Emit trace to specified file" },
	{ "replay", 'R', NULL, 0, "Re-process raw dump (no actual BPF data gathering)" },

	{ "stack-traces", 's', NULL, 0, "Capture stack traces" },
	{ "no-stack-traces", 'S', NULL, 0, "Don't capture stack traces" },

	/* allow/deny filters */
	{ "pid", 'p', "PID", 0, "PID allow filter" },
	{ "no-pid", 'P', "PID", 0, "PID deny filter" },
	{ "tid", OPT_ALLOW_TID, "TID", 0, "TID allow filter" },
	{ "no-tid", OPT_DENY_TID, "TID", 0, "TID deny filter" },
	{ "process-name", 'n', "NAME_GLOB", 0, "Process name allow filter" },
	{ "no-process-name", 'N', "NAME_GLOB", 0, "Process name deny filter" },
	{ "thread-name", OPT_ALLOW_TNAME, "NAME_GLOB", 0, "Thread name allow filter" },
	{ "no-thread-name", OPT_DENY_TNAME, "NAME_GLOB", 0, "Thread name deny filter" },
	{ "idle", OPT_ALLOW_IDLE, NULL, 0, "Allow idle tasks" },
	{ "no-idle", OPT_DENY_IDLE, NULL, 0, "Deny idle tasks" },
	{ "kthread", OPT_ALLOW_KTHREAD, NULL, 0, "Allow kernel tasks" },
	{ "no-kthread", OPT_DENY_KTHREAD, NULL, 0, "Deny kernel tasks" },

	/* event subset targeting */
	{ "feature", 'F', "FEAT", 0, "Features selector. Supported: ipi, numa" },

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
	case OPT_STATS:
		env.stats = true;
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
	/* FEATURES SELECTION */
	case 'F':
		if (strcasecmp(arg, "numa") == 0) {
			env.capture_numa = true;
		} else if (strcasecmp(arg, "ipi") == 0) {
			env.capture_ipi = true;
		} else {
			fprintf(stderr, "Unrecognized requested feature '%s!\n", arg);
			return -EINVAL;
		}
		break;
	/* FILTERING */
	case 'p':
		err = append_num(&env.allow_pids, &env.allow_pid_cnt, arg);
		if (err)
			return err;
		break;
	case 'P':
		err = append_num(&env.deny_pids, &env.deny_pid_cnt, arg);
		if (err)
			return err;
		break;
	case OPT_ALLOW_TID:
		err = append_num(&env.allow_tids, &env.allow_tid_cnt, arg);
		if (err)
			return err;
		break;
	case OPT_DENY_TID:
		err = append_num(&env.deny_tids, &env.deny_tid_cnt, arg);
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
			err = append_str_file(&env.deny_pnames, &env.deny_pname_cnt, arg + 1);
			if (err)
				return err;
		} else if (append_str(&env.deny_pnames, &env.deny_pname_cnt, arg)) {
			return -ENOMEM;
		}
		break;
	case OPT_ALLOW_TNAME:
		if (arg[0] == '@') {
			err = append_str_file(&env.allow_tnames, &env.allow_tname_cnt, arg + 1);
			if (err)
				return err;
		} else if (append_str(&env.allow_tnames, &env.allow_tname_cnt, arg)) {
			return -ENOMEM;
		}
		break;
	case OPT_DENY_TNAME:
		if (arg[0] == '@') {
			err = append_str_file(&env.deny_tnames, &env.deny_tname_cnt, arg + 1);
			if (err)
				return err;
		} else if (append_str(&env.deny_tnames, &env.deny_tname_cnt, arg)) {
			return -ENOMEM;
		}
		break;
	case OPT_ALLOW_IDLE:
		env.allow_idle = true;
		break;
	case OPT_DENY_IDLE:
		env.deny_idle = true;
		break;
	case OPT_ALLOW_KTHREAD:
		env.allow_kthread = true;
		break;
	case OPT_DENY_KTHREAD:
		env.deny_kthread = true;
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
