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
#include "data.h"
#include "requests.h"
#include "utrace_cfg.h"
#include "strs.h"
#include "elf_utils.h"
#include "inject.h"

const char *argp_program_version = "wprof v" WPROF_VERSION;

static void wprof_print_version(FILE *stream, struct argp_state *state)
{
	fprintf(stream, "wprof v%s\n", WPROF_VERSION);
	fprintf(stream, "  wprof build-id:          %s\n", elf_self_build_id());
	fprintf(stream, "  libwprofinj.so build-id: %s\n", wprof_injectee_build_id());
}
void (*argp_program_version_hook)(FILE *stream, struct argp_state *state) = wprof_print_version;

const char *argp_program_bug_address = "Andrii Nakryiko <andrii@kernel.org>";
const char argp_program_doc[] =
"wprof is a system-wide workload tracer and profiler.\n"
"\n"
"USAGE\n"
"    To capture system-wide trace for 3 seconds and generate Perfetto trace:\n"
"        $ sudo wprof -d3000 -T trace.pb\n"
"    To replay captured data and add aditional filters (note no sudo needed):\n"
"        $ wprof -R --replay-end 1s --no-idle -T subtrace.pb\n"
"    Check information about recorded data dump:\n"
"        $ wprof -RI [-D wprof.data]\n"
"    Generate JSON output (use --json-schema to see the data model):\n"
"        $ wprof -R -J trace.json\n"
"\n"
"See `wprof --help` for more information.\n";

bool env_verbose;
int env_debug_level;
enum log_subset env_log_set;

struct env env = {
	.data_path = "wprof.data",
	.ringbuf_sz = DEFAULT_RINGBUF_SZ,
	.ringbuf_cnt = 0,
	.task_state_sz = -1,	/* resolved to a backend-specific default in setup_bpf() */
	.requested_stack_traces = ST_UNSET,
	.capture_ipis = UNSET,
	.capture_requests = UNSET,
	.capture_scx = UNSET,
	.capture_cuda = UNSET,
	.capture_pystacks = UNSET,
	.capture_pytrace = UNSET,
	.capture_pytorch = UNSET,
	.capture_utrace = UNSET,
	.capture_softirq = UNSET,
	.capture_hardirq = UNSET,
	.capture_sched = UNSET,
	.capture_wakeup = UNSET,
	.capture_task_life = UNSET,
	.capture_wq = UNSET,
	.emit_sched_view = UNSET,
	.emit_numa = UNSET,
	.emit_tidpid = UNSET,
	.emit_timer_ticks = UNSET,
	.emit_sched_extras = UNSET,
	.emit_pystacks_only = UNSET,
	.emit_req_split = UNSET,
	.emit_req_embed = UNSET,
	.emit_embed_stacks = UNSET,
	.pmu_real_cnt = -1,
	.pmu_deriv_cnt = -1,
	.pmu_unresolved_cnt = -1,
	.pmu_event_cnt = -1,
	.fr_keep_time_ns = -1,
	.fr_keep_size = -1,
	.fr_chunk_size = DEFAULT_FR_CHUNK_SZ,
};

enum {
	OPT_RINGBUF_SZ = 1000,
	OPT_TASK_STATE_SZ = 1001,
	OPT_TIMER_FREQ = 1002,
	OPT_STATS = 1003,
	OPT_DEBUG = 1004,
	OPT_LOG = 1005,
	OPT_RINGBUF_CNT = 1011,
	OPT_SYMBOLIZE_FRUGALLY = 1012,
	OPT_REPLAY_OFFSET_START = 1013,
	OPT_REPLAY_OFFSET_END = 1014,
	OPT_NO_STACK_TRACES = 1015,
	OPT_PMU_COUNTER = 1016,
	OPT_NO_PMU = 1017,
	OPT_JSON_SCHEMA = 1018,
	OPT_PREPARE = 1019,
	OPT_ACTIVATE = 1020,

	OPT_ALLOW_TID = 2000,
	OPT_DENY_TID = 2001,
	OPT_ALLOW_TNAME = 2002,
	OPT_DENY_TNAME = 2003,
	OPT_ALLOW_IDLE = 2004,
	OPT_DENY_IDLE = 2005,
	OPT_ALLOW_KTHREAD = 2006,
	OPT_DENY_KTHREAD = 2007,

	OPT_REQ_LIST = 3000,
	OPT_REQ_SORT = 3001,
	OPT_REQ_SORT_ASC = 3002,
	OPT_REQ_SORT_DESC = 3003,
	OPT_REQ_FILTER = 3004,
	OPT_REQ_TOP_N = 3005,
	OPT_REQ_BOTTOM_N = 3006,

	OPT_SEAL_OUTPUT = 4000,
	OPT_RECORD = 4001,
};

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose output" },
	{ "stats", OPT_STATS, NULL, 0, "Print various wprof stats (BPF, resource usage, etc.)" },
	{ "debug", OPT_DEBUG, "FEAT", 0, "Debug features (pb-debug-interns, pb-disable-interns, keep-workdir, raw-stacks, no-tsidx, no-task-storage, fr-chunk-size=SIZE)"},
	{ "log", OPT_LOG, "LOG", 0, "Debug logging subset selector (libbpf, usdt, topology, inject, tracee, discovery)"},
	{ "dur", 'd', "DURATION", 0, "Limit running duration; accepts time units s/ms/us/ns/m/h, bare number is ms (default: 1000ms)" },
	{ "dur-ms", 0, 0, OPTION_ALIAS },
	{ "flight-record", 'F', "SPEC", OPTION_ARG_OPTIONAL,
	  "Flight-recorder mode: keep a rolling window, stop on Ctrl-C. SPEC is a "
	  "comma list of a time and/or size limit, e.g. 10s,1000mb. Bare -F uses "
	  "1s,1gb; naming one dimension leaves the other unlimited; a 0 token "
	  "disables a dimension. Mutually exclusive with -d." },
	{ "prepare", OPT_PREPARE, "WHEN", 0, "Delayed tracing setup, syntax: @now, @<ISO time>, +<dur>, /<dur> (align to next period). Default: at startup" },
	{ "activate", OPT_ACTIVATE, "WHEN", 0, "Delayed data capture activation; same syntax as --prepare. Default: immediately after prepare" },
	{ "timer-freq", OPT_TIMER_FREQ, "HZ", 0, "On-CPU timer interrupt frequency (default: 100Hz, i.e., every 10ms)" },

	{ "data", 'D', "FILE", 0, "Data dump path (defaults to 'wprof.data' in current directory)" },
	{ "trace", 'T', "FILE", 0, "Emit Perfetto trace to specified file (use '-' for stdout)" },
	{ "json-trace", 'J', "FILE", 0, "Emit JSON trace for programmatic analysis (use '-' for stdout; see --json-schema)" },
	{ "json-schema", OPT_JSON_SCHEMA, NULL, 0, "Print JSON output data model/schema and exit" },

	{ "record", OPT_RECORD, NULL, 0, "Record mode (default, mutually exclusive with --replay)" },
	{ "seal-output", OPT_SEAL_OUTPUT, NULL, OPTION_HIDDEN, "Prevent subsequent file-output options" },

	{ "replay", 'R', NULL, 0, "Replay mode" },
	{ "replay-start", OPT_REPLAY_OFFSET_START, "TIME_OFFSET", 0, "Session start time offset (replay mode only). Supported syntax: 2s, 1.03s, 10.5ms, 12us, 101213ns" },
	{ "replay-end", OPT_REPLAY_OFFSET_END, "TIME_OFFSET", 0, "Session end time offset (replay mode only). Supported syntax: 2s, 1.03s, 10.5ms, 12us, 101213ns" },
	{ "replay-info", 'I', NULL, 0, "Print recorded data information" },

	{ "stacks", 'S', "KIND", OPTION_ARG_OPTIONAL,
	  "Capture stack traces. Kinds: timer, offcpu, waker, cuda, req, utrace, pmu=<event>[@<rate>], or all (default = timer + offcpu). Repeatable." },
	{ "no-stacks", OPT_NO_STACK_TRACES, "KIND", OPTION_ARG_OPTIONAL, "Don't capture or emit stack traces" },
	{ "symbolize-frugal", OPT_SYMBOLIZE_FRUGALLY, NULL, 0, "Symbolize frugally (slower, but less memory hungry)" },

	/* allow/deny filters */
	{ "pid", 'p', "PID", 0, "PID allow filter (numeric PID or nv-smi)" },
	{ "no-pid", 'P', "PID", 0, "PID deny filter (numeric PID or nv-smi)" },
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
	{ "feature", 'f', "FEAT", 0,
	  "Data capture feature selector. Supported: ipi, req[=PATH|PID], scx, cuda[=nv-smi|all|PID], "
	  "py-stacks[=nv-smi|PID], py-trace[=nv-smi|PID], py-torch[=nv-smi|PID], "
	  "softirq, hardirq, irq, wq, sched (on by default), wakeup (on by default), task-life (on by default). "
	  "All features can be prefixed with 'no-' to disable them explicitly." },

	/* trace emitting options */
	{ "emit-feature", 'e', "FEAT", 0,
	  "Trace visualization feature, any can be negated with a 'no-' prefix. Supported: sched, sched-extras, "
	  "numa, tidpid, timer-ticks, py-stacks-only, req-split (on by default), req-embed, embed-stacks" },

	/* tuning */
	{ "ringbuf-size", OPT_RINGBUF_SZ, "SIZE", 0, "BPF ringbuf size; accepts units b/kb/mb/gb, bare number is KB" },
	{ "task-state-size", OPT_TASK_STATE_SZ, "SIZE", 0, "BPF task state map size (in threads)" },
	{ "ringbuf-cnt", OPT_RINGBUF_CNT, "N", 0, "Number of BPF ringbufs to use" },

	/* user-defined tracing */
	{ "utrace", 'U', "DEFINITION", 0,
	  "User-defined trace probe definition (use @<file> to read from file). Repeatable." },

	/* user-provided metadata */
	{ "metadata", 'M', "KEY=VALUE", 0,
	  "Attach custom metadata to the recording. Repeatable." },

	/* PMUs */
	{ "pmu", OPT_PMU_COUNTER, "EVENT", 0,
	  "Capture pmu counter. Formats: "
	  "hardware (cpu-cycles, instructions, ...), software (page-faults, context-switches, ...), "
	  "raw (r003c), PMU (cpu/event=0x3c/ or cpu/cpu-cycles/), cache (l1-icache-loads), "
	  "derived (derived:ipc=cpu_instructions/cpu_cpu-cycles)" },
	{ "no-pmu", OPT_NO_PMU, NULL, 0, "Don't capture or emit PMUs" },

	/* request listing */
	{ "req-list", OPT_REQ_LIST, NULL, 0, "List all completed requests" },
	{ "req-sort", OPT_REQ_SORT, "FIELD", 0, "Sort request list by given field. Repeatable." },
	{ "req-sort-asc", OPT_REQ_SORT_ASC, "FIELD", 0, "Sort request list by field, ascending. Repeatable." },
	{ "req-sort-desc", OPT_REQ_SORT_DESC, "FIELD", 0, "Sort request list by field, descending. Repeatable." },
	{ "req-filter", OPT_REQ_FILTER, "EXPR", 0, "Filter requests: <field><op><value> (e.g., latency>1ms, pid=1234, name=foo). Repeatable." },
	{ "req-top-n", OPT_REQ_TOP_N, "N", 0, "Show only the first N requests" },
	{ "req-bottom-n", OPT_REQ_BOTTOM_N, "N", 0, "Show only the last N requests" },
	{},
};

static enum stack_trace_kind parse_stack_kinds(const char *arg)
{
	if (!arg)
		return ST_DEFAULT;

	if (strcasecmp(arg, "timer") == 0)
		return ST_TIMER;
	if (strcasecmp(arg, "offcpu") == 0)
		return ST_OFFCPU;
	if (strcasecmp(arg, "waker") == 0)
		return ST_WAKER;
	if (strcasecmp(arg, "cuda") == 0)
		return ST_CUDA;
	if (strcasecmp(arg, "req") == 0)
		return ST_REQ;
	if (strcasecmp(arg, "utrace") == 0)
		return ST_UTRACE;
	if (strcasecmp(arg, "pmu") == 0)
		return ST_PMU;

	if (strcasecmp(arg, "all") == 0)
		return ST_ALL;

	eprintf("Unrecognized stack trace kind: '%s'\n", arg);
	return ST_ERR;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	int err = 0;

	switch (key) {
	case 'v':
		if (env.verbose) {
			env.debug_level++;
			env_debug_level++;
		}
		env.verbose = true;
		env_verbose = true;
		break;
	case OPT_STATS:
		env.emit_stats = true;
		break;
	case OPT_DEBUG:
		if (strcasecmp(arg, "pb-debug-interns") == 0) {
			env.pb_debug_interns = true;
		} else if (strcasecmp(arg, "pb-disable-interns") == 0) {
			env.pb_disable_interns = true;
		} else if (strcasecmp(arg, "keep-workdir") == 0) {
			env.keep_workdir = true;
		} else if (strcasecmp(arg, "raw-stacks") == 0) {
			env.raw_stacks = true;
		} else if (strcasecmp(arg, "no-tsidx") == 0) {
			env.no_tsidx = true;
		} else if (strcasecmp(arg, "no-task-storage") == 0) {
			env.no_task_storage = true;
		} else if (strncasecmp(arg, "fr-chunk-size=", 14) == 0) {
			const char *val = arg + 14;

			if (parse_size(val, SZ_NONE, &env.fr_chunk_size)) {
				eprintf("Invalid fr-chunk-size '%s' (unit required)!\n", val);
				argp_usage(state);
			}
		} else {
			eprintf("Unrecognized debug feature '%s'!\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_LOG:
		if (strcasecmp(arg, "libbpf") == 0) {
			env.log_set |= LOG_LIBBPF;
		} else if (strcasecmp(arg, "usdt") == 0) {
			env.log_set |= LOG_USDT;
		} else if (strcasecmp(arg, "topology") == 0) {
			env.log_set |= LOG_TOPOLOGY;
		} else if (strcasecmp(arg, "inject") == 0) {
			env.log_set |= LOG_INJECTION;
		} else if (strcasecmp(arg, "tracee") == 0) {
			env.log_set |= LOG_TRACEE;
		} else if (strcasecmp(arg, "discovery") == 0) {
			env.log_set |= LOG_DISCOVERY;
		} else {
			eprintf("Unrecognized log subset '%s'!\n", arg);
			argp_usage(state);
		}
		env_log_set = env.log_set;
		break;
	case OPT_SYMBOLIZE_FRUGALLY:
		env.symbolize_frugally = true;
		break;
	case 'd': {
		s64 dur = parse_time_units(arg); /* bare number = ms */
		if (dur <= 0) {
			fprintf(stderr, "Invalid running duration: %s\n", arg);
			argp_usage(state);
		}
		env.duration_ns = dur;
		break;
	}
	case 'F': {
		char *copy, *saveptr, *tok;

		env.flightrec = true;
		/*
		 * Both limits are independent and both apply; each dimension may
		 * be set at most once across all -F flags (a repeat is an error)
		 * and stays -1 until set. A 0 token disables that dimension.
		 * Unset (-1) dimensions are resolved to defaults in main().
		 */

		/* accept the -F=SPEC form (argp keeps the '=' for short optional args) */
		if (arg && arg[0] == '=')
			arg++;

		if (!arg || !arg[0])
			break;

		copy = strdup(arg);
		for (tok = strtok_r(copy, ",", &saveptr); tok; tok = strtok_r(NULL, ",", &saveptr)) {
			char last = tok[strlen(tok) - 1];

			if (last == 'b' || last == 'B') {
				u64 sz;

				/* size token always carries a unit; 0 means no size cap */
				if (env.fr_keep_size >= 0) {
					eprintf("Flight-record size limit specified more than once!\n");
					argp_usage(state);
				}
				if (parse_size(tok, SZ_NONE, &sz)) {
					eprintf("Invalid flight-record size limit '%s'\n", tok);
					argp_usage(state);
				}
				env.fr_keep_size = sz;
			} else {
				/* time token; 0/0s is valid and means no time limit */
				if (env.fr_keep_time_ns >= 0) {
					eprintf("Flight-record time limit specified more than once!\n");
					argp_usage(state);
				}
				s64 t = parse_time_units(tok);

				if (t < 0) {
					eprintf("Invalid flight-record time limit '%s'\n", tok);
					argp_usage(state);
				}
				env.fr_keep_time_ns = t;
			}
		}
		free(copy);
		break;
	}
	case OPT_PREPARE:
		if (parse_timespec(arg, &env.prepare_spec)) {
			fprintf(stderr, "Invalid --prepare time spec: %s\n", arg);
			argp_usage(state);
		}
		env.prepare_spec_str = strdup(arg);
		break;
	case OPT_ACTIVATE:
		if (parse_timespec(arg, &env.activate_spec)) {
			fprintf(stderr, "Invalid --activate time spec: %s\n", arg);
			argp_usage(state);
		}
		env.activate_spec_str = strdup(arg);
		break;
	case 'D':
		if (env.output_sealed) {
			fprintf(stderr, "Output file options are disabled by --seal-output\n");
			return -EINVAL;
		}
		env.data_path = strdup(arg);
		break;
	case 'R':
		if (env.record) {
			fprintf(stderr, "Only one of --record or --replay modes should be enabled\n");
			return -EINVAL;
		}
		env.replay = true;
		break;
	case 'I':
		env.replay_info = true;
		break;
	case OPT_REPLAY_OFFSET_START:
		env.replay_start_offset_ns = parse_time_units(arg);
		if (env.replay_start_offset_ns < 0) {
			eprintf("Failed to parse replay start time offset '%s'\n", arg);
			return -EINVAL;
		}
		break;
	case OPT_REPLAY_OFFSET_END:
		env.replay_end_offset_ns = parse_time_units(arg);
		if (env.replay_end_offset_ns < 0) {
			eprintf("Failed to parse replay end time offset '%s'\n", arg);
			return -EINVAL;
		}
		break;
	case 'T':
		if (env.output_sealed) {
			fprintf(stderr, "Output file options are disabled by --seal-output\n");
			return -EINVAL;
		}
		if (env.trace_path || env.json_path) {
			fprintf(stderr, "Only one trace output can be specified (-T and -J are mutually exclusive)!\n");
			return -EINVAL;
		}
		env.trace_path = strdup(arg);
		break;
	case 'J':
		if (env.output_sealed) {
			fprintf(stderr, "Output file options are disabled by --seal-output\n");
			return -EINVAL;
		}
		if (env.trace_path || env.json_path) {
			fprintf(stderr, "Only one trace output can be specified (-T and -J are mutually exclusive)!\n");
			return -EINVAL;
		}
		env.json_path = strdup(arg);
		break;
	case OPT_JSON_SCHEMA: {
		extern const char json_schema_start[];
		extern const char json_schema_end[];
		fwrite(json_schema_start, 1, json_schema_end - json_schema_start, stdout);
		exit(0);
	}
	case 'S': {
		enum stack_trace_kind kinds;

		if (arg && strncasecmp(arg, "pmu=", 4) == 0) {
			struct pmu_event ev;

			err = parse_pmu_event_spec(arg + 4, &ev);
			if (err) {
				eprintf("Invalid PMU sampling spec: %s\n", arg + 4);
				argp_usage(state);
			}

			if (env.pmu_event_cnt < 0)
				env.pmu_event_cnt = 0;

			env.pmu_events = realloc(env.pmu_events, (env.pmu_event_cnt + 1) * sizeof(*env.pmu_events));
			env.pmu_events[env.pmu_event_cnt++] = ev;
			kinds = ST_PMU;
		} else if (arg && strcasecmp(arg, "pmu") == 0) {
			eprintf("PMU sampling requires an event: use -Spmu=<event>[@<rate>]\n");
			return -EINVAL;
		} else {
			kinds = parse_stack_kinds(arg);
			if (kinds < 0)
				return -EINVAL;
		}

		if (env.requested_stack_traces == ST_UNSET)
			env.requested_stack_traces = 0;

		env.requested_stack_traces |= kinds;
		break;
	}
	case OPT_NO_STACK_TRACES: {
		enum stack_trace_kind kinds;

		kinds = parse_stack_kinds(arg);
		if (kinds < 0)
			return -EINVAL;

		if (env.requested_stack_traces == ST_UNSET)
			env.requested_stack_traces = ST_DEFAULT;

		env.requested_stack_traces &= ~kinds;
		break;
	}
	/* FEATURES SELECTION */
	case 'f': {
		enum tristate val = TRUE;
		/*
		 * 'no-' prefix explicitly disables feature (e.g., if it is
		 * inherited and enbaled due to replayed data dump)
		 */
		if (strncasecmp(arg, "no-", 3) == 0) {
			val = FALSE;
			arg += 3;
		}

		if (strcasecmp(arg, "ipi") == 0) {
			env.capture_ipis = val;
		} else if (strcasecmp(arg, "req") == 0) {
			env.req_global_discovery = val == TRUE;
			env.capture_requests = val;
		} else if (strncasecmp(arg, "req=", 4) == 0) {
			const char *req_arg = arg + 4;
			int pid, n;

			if (val == FALSE) {
				eprintf("-f no-req=... feature form doesn't make much sense!\n");
				return -EINVAL;
			}

			if (sscanf(req_arg, "%d %n", &pid, &n) == 1 && req_arg[n] == '\0') {
				err = append_num(&env.req_pids, &env.req_pid_cnt, req_arg);
				if (err) {
					eprintf("Failed to record PID '%s' for request tracking!\n", req_arg);
					return err;
				}
			} else {
				err = append_str(&env.req_paths, &env.req_path_cnt, req_arg);
				if (err) {
					eprintf("Use -freq=<path-to-binary> or -freq=<PID> to enable request tracking!\n");
					return err;
				}
			}
			env.capture_requests = val;
		} else if (strcasecmp(arg, "scx") == 0) {
			env.capture_scx = val;
			// TODO(patlu): unified cuda/py-stacks/py-trace
		} else if (strcasecmp(arg, "cuda") == 0) {
			env.cuda_discovery = (val == TRUE) ? CUDA_DISCOVER_SMI : CUDA_DISCOVER_NONE;
			env.capture_cuda = val;
		} else if (strcasecmp(arg, "cuda=nv-smi") == 0 || strcasecmp(arg, "cuda=nvidia-smi") == 0) {
			env.cuda_discovery = (val == TRUE) ? CUDA_DISCOVER_SMI : CUDA_DISCOVER_NONE;
			env.capture_cuda = val;
		} else if (strcasecmp(arg, "cuda=all") == 0) {
			env.cuda_discovery = (val == TRUE) ? CUDA_DISCOVER_PROC : CUDA_DISCOVER_NONE;
			env.capture_cuda = val;
		} else if (strncasecmp(arg, "cuda=", 5) == 0) {
			const char *cuda_arg = arg + 5;
			int pid, n;

			if (val == FALSE) {
				eprintf("-f no-cuda=... feature form doesn't make much sense!\n");
				return -EINVAL;
			}

			if (sscanf(cuda_arg, "%d %n", &pid, &n) == 1 && cuda_arg[n] == '\0') {
				err = append_num(&env.cuda_pids, &env.cuda_pid_cnt, cuda_arg);
				if (err) {
					eprintf("Failed to record PID '%s' for CUDA tracking!\n", cuda_arg);
					return err;
				}
			} else {
				eprintf("Use -fcuda, -fcuda=all, or -fcuda=<PID> to enable CUDA tracking!\n");
				return -EINVAL;
			}
			env.capture_cuda = val;
		} else if (strcasecmp(arg, "py-stacks") == 0) {
			env.pystacks_discovery = (val == TRUE) ? PYSTACKS_DISCOVER_PROC : PYSTACKS_DISCOVER_NONE;
			env.capture_pystacks = val;
		} else if (strcasecmp(arg, "py-stacks=nvidia-smi") == 0 || strcasecmp(arg, "py-stacks=nv-smi") == 0) {
			env.pystacks_discovery = (val == TRUE) ? PYSTACKS_DISCOVER_NV_SMI : PYSTACKS_DISCOVER_NONE;
			env.capture_pystacks = val;
		} else if (strncasecmp(arg, "py-stacks=", 10) == 0) {
			const char *py_arg = arg + 10;
			int pid, n;

			if (val == FALSE) {
				eprintf("-f no-py-stacks=... feature form doesn't make much sense!\n");
				return -EINVAL;
			}

			if (sscanf(py_arg, "%d %n", &pid, &n) == 1 && py_arg[n] == '\0') {
				err = append_num(&env.pystacks_pids, &env.pystacks_pid_cnt, py_arg);
				if (err) {
					eprintf("Failed to record PID '%s' for Python stack tracking!\n", py_arg);
					return err;
				}
			} else {
				eprintf("Use -fpy-stacks, -fpy-stacks=nv-smi, or -fpy-stacks=<PID>!\n");
				return -EINVAL;
			}
			env.capture_pystacks = val;
		} else if (strcasecmp(arg, "py-trace") == 0) {
			env.pytrace_discovery = (val == TRUE) ? PYTRACE_DISCOVER_PROC : PYTRACE_DISCOVER_NONE;
			env.capture_pytrace = val;
		} else if (strcasecmp(arg, "py-trace=nvidia-smi") == 0 || strcasecmp(arg, "py-trace=nv-smi") == 0) {
			if (val == FALSE) {
				eprintf("-f no-py-trace=... feature form doesn't make much sense!\n");
				return -EINVAL;
			}
			env.pytrace_discovery = PYTRACE_DISCOVER_NV_SMI;
			env.capture_pytrace = val;
		} else if (strncasecmp(arg, "py-trace=", 9) == 0) {
			const char *pf_arg = arg + 9;
			int pid, n;

			if (val == FALSE) {
				eprintf("-f no-py-trace=... feature form doesn't make much sense!\n");
				return -EINVAL;
			}

			if (sscanf(pf_arg, "%d %n", &pid, &n) == 1 && pf_arg[n] == '\0') {
				err = append_num(&env.pytrace_pids, &env.pytrace_pid_cnt, pf_arg);
				if (err) {
					eprintf("Failed to record PID '%s' for Python function tracing!\n", pf_arg);
					return err;
				}
			} else {
				eprintf("Use -fpy-trace, -fpy-trace=nv-smi, or -fpy-trace=<PID>!\n");
				return -EINVAL;
			}
			env.capture_pytrace = val;
		} else if (strcasecmp(arg, "py-torch") == 0) {
			env.pytorch_discovery = (val == TRUE) ? PYTRACE_DISCOVER_PROC : PYTRACE_DISCOVER_NONE;
			env.capture_pytorch = val;
		} else if (strcasecmp(arg, "py-torch=nvidia-smi") == 0 || strcasecmp(arg, "py-torch=nv-smi") == 0) {
			if (val == FALSE) {
				eprintf("-f no-py-torch=... feature form doesn't make much sense!\n");
				return -EINVAL;
			}
			env.pytorch_discovery = PYTRACE_DISCOVER_NV_SMI;
			env.capture_pytorch = val;
		} else if (strncasecmp(arg, "py-torch=", 9) == 0) {
			const char *pf_arg = arg + 9;
			int pid, n;

			if (val == FALSE) {
				eprintf("-f no-py-torch=... feature form doesn't make much sense!\n");
				return -EINVAL;
			}

			if (sscanf(pf_arg, "%d %n", &pid, &n) == 1 && pf_arg[n] == '\0') {
				err = append_num(&env.pytorch_pids, &env.pytorch_pid_cnt, pf_arg);
				if (err) {
					eprintf("Failed to record PID '%s' for PyTorch tracing!\n", pf_arg);
					return err;
				}
			} else {
				eprintf("Use -fpy-torch, -fpy-torch=nv-smi, or -fpy-torch=<PID>!\n");
				return -EINVAL;
			}
			env.capture_pytorch = val;
		} else if (strcasecmp(arg, "softirq") == 0) {
			env.capture_softirq = val;
		} else if (strcasecmp(arg, "hardirq") == 0) {
			env.capture_hardirq = val;
		} else if (strcasecmp(arg, "irq") == 0) {
			env.capture_softirq = val;
			env.capture_hardirq = val;
		} else if (strcasecmp(arg, "sched") == 0) {
			env.capture_sched = val;
		} else if (strcasecmp(arg, "wakeup") == 0) {
			env.capture_wakeup = val;
		} else if (strcasecmp(arg, "task-life") == 0) {
			env.capture_task_life = val;
		} else if (strcasecmp(arg, "wq") == 0) {
			env.capture_wq = val;
		} else {
			fprintf(stderr, "Unrecognized data feature '%s!\n", arg);
			return -EINVAL;
		}
		break;
	}
	case 'e': {
		/* any emit feature can be negated with a "no-" prefix */
		enum tristate val = TRUE, *flag;

		if (strncasecmp(arg, "no-", 3) == 0) {
			val = FALSE;
			arg += 3;
		}

		if (strcasecmp(arg, "numa") == 0) {
			flag = &env.emit_numa;
		} else if (strcasecmp(arg, "tidpid") == 0) {
			flag = &env.emit_tidpid;
		} else if (strcasecmp(arg, "timer-ticks") == 0) {
			flag = &env.emit_timer_ticks;
		} else if (strcasecmp(arg, "sched") == 0) {
			flag = &env.emit_sched_view;
		} else if (strcasecmp(arg, "sched-extras") == 0) {
			flag = &env.emit_sched_extras;
		} else if (strcasecmp(arg, "py-stacks-only") == 0) {
			flag = &env.emit_pystacks_only;
		} else if (strcasecmp(arg, "req-split") == 0) {
			flag = &env.emit_req_split;
		} else if (strcasecmp(arg, "req-embed") == 0) {
			flag = &env.emit_req_embed;
		} else if (strcasecmp(arg, "embed-stacks") == 0) {
			flag = &env.emit_embed_stacks;
		} else {
			fprintf(stderr, "Unrecognized emit feature '%s'!\n", arg);
			return -EINVAL;
		}

		if (*flag != UNSET && *flag != val) {
			fprintf(stderr, "Conflicting -e %s setting!\n", arg);
			return -EINVAL;
		}
		*flag = val;
		break;
	}
	/* FILTERING */
	case 'p':
		if (strcasecmp(arg, "nv-smi") == 0 || strcasecmp(arg, "nvidia-smi") == 0) {
			env.allow_pids_nv_smi = true;
		} else {
			err = append_num(&env.allow_pids, &env.allow_pid_cnt, arg);
			if (err)
				return err;
		}
		break;
	case 'P':
		if (strcasecmp(arg, "nv-smi") == 0 || strcasecmp(arg, "nvidia-smi") == 0) {
			env.deny_pids_nv_smi = true;
		} else {
			err = append_num(&env.deny_pids, &env.deny_pid_cnt, arg);
			if (err)
				return err;
		}
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
	case OPT_TIMER_FREQ:
		errno = 0;
		env.timer_freq_hz = strtol(arg, NULL, 0);
		if (errno || env.timer_freq_hz <= 0) {
			fprintf(stderr, "Invalid frequency: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_RINGBUF_SZ: {
		u64 sz;

		if (parse_size(arg, SZ_KB, &sz)) {	/* bare number still = KB (back-compat) */
			fprintf(stderr, "Invalid ringbuf size: %s\n", arg);
			argp_usage(state);
		}
		if (sz > INT_MAX) {	/* env.ringbuf_sz / round_pow_of_2() are int */
			fprintf(stderr, "Ringbuf size too large: %s\n", arg);
			argp_usage(state);
		}
		env.ringbuf_sz = round_pow_of_2(sz);
		break;
	}
	case OPT_TASK_STATE_SZ:
		errno = 0;
		env.task_state_sz = strtol(arg, NULL, 0);
		if (errno || env.task_state_sz < 0) {
			fprintf(stderr, "Invalid task state size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_RINGBUF_CNT: {
		errno = 0;
		int ringbuf_cnt = strtol(arg, NULL, 0);
		if (errno || ringbuf_cnt <= 0) {
			fprintf(stderr, "Invalid ringbuf count: %s\n", arg);
			argp_usage(state);
		}
		env.ringbuf_cnt = ringbuf_cnt;
		break;
	}
	case OPT_NO_PMU:
		env.pmu_real_cnt = 0;
		env.pmu_deriv_cnt = 0;
		env.pmu_unresolved_cnt = 0;
		break;
	case OPT_PMU_COUNTER: {
		struct pmu_event ev;
		int err;

		err = parse_perf_counter(arg, &ev);
		if (err) {
			/* For replay mode, allow specifying just the stored event name.
			 * Create a placeholder event with just the name - it will be
			 * resolved against stored events during replay initialization.
			 */
			memset(&ev, 0, sizeof(ev));
			ev.perf_type = PERF_TYPE_UNRESOLVED;
			ev.def_idx = -1;
			ev.name = strdup(arg);
		}

		/* First counter specified resets all arrays from sentinel */
		if (env.pmu_real_cnt < 0)
			env.pmu_real_cnt = 0;
		if (env.pmu_deriv_cnt < 0)
			env.pmu_deriv_cnt = 0;
		if (env.pmu_unresolved_cnt < 0)
			env.pmu_unresolved_cnt = 0;

		/* Check for duplicates (by name) across all arrays */
		for (int i = 0; i < env.pmu_real_cnt; i++) {
			if (strcmp(env.pmu_reals[i].name, ev.name) == 0) {
				eprintf("Duplicate counter '%s' specified\n", ev.name);
				argp_usage(state);
			}
		}
		for (int i = 0; i < env.pmu_deriv_cnt; i++) {
			if (strcmp(env.pmu_derivs[i].name, ev.name) == 0) {
				eprintf("Duplicate counter '%s' specified\n", ev.name);
				argp_usage(state);
			}
		}
		for (int i = 0; i < env.pmu_unresolved_cnt; i++) {
			if (strcmp(env.pmu_unresolveds[i].name, ev.name) == 0) {
				eprintf("Duplicate counter '%s' specified\n", ev.name);
				argp_usage(state);
			}
		}

		ev.spec = strdup(arg);

		if (ev.perf_type == PERF_TYPE_UNRESOLVED) {
			env.pmu_unresolveds = realloc(env.pmu_unresolveds, (env.pmu_unresolved_cnt + 1) * sizeof(*env.pmu_unresolveds));
			env.pmu_unresolveds[env.pmu_unresolved_cnt++] = ev;
		} else if (ev.perf_type == PERF_TYPE_DERIVED) {
			ev.def_idx = -1;
			env.pmu_derivs = realloc(env.pmu_derivs, (env.pmu_deriv_cnt + 1) * sizeof(*env.pmu_derivs));
			env.pmu_derivs[env.pmu_deriv_cnt++] = ev;
		} else {
			if (env.pmu_real_cnt >= MAX_REAL_PMU_COUNTERS) {
				eprintf("Too many real PMU counters requested, only %d are supported!\n", MAX_REAL_PMU_COUNTERS);
				return -E2BIG;
			}
			ev.def_idx = env.pmu_real_cnt;
			env.pmu_reals = realloc(env.pmu_reals, (env.pmu_real_cnt + 1) * sizeof(*env.pmu_reals));
			env.pmu_reals[env.pmu_real_cnt++] = ev;
		}
		break;
	}
	/* USER-DEFINED TRACING */
	case 'U': {
		if (arg[0] == '@')
			err = utrace_cfg_parse_file(arg + 1);
		else
			err = utrace_cfg_parse(arg);
		if (err)
			return err;
		break;
	}
	/* METADATA */
	case 'M': {
		struct sview key_sv, val_sv;

		key_sv = sv_trim(sv_split(sv_new(arg), "=", &val_sv));
		val_sv = sv_trim(sv_consume_left(val_sv, 1));

		if (sv_is_empty(key_sv)) {
			eprintf("Metadata must be in KEY=VALUE format: '%s'\n", arg);
			return -EINVAL;
		}

		const char *kv = sfmt("%.*s=%.*s", key_sv.len, key_sv.s, val_sv.len, val_sv.s);
		env.metadata = realloc(env.metadata, (env.metadata_cnt + 1) * sizeof(*env.metadata));
		env.metadata[env.metadata_cnt++] = strdup(kv);
		break;
	}
	/* REQUESTS QUERYING */
	case OPT_REQ_LIST:
		env.req_list_cfg = env.req_list_cfg ?: calloc(1, sizeof(*env.req_list_cfg));
		env.req_list = true;
		break;
	case OPT_REQ_SORT:
		env.req_list_cfg = env.req_list_cfg ?: calloc(1, sizeof(*env.req_list_cfg));
		err = req_list_parse_sort(arg, REQ_ORDER_DEFAULT);
		if (err)
			return err;
		break;
	case OPT_REQ_SORT_ASC:
		env.req_list_cfg = env.req_list_cfg ?: calloc(1, sizeof(*env.req_list_cfg));
		err = req_list_parse_sort(arg, REQ_ORDER_ASC);
		if (err)
			return err;
		break;
	case OPT_REQ_SORT_DESC:
		env.req_list_cfg = env.req_list_cfg ?: calloc(1, sizeof(*env.req_list_cfg));
		err = req_list_parse_sort(arg, REQ_ORDER_DESC);
		if (err)
			return err;
		break;
	case OPT_REQ_FILTER:
		env.req_list_cfg = env.req_list_cfg ?: calloc(1, sizeof(*env.req_list_cfg));
		err = req_list_parse_filter(arg);
		if (err)
			return err;
		break;
	case OPT_REQ_TOP_N: {
		char *end;
		env.req_list_cfg = env.req_list_cfg ?: calloc(1, sizeof(*env.req_list_cfg));
		errno = 0;
		env.req_list_cfg->top_n = strtol(arg, &end, 0);
		if (errno || *end || env.req_list_cfg->top_n <= 0) {
			eprintf("Invalid --req-top-n value: '%s'\n", arg);
			return -EINVAL;
		}
		break;
	}
	case OPT_REQ_BOTTOM_N: {
		char *end;
		env.req_list_cfg = env.req_list_cfg ?: calloc(1, sizeof(*env.req_list_cfg));
		errno = 0;
		env.req_list_cfg->bottom_n = strtol(arg, &end, 0);
		if (errno || *end || env.req_list_cfg->bottom_n <= 0) {
			eprintf("Invalid --req-bottom-n value: '%s'\n", arg);
			return -EINVAL;
		}
		break;
	}
	case OPT_RECORD:
		if (env.replay) {
			fprintf(stderr, "Only one of --record or --replay modes should be enabled\n");
			return -EINVAL;
		}
		env.record = true;
		break;
	case OPT_SEAL_OUTPUT:
		env.output_sealed = true;
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
