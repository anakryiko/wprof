// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <argp.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <time.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <pthread.h>
#include <limits.h>
#include <linux/fs.h>
#include <sched.h>

#include "utils.h"
#include "wprof.h"
#include "data.h"
#include "wprof.skel.h"

#include "env.h"
#include "protobuf.h"
#include "emit.h"
#include "stacktrace.h"
#include "topology.h"
#include "proc.h"
#include "requests.h"
#include "cuda.h"
#include "cuda_data.h"
#include "pytrace.h"
#include "pytrace_data.h"
#include "bpf_utils.h"
#include "elf_utils.h"
#include "sys.h"
#include "inject.h"
#include "inj_common.h"
#include "merge.h"
#include "../libbpf/src/strset.h"
#include "pystacks.h"
#include "pysym.h"
#include "utrace.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !(env.log_set & LOG_LIBBPF))
		return 0;
	return vfprintf(stderr, format, args);
}

const struct capture_feature capture_features[] = {
	{"IPIs", "IPIs:", "capture_ipis", DEFAULT_CAPTURE_IPIS,
	 offsetof(struct env, capture_ipis), CFG_CAPTURE_IPIS},
	{"requests", "Requests:", "capture_requests", DEFAULT_CAPTURE_REQUESTS,
	 offsetof(struct env, capture_requests), CFG_CAPTURE_REQUESTS},
	{"sched-ext info", "SCX info:", "capture_scx", DEFAULT_CAPTURE_SCX,
	 offsetof(struct env, capture_scx), CFG_CAPTURE_SCX},
	{"CUDA", "CUDA:", "capture_cuda", DEFAULT_CAPTURE_CUDA,
	 offsetof(struct env, capture_cuda), CFG_CAPTURE_CUDA},
	{"Python stacks", "PyStacks:", "capture_pystacks", DEFAULT_CAPTURE_PYSTACKS,
	 offsetof(struct env, capture_pystacks), CFG_CAPTURE_PYSTACKS},
	{"Python function tracing", "PyTrace:", "capture_pytrace", DEFAULT_CAPTURE_PYTRACE,
	 offsetof(struct env, capture_pytrace), CFG_CAPTURE_PYTRACE},
	{"PyTorch RecordFunction", "PyTorch:", "capture_pytorch", DEFAULT_CAPTURE_TORCH_PROFILER,
	 offsetof(struct env, capture_pytorch), CFG_CAPTURE_PYTORCH},
	{"user-defined tracing", "Utrace:", "capture_utrace", DEFAULT_CAPTURE_UTRACE,
	 offsetof(struct env, capture_utrace), CFG_CAPTURE_UTRACE},
	{"softirqs", "Softirqs:", "capture_softirq", DEFAULT_CAPTURE_SOFTIRQ,
	 offsetof(struct env, capture_softirq), CFG_CAPTURE_SOFTIRQ},
	{"hardirqs", "Hardirqs:", "capture_hardirq", DEFAULT_CAPTURE_HARDIRQ,
	 offsetof(struct env, capture_hardirq), CFG_CAPTURE_HARDIRQ},
};

const int capture_feature_cnt = ARRAY_SIZE(capture_features);

const struct emit_feature emit_features[] = {
	{WEXTRA_EMIT_NUMA, offsetof(struct env, emit_numa), DEFAULT_EMIT_NUMA},
	{WEXTRA_EMIT_TIDPID, offsetof(struct env, emit_tidpid), DEFAULT_EMIT_TIDPID},
	{WEXTRA_EMIT_TIMER_TICKS, offsetof(struct env, emit_timer_ticks), DEFAULT_EMIT_TIMER_TICKS},
	{WEXTRA_EMIT_SCHED, offsetof(struct env, emit_sched_view), DEFAULT_EMIT_SCHED},
	{WEXTRA_EMIT_SCHED_EXTRAS, offsetof(struct env, emit_sched_extras), DEFAULT_EMIT_SCHED_EXTRAS},
	{WEXTRA_EMIT_PYSTACKS_ONLY, offsetof(struct env, emit_pystacks_only), DEFAULT_EMIT_PYSTACKS_ONLY},
	{WEXTRA_EMIT_REQ_SPLIT, offsetof(struct env, emit_req_split), DEFAULT_EMIT_REQ_SPLIT},
	{WEXTRA_EMIT_REQ_EMBED, offsetof(struct env, emit_req_embed), DEFAULT_EMIT_REQ_EMBED},
	{WEXTRA_EMIT_EMBED_STACKS, offsetof(struct env, emit_embed_stacks), DEFAULT_EMIT_EMBED_STACKS},
};

const int emit_feature_cnt = ARRAY_SIZE(emit_features);

/*
 * Render an extra param as the CLI option that produced it. -e options carry
 * their on/off value in the union; everything else carries an optional string
 * argument in stroff.
 */
const char *extra_param_str(struct wprof_data_hdr *hdr, const struct wprof_extra_param *e)
{
	switch (e->kind) {
	case WEXTRA_FILTER_PID_ALLOW:		return sfmt("--pid %s", wevent_str(hdr, e->stroff));
	case WEXTRA_FILTER_PID_DENY:		return sfmt("--no-pid %s", wevent_str(hdr, e->stroff));
	case WEXTRA_FILTER_TID_ALLOW:		return sfmt("--tid %s", wevent_str(hdr, e->stroff));
	case WEXTRA_FILTER_TID_DENY:		return sfmt("--no-tid %s", wevent_str(hdr, e->stroff));
	case WEXTRA_FILTER_PNAME_ALLOW:		return sfmt("--process-name %s", wevent_str(hdr, e->stroff));
	case WEXTRA_FILTER_PNAME_DENY:		return sfmt("--no-process-name %s", wevent_str(hdr, e->stroff));
	case WEXTRA_FILTER_TNAME_ALLOW:		return sfmt("--thread-name %s", wevent_str(hdr, e->stroff));
	case WEXTRA_FILTER_TNAME_DENY:		return sfmt("--no-thread-name %s", wevent_str(hdr, e->stroff));
	case WEXTRA_FILTER_IDLE_ALLOW:		return "--idle";
	case WEXTRA_FILTER_IDLE_DENY:		return "--no-idle";
	case WEXTRA_FILTER_KTHREAD_ALLOW:	return "--kthread";
	case WEXTRA_FILTER_KTHREAD_DENY:	return "--no-kthread";
	case WEXTRA_UTRACE_DEF:			return sfmt("--utrace %s", wevent_str(hdr, e->stroff));
	case WEXTRA_METADATA:			return sfmt("--metadata %s", wevent_str(hdr, e->stroff));
	case WEXTRA_STATS:			return "--stats";
	case WEXTRA_PMU:			return sfmt("--pmu %s", wevent_str(hdr, e->stroff));
	case WEXTRA_EMIT_NUMA:			return e->value ? "-e numa" : "-e no-numa";
	case WEXTRA_EMIT_TIDPID:		return e->value ? "-e tidpid" : "-e no-tidpid";
	case WEXTRA_EMIT_TIMER_TICKS:		return e->value ? "-e timer-ticks" : "-e no-timer-ticks";
	case WEXTRA_EMIT_SCHED:			return e->value ? "-e sched" : "-e no-sched";
	case WEXTRA_EMIT_SCHED_EXTRAS:		return e->value ? "-e sched-extras" : "-e no-sched-extras";
	case WEXTRA_EMIT_PYSTACKS_ONLY:		return e->value ? "-e py-stacks-only" : "-e no-py-stacks-only";
	case WEXTRA_EMIT_REQ_SPLIT:		return e->value ? "-e req-split" : "-e no-req-split";
	case WEXTRA_EMIT_REQ_EMBED:		return e->value ? "-e req-embed" : "-e no-req-embed";
	case WEXTRA_EMIT_EMBED_STACKS:		return e->value ? "-e embed-stacks" : "-e no-embed-stacks";
	case WEXTRA_PREPARE_SPEC:		return sfmt("--prepare %s", wevent_str(hdr, e->stroff));
	case WEXTRA_ACTIVATE_SPEC:		return sfmt("--activate %s", wevent_str(hdr, e->stroff));
	default:
		BUG("unknown extra param kind %d\n", e->kind);
	}
}

static volatile bool exiting;

static void sig_term(int sig)
{
	exiting = true;
	if (env.sess_ctl.sig_efd >= 0) {
		u64 v = 1;
		(void)write(env.sess_ctl.sig_efd, &v, sizeof(v));
	}
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
}

static void sig_pipe(int sig)
{
	eprintf("!!! Got unexpected SIGPIPE!\n");
}

/* Receive events from the ring buffer. */
static int handle_rb_event(void *ctx, void *data, size_t size)
{
	struct wprof_event *e = data;
	struct worker_state *w = ctx;

	if (exiting)
		return -EINTR;

	if (env.sess_end_ts && (long long)(e->ts - env.sess_end_ts) >= 0) {
		w->rb_ignored_cnt++;
		w->rb_ignored_sz += size;
		return 0;
	}

	if (fwrite(data, size, 1, w->dump) != 1) {
		int err = -errno;

		eprintf("Failed to write raw data dump: %d\n", err);
		return err;
	}

	w->rb_handled_cnt++;
	w->rb_handled_sz += size;

	return 0;
}

static void print_stats(const struct wprof_stats *s, int exit_code)
{
	double dur_s = env.duration_ns / 1000000000.0;
	u64 total_handled_cnt = 0, total_handled_sz = 0;
	u64 total_drops = 0, total_rescues = 0;

	if (!s || !env.emit_stats)
		goto skip_prog_stats;

	wprintf("BPF program stats:\n");

	int num_cpus = s->cpu_cnt;
	for (int i = 0; i < s->prog_cnt; i++) {
		u64 name_off = wstat(s, WSTAT_PROG_NAME, 1 + i);
		u64 run_cnt = wstat(s, WSTAT_PROG_RUN_CNT, 1 + i);
		u64 run_time_ns = wstat(s, WSTAT_PROG_RUN_TIME_NS, 1 + i);
		const char *name = wevent_str(env.data_hdr, name_off);

		wprintf("\t%s%-*s %8llu (%6.0lf/CPU/s) runs for total of %.3lfms (%.3lfms/CPU/s).\n",
			name,
			(int)max(1UL, 24 - strlen(name)), ":",
			run_cnt,
			run_cnt / num_cpus / dur_s,
			run_time_ns / 1000000.0,
			run_time_ns / 1000000.0 / num_cpus / dur_s);
	}

	u64 total_run_cnt = wstat(s, WSTAT_PROG_RUN_CNT, 0);
	u64 total_run_ns = wstat(s, WSTAT_PROG_RUN_TIME_NS, 0);
	wprintf("\t%-24s %8llu (%6.0lf/CPU/s) runs for total of %.3lfms (%.3lfms/CPU/s).\n",
		"TOTAL:", total_run_cnt,
		total_run_cnt / num_cpus / dur_s,
		total_run_ns / 1000000.0,
		total_run_ns / 1000000.0 / num_cpus / dur_s);

skip_prog_stats:
	if (!s)
		goto skip_rb_stats;

	total_handled_cnt = wstat(s, WSTAT_RB_HANDLED_CNT, 0);
	total_handled_sz = wstat(s, WSTAT_RB_HANDLED_SZ, 0);
	total_drops = wstat(s, WSTAT_RB_DROPS, 0);
	total_rescues = wstat(s, WSTAT_RB_RESCUES, 0);

	if (!env.emit_stats)
		goto skip_rb_stats;

	wprintf("Data procesing stats:\n");

	for (int i = 0; i < s->rb_cnt; i++) {
		u64 handled_cnt = wstat(s, WSTAT_RB_HANDLED_CNT, 1 + i);
		u64 handled_sz = wstat(s, WSTAT_RB_HANDLED_SZ, 1 + i);
		u64 drops = wstat(s, WSTAT_RB_DROPS, 1 + i);
		u64 rescues = wstat(s, WSTAT_RB_RESCUES, 1 + i);

		char rb_name[32];
		snprintf(rb_name, sizeof(rb_name), "RB #%d:", i);

		wprintf("\t%-8s %8llu (%.3lf%%) records (%.3lfMB, %.3lfMB/s) processed, %llu rescued (%.3lf%%), %llu dropped (%.3lf%%).\n",
			rb_name,
			handled_cnt, handled_cnt * 100.0 / (handled_cnt + drops),
			handled_sz / 1024.0 / 1024.0, handled_sz / 1024.0 / 1024.0 / dur_s,
			rescues, rescues * 100.0 / (handled_cnt + drops),
			drops, drops * 100.0 / (handled_cnt + drops));
	}
	wprintf("\t%-8s %8llu (%.3lf%%) records (%.3lfMB, %.3lfMB/s, %.3lfMB/RB/s) processed, %llu rescued (%.3lf%%), %llu dropped (%.3lf%%).\n",
		"TOTAL:",
		total_handled_cnt, total_handled_cnt * 100.0 / (total_handled_cnt + total_drops),
		total_handled_sz / 1024.0 / 1024.0, total_handled_sz / 1024.0 / 1024.0 / dur_s,
		total_handled_sz / 1024.0 / 1024.0 / dur_s / s->rb_cnt,
		total_rescues, total_rescues * 100.0 / (total_handled_cnt + total_drops),
		total_drops, total_drops * 100.0 / (total_handled_cnt + total_drops));

skip_rb_stats:
	if (!s || !env.emit_stats)
		goto skip_rusage;

	wprintf("Resource usage:\n");
	wprintf("\tCPU time (user/system, s):\t\t%.3lf/%.3lf\n",     wstat(s, WSTAT_RUSAGE_UTIME_US, 0) / 1000000.0,
								     wstat(s, WSTAT_RUSAGE_STIME_US, 0) / 1000000.0);
	wprintf("\tMemory (max RSS, MB):\t\t\t%.3lf\n",		     wstat(s, WSTAT_RUSAGE_MAXRSS_KB, 0) / 1024.0);
	wprintf("\tPage faults (maj/min, K)\t\t%.3lf/%.3lf\n",	     wstat(s, WSTAT_RUSAGE_MAJFLT, 0) / 1000.0,
								     wstat(s, WSTAT_RUSAGE_MINFLT, 0) / 1000.0);
	wprintf("\tBlock I/Os (K):\t\t\t\t%.3lf/%.3lf\n",	     wstat(s, WSTAT_RUSAGE_INBLOCK, 0) / 1000.0,
								     wstat(s, WSTAT_RUSAGE_OUBLOCK, 0) / 1000.0);
	wprintf("\tContext switches (vol/invol, K):\t%.3lf/%.3lf\n", wstat(s, WSTAT_RUSAGE_NVCSW, 0) / 1000.0,
								     wstat(s, WSTAT_RUSAGE_NIVCSW, 0) / 1000.0);

skip_rusage:
	if (!s)
		goto skip_error_diag;

	for (int i = 0; i < s->cuda_cnt; i++) {
		u64 state = wstat(s, WSTAT_CUDA_STATE, 1 + i);
		const char *name = wevent_str(env.data_hdr, wstat(s, WSTAT_CUDA_NAME, 1 + i));

		if (state == TRACEE_IGNORED)
			continue;

		if (state != TRACEE_INACTIVE) {
			eprintf("!!! CUDA tracee #%d (%s) encountered problem. Last state: %s\n",
				i, name, cuda_tracee_state_str(state));
			continue;
		}

		u64 drop_cnt = wstat(s, WSTAT_CUDA_DROP_CNT, 1 + i);
		u64 err_cnt = wstat(s, WSTAT_CUDA_ERR_CNT, 1 + i);
		if (drop_cnt + err_cnt > 0) {
			eprintf("!!! CUDA tracee #%d (%s): %llu records dropped, %llu errors.\n",
				i, name, drop_cnt, err_cnt);
		}
		if (env.verbose || env.emit_stats) {
			eprintf("CUDA tracee #%d (%s): %llu records (%llu ignored), %llu buffers, %.3lfMBs.\n",
				i, name,
				wstat(s, WSTAT_CUDA_REC_CNT, 1 + i),
				wstat(s, WSTAT_CUDA_IGNORE_CNT, 1 + i),
				wstat(s, WSTAT_CUDA_BUF_CNT, 1 + i),
				wstat(s, WSTAT_CUDA_DATA_SZ, 1 + i) / 1024.0 / 1024.0);
		}
	}

	for (int i = 0; i < s->py_cnt; i++) {
		u64 state = wstat(s, WSTAT_PYTRACE_STATE, 1 + i);
		const char *name = wevent_str(env.data_hdr, wstat(s, WSTAT_PYTRACE_NAME, 1 + i));

		if (state != TRACEE_INACTIVE && state != TRACEE_SHUTDOWN_TIMEOUT) {
			eprintf("!!! Python tracee #%d (%s) encountered problem. Last state: %s\n",
				i, name, cuda_tracee_state_str(state));
			continue;
		}
		if (env.verbose || env.emit_stats) {
			eprintf("Python tracee #%d (%s): %llu events, %llu code objects cached.\n",
				i, name,
				wstat(s, WSTAT_PYTRACE_EVENT_CNT, 1 + i),
				wstat(s, WSTAT_PYTRACE_CODE_CACHE_CNT, 1 + i));
		}
	}

	u64 pystacks_attempted = wstat(s, WSTAT_PYSTACKS_ATTEMPTED, 0);
	u64 pystacks_found = wstat(s, WSTAT_PYSTACKS_FOUND, 0);
	if ((env.verbose || env.emit_stats) && pystacks_attempted > 0) {
		wprintf("PyStacks: %llu attempted, %llu found (%.2lf%%)\n",
			pystacks_attempted, pystacks_found,
			pystacks_found * 100.0 / pystacks_attempted);
	}

	u64 rb_misses = wstat(s, WSTAT_RB_MISSES, 0);
	if (rb_misses)
		eprintf("!!! Ringbuf fetch misses: %llu\n", rb_misses);

	if (total_drops) {
		for (int i = 0; i < s->cpu_cnt; i++) {
			u64 cpu_drops = wstat(s, WSTAT_RB_DROPS, 1 + s->rb_cnt + i);
			if (cpu_drops == 0)
				continue;

			u64 cpu_handled = wstat(s, WSTAT_RB_HANDLED_CNT, 1 + s->rb_cnt + i);
			u64 cpu_rescues = wstat(s, WSTAT_RB_RESCUES, 1 + s->rb_cnt + i);
			eprintf("!!! Drops (CPU #%d): %llu (%.3lf%% handled, %.3lf%% rescued, %.3lf%% dropped)\n",
				i, cpu_drops,
				cpu_handled * 100.0 / (cpu_handled + cpu_drops),
				cpu_rescues * 100.0 / (cpu_handled + cpu_drops),
				cpu_drops * 100.0 / (cpu_handled + cpu_drops));
		}
		for (int i = 0; i < s->rb_cnt; i++) {
			u64 rb_drops = wstat(s, WSTAT_RB_DROPS, 1 + i);
			if (rb_drops == 0)
				continue;

			u64 rb_hcnt = wstat(s, WSTAT_RB_HANDLED_CNT, 1 + i);
			u64 rb_rescues = wstat(s, WSTAT_RB_RESCUES, 1 + i);
			eprintf("!!! Drops (RB #%d): %llu (%.3lf%% handled, %.3lf%% rescued, %.3lf%% dropped)\n",
				i, rb_drops,
				rb_hcnt * 100.0 / (rb_hcnt + rb_drops),
				rb_rescues * 100.0 / (rb_hcnt + rb_drops),
				rb_drops * 100.0 / (rb_hcnt + rb_drops));
		}
		eprintf("!!! Drops (TOTAL): %llu (%.3lf%% handled, %.3lf%% rescued, %.3lf%% dropped)\n",
			total_drops,
			total_handled_cnt * 100.0 / (total_handled_cnt + total_drops),
			total_rescues * 100.0 / (total_handled_cnt + total_drops),
			total_drops * 100.0 / (total_handled_cnt + total_drops));
	}

	u64 task_drops = wstat(s, WSTAT_TASK_STATE_DROPS, 0);
	u64 req_drops = wstat(s, WSTAT_REQ_STATE_DROPS, 0);

	if (task_drops)
		eprintf("!!! Task state drops: %llu\n", task_drops);
	if (req_drops)
		eprintf("!!! Request state drops: %llu\n", req_drops);

	for (int i = 0; i < s->prog_cnt; i++) {
		u64 rec_misses = wstat(s, WSTAT_PROG_RECURSION_MISSES, 1 + i);
		if (rec_misses) {
			const char *name = wevent_str(env.data_hdr, wstat(s, WSTAT_PROG_NAME, 1 + i));
			eprintf("!!! %s: %llu recursion misses!\n", name, rec_misses);
		}
	}

	double *pmu_active_frac = (double *)wstats(s, WSTAT_PMU_ACTIVE_FRAC, NULL);
	for (int i = 0; pmu_active_frac && i < s->pmu_cnt; i++) {
		double active_frac = pmu_active_frac[1 + i];

		/* 0 = not captured, 1.0 = always running; anything else means multiplexed */
		if (active_frac == 0.0 || active_frac == 1.0)
			continue;

		struct wevent_pmu_def *def = wevent_pmu_def(env.data_hdr, i);
		const char *name = wevent_str(env.data_hdr, def->name_stroff);
		eprintf("!!! PMU counter '%s' was multiplexed by kernel (active %.2f%%), values can be unreliable!\n",
			name, 100.0 * active_frac);
	}

skip_error_diag:
	return;
}

struct timer_plan {
	int cpu;
	u64 delay_ns;
};

static int timer_plan_cmp(const void *a, const void *b)
{
	const struct timer_plan *x = a, *y = b;

	if (x->delay_ns != y->delay_ns)
		return x->delay_ns < y->delay_ns ? -1 : 1;

	return x->cpu - y->cpu;
}

static int setup_perf_timer_ticks(struct bpf_state *st, int num_cpus)
{
	struct perf_event_attr attr;

	st->perf_timer_fds = calloc(num_cpus, sizeof(int));
	for (int i = 0; i < num_cpus; i++)
		st->perf_timer_fds[i] = -1;

	/* determine randomized spread-out "plan" for attaching to timers to
	 * avoid too aligned (in time) triggerings across all CPUs
	 */
	u64 timer_start_ts = ktime_now_ns();
	struct timer_plan *timer_plan = calloc(num_cpus, sizeof(*timer_plan));

	for (int cpu = 0; cpu < num_cpus; cpu++) {
		timer_plan[cpu].cpu = cpu;
		timer_plan[cpu].delay_ns = 1000000000ULL / env.timer_freq_hz * ((double)rand() / RAND_MAX);
	}
	qsort(timer_plan, num_cpus, sizeof(*timer_plan), timer_plan_cmp);

	for (int i = 0; i < num_cpus; i++) {
		int cpu = timer_plan[i].cpu;

		/* skip offline/not present CPUs */
		if (cpu >= st->num_online_cpus || !st->online_mask[cpu])
			continue;

		/* timer perf event */
		memset(&attr, 0, sizeof(attr));
		attr.size = sizeof(attr);
		attr.type = PERF_TYPE_SOFTWARE;
		attr.config = PERF_COUNT_SW_CPU_CLOCK;
		attr.sample_freq = env.timer_freq_hz;
		attr.freq = 1;

		u64 now = ktime_now_ns();
		if (now < timer_start_ts + timer_plan[i].delay_ns)
			usleep((timer_start_ts + timer_plan[i].delay_ns - now) / 1000);

		int pefd = sys_perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (pefd < 0) {
			int err = -errno;
			eprintf("Failed to set up performance monitor on CPU %d: %d\n", cpu, err);
			return err;
		}
		st->perf_timer_fds[cpu] = pefd;
	}

	return 0;
}

static int setup_perf_counters(struct bpf_state *st, int num_cpus)
{
	struct perf_event_attr attr;
	int err;

	st->perf_counter_fds = calloc(st->perf_counter_fd_cnt, sizeof(int));
	for (int i = 0; i < num_cpus; i++) {
		for (int j = 0; j < env.pmu_real_cnt; j++)
			st->perf_counter_fds[i * env.pmu_real_cnt + j] = -1;
	}

	for (int cpu = 0; cpu < num_cpus; cpu++) {
		/* set up requested perf counters */
		for (int j = 0; j < env.pmu_real_cnt; j++) {
			const struct pmu_event *ev = &env.pmu_reals[j];
			int pe_idx = cpu * env.pmu_real_cnt + j;

			memset(&attr, 0, sizeof(attr));
			attr.size = sizeof(attr);
			attr.type = ev->perf_type;
			attr.config = ev->config;
			attr.config1 = ev->config1;
			attr.config2 = ev->config2;
			/*
			 * So we can detect multiplexing at session end by comparing
			 * time_running against time_enabled per event.
			 */
			attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;

			int pefd = sys_perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
			if (pefd < 0) {
				eprintf("Failed to create %s PMU for CPU #%d, skipping...\n", ev->name, cpu);
			} else {
				st->perf_counter_fds[pe_idx] = pefd;
				err = bpf_map__update_elem(st->skel->maps.perf_cntrs,
							   &pe_idx, sizeof(pe_idx),
							   &pefd, sizeof(pefd), 0);
				if (err) {
					eprintf("Failed to set up %s PMU on CPU#%d for BPF: %d\n", ev->name, cpu, err);
					return err;
				}
				err = ioctl(pefd, PERF_EVENT_IOC_ENABLE, 0);
				if (err) {
					err = -errno;
					eprintf("Failed to enable %s PMU on CPU#%d: %d\n", ev->name, cpu, err);
					return err;
				}
			}
		}
	}

	return 0;
}

static int setup_bpf(struct bpf_state *st, struct worker_state *workers, int num_cpus, int workdir_fd)
{
	const char *online_cpus_file = "/sys/devices/system/cpu/online";
	struct wprof_bpf *skel;
	int i, err = 0;

#if !defined(__x86_64__) && !defined(__aarch64__)
	if (env.capture_ipis) {
		eprintf("IPI capture is supported only on x86-64 and arm64 architectures!\n");
		return -EOPNOTSUPP;
	}
#endif

	libbpf_set_print(libbpf_print_fn);

	err = parse_cpu_mask(online_cpus_file, &st->online_mask, &st->num_online_cpus);
	if (err) {
		eprintf("Failed to get online CPU numbers: %d\n", err);
		return -EINVAL;
	}

	env.skel = st->skel = skel = wprof_bpf__open();
	if (!skel) {
		err = -errno;
		eprintf("Failed to open and load BPF skeleton: %d\n", err);
		return err;
	}

	if (env.capture_ipis) {
		bpf_program__set_autoload(skel->progs.wprof_ipi_send_cpu, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_send_mask, true);
#if defined(__x86_64__)
		bpf_program__set_autoload(skel->progs.wprof_ipi_single_entry, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_single_exit, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_multi_entry, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_multi_exit, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_resched_entry, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_resched_exit, true);
#elif defined(__aarch64__)
		bpf_program__set_autoload(skel->progs.wprof_ipi_entry, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_exit, true);
#endif
	}

	if (env.capture_softirq) {
		bpf_program__set_autoload(skel->progs.wprof_softirq_entry, true);
		bpf_program__set_autoload(skel->progs.wprof_softirq_exit, true);
	}
	if (env.capture_hardirq) {
		bpf_program__set_autoload(skel->progs.wprof_hardirq_entry, true);
		bpf_program__set_autoload(skel->progs.wprof_hardirq_exit, true);
	}

	if (env.req_pid_cnt > 0 || env.req_path_cnt > 0 || env.req_global_discovery) {
		err = setup_req_tracking_discovery();
		if (err) {
			eprintf("Request tracking discovery step failed: %d\n", err);
			return err;
		}
	}

	if (env.req_binaries) {
		bpf_program__set_autoload(skel->progs.wprof_req_ctx, true);
		bpf_program__set_autoload(skel->progs.wprof_req_task_enqueue, true);
		bpf_program__set_autoload(skel->progs.wprof_req_task_dequeue, true);
		bpf_program__set_autoload(skel->progs.wprof_req_task_stats, true);
		bpf_map__set_max_entries(skel->maps.req_states, max(16 * 1024, env.task_state_sz));
	} else {
		bpf_map__set_autocreate(skel->maps.req_states, false);
		env.capture_requests = false;
	}

	if (env.cuda_pid_cnt > 0 || env.cuda_discovery) {
		err = cuda_trace_setup(workdir_fd);
		if (err) {
			eprintf("CUDA trace setup failed: %d\n", err);
			return err;
		}
		if (env.requested_stack_traces & ST_CUDA)
			bpf_program__set_autoload(skel->progs.wprof_cuda_call, true);
	}

	if ((env.capture_pytrace == TRUE || env.capture_pytorch == TRUE) &&
	    (env.pytrace_pid_cnt > 0 || env.pytorch_pid_cnt > 0 ||
	     env.pytrace_discovery || env.pytorch_discovery)) {
		err = pytrace_trace_setup(workdir_fd);
		if (err) {
			eprintf("Python trace setup failed: %d\n", err);
			return err;
		}
	}

	if (env.capture_scx) {
		struct btf *vmlinux_btf = load_vmlinux_btf();

		if (btf__find_by_name_kind(vmlinux_btf, "scx_bpf_dsq_insert", BTF_KIND_FUNC) < 0) {
			bpf_program__set_autoload(skel->progs.wprof_dispatch, true);
		} else {
			bpf_program__set_autoload(skel->progs.wprof_dsq_insert, true);
		}
		if (btf__find_by_name_kind(vmlinux_btf, "scx_bpf_dsq_insert_vtime", BTF_KIND_FUNC) < 0) {
			bpf_program__set_autoload(skel->progs.wprof_dispatch_vtime, true);
		} else {
			bpf_program__set_autoload(skel->progs.wprof_dsq_insert_vtime, true);
		}
		if (btf__find_by_name_kind(vmlinux_btf, "scx_bpf_dsq_move", BTF_KIND_FUNC) < 0) {
			bpf_program__set_autoload(skel->progs.wprof_dispatch_from_dsq, true);
		} else {
			bpf_program__set_autoload(skel->progs.wprof_dsq_move, true);
		}
		if (btf__find_by_name_kind(vmlinux_btf, "scx_bpf_dsq_move_vtime", BTF_KIND_FUNC) < 0) {
			bpf_program__set_autoload(skel->progs.wprof_dispatch_vtime_from_dsq, true);
		} else {
			bpf_program__set_autoload(skel->progs.wprof_dsq_move_vtime, true);
		}

		/*
		 * Try to find scx_layered's task_ctxs map for reliable layer_id.
		 * If found, we reuse its fd so our BPF code can look up layer_id
		 * directly from scx_layered's task-local storage.
		 */
		u32 next_id = 0;
		bool found = false;

		while (true) {
			err = bpf_map_get_next_id(next_id, &next_id);
			if (err == -ENOENT)
				break;
			if (err < 0) {
				eprintf("Failed to iterate BPF maps: %d\n", err);
				return err;
			}

			int map_fd = bpf_map_get_fd_by_id(next_id);
			if (map_fd == -ENOENT)
				continue;
			if (map_fd < 0) {
				eprintf("Failed to fetch map FD for map #%d: %d\n", next_id, map_fd);
				continue;
			}

			struct bpf_map_info info;
			u32 info_len = sizeof(info);

			memset(&info, 0, sizeof(info));
			err = bpf_obj_get_info_by_fd(map_fd, &info, &info_len);
			if (err) {
				eprintf("Failed to fetch map info for map #%d: %d\n", next_id, err);
				close(map_fd);
				continue;
			}

			if (strcmp(info.name, "task_ctxs") != 0) {
				close(map_fd);
				continue;
			}

			if (found) {
				close(map_fd);
				eprintf("Found multiple 'task_ctxs' BPF maps, unsure which one to use!\n");
				return -EINVAL;
			}

			err = bpf_map__reuse_fd(skel->maps.scx_task_ctxs, map_fd);
			close(map_fd);
			if (err) {
				eprintf("Failed to reuse map #%d ('%s'): %d\n",
					next_id, info.name, err);
				continue;
			}
			found = true;
		}

		if (!found)
			eprintf("WARNING: scx_layered's 'task_ctxs' map not found; layer_id will not be available\n");
		else
			skel->rodata->capture_scx_layer_id = true;
	}
	bpf_map__set_autocreate(skel->maps.scx_task_ctxs, skel->rodata->capture_scx_layer_id);

	skel->rodata->capture_scx = env.capture_scx == TRUE;

	skel->rodata->rb_cnt = env.ringbuf_cnt;
	bpf_map__set_max_entries(skel->maps.rbs, env.ringbuf_cnt);
	bpf_map__set_max_entries(skel->maps.task_states, env.task_state_sz);

	/* FILTERING */
	struct {
		enum wprof_filt_mode filt_mode;
		const char *name;
		int cnt;
		int *ints;
		struct bpf_map *map;
		int **mmap;
		int *skel_cnt;
	} int_filters[] = {
		{
			FILT_ALLOW_PID, "PID allowlist",
			env.allow_pid_cnt, env.allow_pids,
			skel->maps.data_allow_pids, (int **)&skel->data_allow_pids,
			&skel->rodata->allow_pid_cnt,
		},
		{
			FILT_DENY_PID, "PID denylist",
			env.deny_pid_cnt, env.deny_pids,
			skel->maps.data_deny_pids, (int **)&skel->data_deny_pids,
			&skel->rodata->deny_pid_cnt,
		},
		{
			FILT_ALLOW_TID, "TID allowlist",
			env.allow_tid_cnt, env.allow_tids,
			skel->maps.data_allow_tids, (int **)&skel->data_allow_tids,
			&skel->rodata->allow_tid_cnt,
		},
		{
			FILT_DENY_TID, "TID denylist",
			env.deny_tid_cnt, env.deny_tids,
			skel->maps.data_deny_tids, (int **)&skel->data_deny_tids,
			&skel->rodata->deny_tid_cnt,
		},
	};
	for (int i = 0; i < ARRAY_SIZE(int_filters); i++) {
		const typeof(int_filters[0]) *f = &int_filters[i];
		size_t _sz;

		if (f->cnt == 0)
			continue;

		skel->rodata->filt_mode |= f->filt_mode;
		*f->skel_cnt = f->cnt;
		if ((err = bpf_map__set_value_size(f->map, f->cnt * sizeof(int)))) {
			eprintf("Failed to size BPF-side %s: %d\n", f->name, err);
			return err;
		}
		*f->mmap = bpf_map__initial_value(f->map, &_sz);
		for (int i = 0; i < f->cnt; i++)
			(*f->mmap)[i] = f->ints[i];
	}

	struct {
		enum wprof_filt_mode filt_mode;
		const char *name;
		int cnt;
		char **globs;
		struct bpf_map *map;
		struct glob_str **mmap;
		int *skel_cnt;
	} glob_filters[] = {
		{
			FILT_ALLOW_PNAME, "process name allowlist",
			env.allow_pname_cnt, env.allow_pnames,
			skel->maps.data_allow_pnames, (struct glob_str **)&skel->data_allow_pnames,
			&skel->rodata->allow_pname_cnt,
		},
		{
			FILT_DENY_PNAME, "process name denylist",
			env.deny_pname_cnt, env.deny_pnames,
			skel->maps.data_deny_pnames, (struct glob_str **)&skel->data_deny_pnames,
			&skel->rodata->deny_pname_cnt,
		},
		{
			FILT_ALLOW_TNAME, "thread name allowlist",
			env.allow_tname_cnt, env.allow_tnames,
			skel->maps.data_allow_tnames, (struct glob_str **)&skel->data_allow_tnames,
			&skel->rodata->allow_tname_cnt,
		},
		{
			FILT_DENY_TNAME, "thread name denylist",
			env.deny_tname_cnt, env.deny_tnames,
			skel->maps.data_deny_tnames, (struct glob_str **)&skel->data_deny_tnames,
			&skel->rodata->deny_tname_cnt,
		},
	};
	for (int i = 0; i < ARRAY_SIZE(glob_filters); i++) {
		const typeof(glob_filters[0]) *f = &glob_filters[i];
		size_t _sz;

		if (f->cnt == 0)
			continue;

		skel->rodata->filt_mode |= f->filt_mode;
		*f->skel_cnt = f->cnt;
		if ((err = bpf_map__set_value_size(f->map, f->cnt * sizeof(**f->mmap)))) {
			eprintf("Failed to size BPF-side %s: %d\n", f->name, err);
			return err;
		}
		*f->mmap = bpf_map__initial_value(f->map, &_sz);
		for (int i = 0; i < f->cnt; i++)
			wprof_strlcpy((*f->mmap)[i].pat, f->globs[i], sizeof(**f->mmap));
	}

	if (env.allow_idle)
		skel->rodata->filt_mode |= FILT_ALLOW_IDLE;
	if (env.deny_idle)
		skel->rodata->filt_mode |= FILT_DENY_IDLE;
	if (env.allow_kthread)
		skel->rodata->filt_mode |= FILT_ALLOW_KTHREAD;
	if (env.deny_kthread)
		skel->rodata->filt_mode |= FILT_DENY_KTHREAD;

	st->perf_counter_fd_cnt = num_cpus * env.pmu_real_cnt;
	skel->rodata->perf_ctr_cnt = env.pmu_real_cnt;
	bpf_map__set_max_entries(skel->maps.perf_cntrs, st->perf_counter_fd_cnt);

	if (env.requested_stack_traces & ST_TIMER)
		bpf_program__set_autoload(st->skel->progs.wprof_timer_tick, true);
	skel->rodata->requested_stack_traces = env.requested_stack_traces;

	int cpu_cnt_pow2 = round_pow_of_2(num_cpus);
	skel->rodata->rb_cpu_map_mask = cpu_cnt_pow2 - 1;
	if ((err = bpf_map__set_value_size(skel->maps.data_rb_cpu_map, cpu_cnt_pow2 * sizeof(*skel->data_rb_cpu_map)))) {
		eprintf("Failed to size RB-to-CPU mapping: %d\n", err);
		return err;
	}
	size_t _sz;
	skel->data_rb_cpu_map = bpf_map__initial_value(skel->maps.data_rb_cpu_map, &_sz);

	err = setup_cpu_to_ringbuf_mapping(skel->data_rb_cpu_map->rb_cpu_map, env.ringbuf_cnt, num_cpus);
	if (err) {
		eprintf("Failed to setup RB-to-CPU mapping: %d\n", err);
		return err;
	}

	err = utrace_setup(skel);
	if (err) {
		eprintf("Failed to setup utrace: %d\n", err);
		return err;
	}

	 /* force RB notification when at least 2.0MB or 25% of ringbuf (whichever is less) is full */
	skel->rodata->rb_submit_threshold_bytes = min(2 * 1024 * 1024, env.ringbuf_sz / 4);

	if (env.emit_stats) {
		st->stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
		if (st->stats_fd < 0)
			eprintf("Failed to enable BPF run stats tracking: %d!\n", st->stats_fd);
	}

	err = bpf_object__prepare(skel->obj);
	if (err) {
		eprintf("Failed to prepare BPF skeleton: %d\n", err);
		return err;
	}

	/*
	 * BPF fentry/fexit templates needed to be autoloaded for prepare() to
	 * process them, but must not be loaded into the kernel — they are only
	 * used as clone sources. Unconditionally disable; harmless if unused.
	 */
	bpf_program__set_autoload(skel->progs.wprof_ut_bpf_entry, false);
	bpf_program__set_autoload(skel->progs.wprof_ut_bpf_exit, false);

	err = wprof_bpf__load(skel);
	if (err) {
		eprintf("Failed to load BPF skeleton: %d\n", err);
		return err;
	}

	st->rb_map_fds = calloc(env.ringbuf_cnt, sizeof(*st->rb_map_fds));
	u32 *rb_keys = calloc(env.ringbuf_cnt, sizeof(*rb_keys));
	for (int i = 0; i < env.ringbuf_cnt; i++) {
		int map_fd;

		map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, sfmt("wprof_rb_%d", i), 0, 0, env.ringbuf_sz, NULL);
		if (map_fd < 0) {
			eprintf("Failed to create BPF ringbuf #%d: %d\n", i, map_fd);
			return map_fd;
		}

		rb_keys[i] = i;
		st->rb_map_fds[i] = map_fd;
	}

	u32 rb_cnt = env.ringbuf_cnt;
	LIBBPF_OPTS(bpf_map_batch_opts, batch_opts);
	err = bpf_map_update_batch(bpf_map__fd(skel->maps.rbs), rb_keys, st->rb_map_fds,
				   &rb_cnt, &batch_opts);
	free(rb_keys);
	if (err < 0) {
		eprintf("Failed to set BPF ringbufs into ringbuf map-of-maps: %d\n", err);
		return err;
	}

	/* Prepare ring buffers to receive events from the BPF program. */
	st->rb_managers = calloc(env.ringbuf_cnt, sizeof(*st->rb_managers));
	for (i = 0; i < env.ringbuf_cnt; i++) {
		st->rb_managers[i] = ring_buffer__new(st->rb_map_fds[i], handle_rb_event, &workers[i], NULL);
		if (!st->rb_managers[i]) {
			eprintf("Failed to create ring buffer manager for ringbuf #%d: %d\n", i, err);
			err = -errno;
			return err;
		}
		workers[i].rb_manager = st->rb_managers[i];
	}

	if (env.requested_stack_traces & ST_TIMER) {
		err = setup_perf_timer_ticks(st, num_cpus);
		if (err) {
			eprintf("Failed to setup timer tick events: %d\n", err);
			return err;
		}
	}

	if (env.pmu_real_cnt) {
		err = setup_perf_counters(st, num_cpus);
		if (err) {
			eprintf("Failed to setup perf counters: %d\n", err);
			return err;
		}
	}

	if (env.capture_pystacks) {
		err = pystacks_init(skel);
		if (err) {
			eprintf("Failed to initialize pystacks: %d\n", err);
			return err;
		}
	}

	return 0;
}

static atomic_int rb_workers_ready = 0;

static void *rb_worker(void *ctx)
{
	struct worker_state *worker = ctx;
	char name[32];

	snprintf(name, sizeof(name), "wprof_rb%03d", worker->worker_id);
	pthread_setname_np(pthread_self(), name);

	rb_workers_ready += 1;

	while (!exiting) {
		ring_buffer__poll(worker->rb_manager, 100);
	}

	return NULL;
}

int attach_usdt_probe(struct bpf_state *st, struct bpf_program *prog,
		      const char *binary_path, const char *binary_attach_path,
		      const char *usdt_provider, const char *usdt_name)
{
	struct bpf_link *link, **tmp;
	struct usdt_info info;

	if (elf_find_usdt(binary_attach_path, usdt_provider, usdt_name, &info)) {
		dlogf(USDT, 2, "No USDT %s:%s in %s (%s), skipping.\n",
		      usdt_provider, usdt_name, binary_path, binary_attach_path);
		return -ENOENT;
	}

	link = bpf_program__attach_usdt(prog, -1, binary_attach_path,
					usdt_provider, usdt_name, NULL);
	if (!link) {
		vprintf("Failed to attach USDT %s:%s to %s (%s): %d, skipping.\n",
		      usdt_provider, usdt_name, binary_path, binary_attach_path, -errno);
		return -ENOENT;
	}

	dlogf(USDT, 1, "Attached USDT %s:%s to %s (%s).\n",
	      usdt_provider, usdt_name, binary_path, binary_attach_path);

	tmp = realloc(st->links, (st->link_cnt + 1) * sizeof(struct bpf_link *));
	if (!tmp)
		return -ENOMEM;
	st->links = tmp;
	st->links[st->link_cnt] = link;
	st->link_cnt++;

	return 0;
}

static int attach_bpf(struct bpf_state *st, struct worker_state *workers, int num_cpus)
{
	int err = 0;

	st->links = calloc(num_cpus, sizeof(struct bpf_link *));
	for (int cpu = 0; cpu < num_cpus; cpu++) {
		if (!st->perf_timer_fds || st->perf_timer_fds[cpu] < 0)
			continue;

		st->links[cpu] = bpf_program__attach_perf_event(st->skel->progs.wprof_timer_tick,
								st->perf_timer_fds[cpu]);
		if (!st->links[cpu]) {
			err = -errno;
			return err;
		}
		st->link_cnt++;
	}

	err = wprof_bpf__attach(st->skel);
	if (err) {
		eprintf("Failed to attach skeleton: %d\n", err);
		return err;
	}

	if (env.req_binaries) {
		err = attach_req_tracking_usdts(st);
		if (err) {
			eprintf("Failed to attach request tracking USDTs: %d\n", err);
			return err;
		}
	}

	if (env.utrace_cfg_cnt > 0) {
		err = utrace_attach(st, st->skel);
		if (err) {
			eprintf("Failed to attach utrace probes: %d\n", err);
			return err;
		}
	}

	/* spin up and ready ringbuf consumer threads */
	st->rb_threads = calloc(env.ringbuf_cnt, sizeof(*st->rb_threads));

	for (int i = 0; i < env.ringbuf_cnt; i++) {
		int err = pthread_create(&st->rb_threads[i], NULL, rb_worker, &workers[i]);
		if (err) {
			err = -errno;
			eprintf("Failed to spawn ringbuf worker thread #%d: %d\n", i, err);
			return err;
		}
	}

	while (rb_workers_ready != env.ringbuf_cnt)
		sched_yield();

	return 0;
}

static int wait_bpf(struct bpf_state *st)
{
	for (int i = 0; i < env.ringbuf_cnt; i++) {
		int err = pthread_join(st->rb_threads[i], NULL);
		if (err) {
			err = -errno;
			eprintf("Failed to cleanly join ringbuf worker thread #%d: %d\n", i, err);
		}
	}

	return 0;
}

static void detach_bpf(struct bpf_state *st, int num_cpus)
{
	if (env.replay)
		return;
	if (st->detached)
		return;

	if (st->skel)
		wprof_bpf__detach(st->skel);
	if (st->stats_fd >= 0)
		close(st->stats_fd);
	if (st->links) {
		for (int i = 0; i < st->link_cnt; i++)
			bpf_link__destroy(st->links[i]);
		free(st->links);
	}
	if (st->link_fds) {
		for (int i = 0; i < st->link_fd_cnt; i++)
			close(st->link_fds[i]);
		free(st->link_fds);
	}
	if (st->perf_timer_fds) {
		for (int i = 0; i < num_cpus; i++) {
			if (st->perf_timer_fds[i] >= 0)
				close(st->perf_timer_fds[i]);
		}
		free(st->perf_timer_fds);
	}
	if (st->perf_counter_fds) {
		/*
		 * Disable, read, and close each PMU fd. time_enabled/time_running
		 * are accumulated per real PMU to compute active_frac, which is
		 * later persisted via WSTAT_PMU_ACTIVE_FRAC.
		 */
		for (int i = 0; i < env.pmu_real_cnt; i++) {
			u64 tot_enabled = 0, tot_running = 0;

			for (int cpu = 0; cpu < num_cpus; cpu++) {
				int pe_idx = cpu * env.pmu_real_cnt + i;
				int fd = st->perf_counter_fds[pe_idx];
				if (fd < 0)
					continue;

				(void)ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

				u64 buf[3] = {}; /* value, time_enabled, time_running */
				if (read(fd, buf, sizeof(buf)) == sizeof(buf)) {
					tot_enabled += buf[1];
					tot_running += buf[2];
				}

				close(fd);
			}

			if (tot_enabled == tot_running)
				env.pmu_reals[i].active_frac = 1.0;
			else if (tot_enabled == 0)
				env.pmu_reals[i].active_frac = 0.0;
			else
				env.pmu_reals[i].active_frac = tot_running / (double)tot_enabled;
		}
		free(st->perf_counter_fds);
	}

	st->detached = true;
}

static void drain_bpf(struct bpf_state *st, int num_cpus)
{
	if (env.replay)
		return;
	if (st->drained)
		return;

	if (st->rb_managers) {
		for (int i = 0; i < env.ringbuf_cnt; i++) {
			if (st->rb_managers[i]) { /* drain ringbuf */
				exiting = false; /* ringbuf callback will stop early, if exiting is set */
				(void)ring_buffer__consume(st->rb_managers[i]);
			}
			ring_buffer__free(st->rb_managers[i]);
		}
	}

	if (st->rb_map_fds) {
		for (int i = 0; i < env.ringbuf_cnt; i++)
			if (st->rb_map_fds[i])
				close(st->rb_map_fds[i]);
	}

	st->drained = true;
}

static void cleanup_bpf(struct bpf_state *st)
{
	if (env.replay)
		return;

	wprof_bpf__destroy(st->skel);
	st->skel = NULL;

	free(st->online_mask);
	st->online_mask = NULL;
}

static void cleanup_workers(struct worker_state *workers, int worker_cnt)
{
	for (int i = 0; i < worker_cnt; i++) {
		struct worker_state *w = &workers[i];
		if (!w)
			return;

		wpb_writer_free(w->wpb_writer);

		if (w->trace && w->trace != stdout)
			fclose(w->trace);

		if (w->dump_mem && w->dump_mem != MAP_FAILED) {
			int err = munmap(w->dump_mem, w->dump_sz);
			if (err < 0) {
				err = -errno;
				eprintf("Failed to munmap() dump file '%s': %d\n", env.data_path, err);
			}
		}

		if (w->dump)
			fclose(w->dump);

		free(w->dump_path);
		free(w->req_allowlist.ids);

		w->dump_mem = NULL;
		w->dump = NULL;
	}
}


static int arm_timer_abs(int tfd, u64 abs_ktime_ns)
{
	struct itimerspec its = {
		.it_value = {
			.tv_sec  = abs_ktime_ns / 1000000000ULL,
			.tv_nsec = abs_ktime_ns % 1000000000ULL,
		},
	};
	return timerfd_settime(tfd, TFD_TIMER_ABSTIME, &its, NULL);
}

static void drain_fd(int fd)
{
	u64 v;
	(void)read(fd, &v, sizeof(v));
}

static int ctl_epoll_add(int epoll_fd, int fd, u32 tag)
{
	struct epoll_event ev = { .events = EPOLLIN, .data = { .u32 = tag } };
	return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
}

/* SESS_PREP: discovery, BPF load/attach, and tracee injection. */
static int do_prepare(struct bpf_state *bpf, struct worker_state *workers, int num_cpus, int workdir_fd)
{
	int err;
	/*
	 * Injected agents auto-retract if wprof dies without tearing them down.
	 * Size that timeout to cover the whole window from now to the planned
	 * session end (the wait for activation plus the run duration), with margin.
	 */
	u64 activate_at = env.sess_ctl.activate_target_ts ?: ktime_now_ns();
	long sess_timeout_ms = (s64)(activate_at + env.duration_ns - ktime_now_ns()) / 1000000 +
			       LIBWPROFINJ_SESSION_TIMEOUT_MS;

	err = setup_bpf(bpf, workers, num_cpus, workdir_fd);
	if (err) {
		eprintf("Failed to setup BPF parts: %d\n", err);
		return err;
	}

	err = attach_bpf(bpf, workers, num_cpus);
	if (err) {
		eprintf("Failed to attach BPF parts: %d\n", err);
		return err;
	}

	if (env.cuda_cnt > 0) {
		wprintf("Preparing CUDA tracees...\n");
		err = cuda_trace_prepare(workdir_fd, sess_timeout_ms);
		if (err) {
			eprintf("Failed to prepare CUDA tracing sessions: %d\n", err);
			return err;
		}
	}

	if (env.py_cnt > 0) {
		wprintf("Preparing Python tracees...\n");
		err = pytrace_trace_prepare(workdir_fd, sess_timeout_ms);
		if (err) {
			eprintf("Failed to prepare Python tracing sessions: %d\n", err);
			return err;
		}
	}

	return 0;
}

/* SESS_ARMED -> SESS_RECORDING: stamp t=0, open the session window, activate tracees. */
static int do_activate(struct bpf_state *bpf)
{
	int err;

	wprintf("Running...\n");

	env.ktime_start_ns = ktime_now_ns();
	env.realtime_start_ns = ktime_to_realtime_ns(env.ktime_start_ns);
	env.sess_start_ts = env.ktime_start_ns;
	env.sess_end_ts = env.ktime_start_ns + env.duration_ns;

	bpf->skel->bss->session_start_ts = env.sess_start_ts;
	bpf->skel->bss->session_end_ts = env.sess_end_ts;

	if (env.cuda_cnt > 0) {
		wprintf("Activating CUDA tracees...\n");
		err = cuda_trace_activate(env.sess_start_ts, env.sess_end_ts);
		if (err) {
			eprintf("Failed to activate CUDA tracing sessions: %d\n", err);
			return err;
		}

		if (env.requested_stack_traces & ST_CUDA) {
			wprintf("Attaching CUDA USDTs...\n");
			err = cuda_trace_attach_usdts(bpf, bpf->skel->progs.wprof_cuda_call);
			if (err) {
				eprintf("Failed to attach CUDA tracking USDTs: %d\n", err);
				return err;
			}
		}
	}

	if (env.py_cnt > 0) {
		wprintf("Activating Python tracees...\n");
		err = pytrace_trace_activate(env.sess_start_ts, env.sess_end_ts);
		if (err) {
			eprintf("Failed to activate Python tracing sessions: %d\n", err);
			return err;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_state bpf_state = {};
	int num_cpus = 0, err = 0;
	int worker_cnt = 0;
	struct worker_state *workers = NULL;
	char workdir_name[PATH_MAX] = {};
	int workdir_fd = -1;

	env.actual_start_ts = ktime_now_ns();
	calibrate_ktime(); /* establish the ktime<->realtime mapping up front, so it is always available */
	env.sess_ctl.sig_efd = -1; /* so an early SIGINT (before the eventfd exists) is a no-op */

	/* Parse command line arguments */
	setenv("ARGP_HELP_FMT", "opt-doc-col=35,rmargin=150", 0); /* widen default --help output */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) {
		err = -1;
		goto cleanup;
	}

	{
		int output_modes = !!(env.trace_path || env.json_path) + env.req_list + !!env.replay_info;
		if (output_modes > 1) {
			eprintf("Only one of -T, -J, --req-list, and --replay-info (-RI) can be specified at a time!\n");
			err = -EINVAL;
			goto cleanup;
		}
		if (env.replay && output_modes == 0) {
			eprintf("Replay mode (-R) requires an output: -T, -J, -I, or --req-list.\n");
			err = -EINVAL;
			goto cleanup;
		}
		if (env.req_list_cfg && !env.req_list) {
			if (env.req_list_cfg->sort_cnt > 0 || env.req_list_cfg->top_n > 0 || env.req_list_cfg->bottom_n > 0) {
				eprintf("--req-sort, --req-top-n, and --req-bottom-n require --req-list!\n");
				err = -EINVAL;
				goto cleanup;
			}
			if (env.req_list_cfg->filter_cnt > 0 && !env.trace_path && !env.json_path) {
				eprintf("--req-filter requires --req-list or -T/-J!\n");
				err = -EINVAL;
				goto cleanup;
			}
		}
	}

	if (!env.replay && geteuid() != 0)
		eprintf("WARNING: wprof is not running as root, data capture will most probably FAIL due to insufficient permissions!\n");

	vprintf("wprof v%s (PID %d) started!\n", WPROF_VERSION, getpid());

	env.num_cpus = num_cpus = libbpf_num_possible_cpus();
	if (num_cpus <= 0) {
		eprintf("Failed to get the number of processors\n");
		err = -1;
		goto cleanup;
	}

	signal(SIGINT, sig_term);
	signal(SIGTERM, sig_term);
	signal(SIGPIPE, sig_pipe);

	if (env.ringbuf_cnt == 0) {
		if (env.replay) {
			env.ringbuf_cnt = 1;
		} else {
			/* random heuristics: 8 CPUs per ringbuf, but at least 4 ringbuf */
			env.ringbuf_cnt = max(4, (num_cpus + 7) / 8);
		}
	}
	env.ringbuf_cnt = min(env.ringbuf_cnt, num_cpus);
	if (!env.replay) {
		vprintf("Using %zu BPF ring buffers.\n", env.ringbuf_cnt);
		/* -1 is only meaningful for the replay mode to autoload counters */
		if (env.pmu_real_cnt == -1)
			env.pmu_real_cnt = 0;
		if (env.pmu_deriv_cnt == -1)
			env.pmu_deriv_cnt = 0;
		if (env.pmu_unresolved_cnt == -1)
			env.pmu_unresolved_cnt = 0;
	}

	/* during replay or trace generation there is only one worker */
	worker_cnt = env.replay ? 1 : env.ringbuf_cnt;
	workers = calloc(worker_cnt, sizeof(*workers));
	for (int i = 0; i < worker_cnt; i++)
		workers[i].worker_id = i;
	workers[0].name_iids = (struct str_iid_domain) {
		.str_iids = hashmap__new(str_hash_fn, str_equal_fn, NULL),
		.next_str_iid = IID_FIXED_LAST_ID,
		.domain_desc = "dynamic",
	};

	if (env.replay) {
		struct worker_state *worker = &workers[0];
		worker->dump = fopen(env.data_path, "r");
		if (!worker->dump) {
			err = -errno;
			eprintf("Failed to open data dump at '%s': %d\n", env.data_path, err);
			goto cleanup;
		}
		err = wprof_load_data_dump(worker);
		if (err) {
			eprintf("Failed to load data dump at '%s': %d\n", env.data_path, err);
			goto cleanup;
		}
		struct wprof_data_hdr *dump_hdr = worker->dump_hdr;
		const struct wprof_data_cfg *cfg = &dump_hdr->cfg;
		env.data_hdr = dump_hdr;

		for (u64 i = 0; i < dump_hdr->extra_cnt; i++) {
			struct wprof_extra_param *ep = wevent_extra_param(dump_hdr, i);
			if (ep->kind == WEXTRA_STATS) {
				env.stats = wevent_blob(dump_hdr, ep->bloboff);
				break;
			}
		}

		if (env.replay_info) {
			const int w = 26;
			const double MB = 1024.0 * 1024.0;
			const double S = 1000000000.0;
			const double ms = 1000000.0;

			env.replay_start_offset_ns = 0;
			env.replay_end_offset_ns = cfg->duration_ns;
			env.duration_ns = cfg->duration_ns;

			wprintf("Replay info:\n");
			wprintf("============\n");
			wprintf("%-*s%s\n", w, "Timestamp:", fmt_timestamp_ns(cfg->realtime_start_ns));
			wprintf("%-*s%.3lfs (%.3lfms)\n", w, "Duration:", cfg->duration_ns / S, cfg->duration_ns / ms);
			wprintf("%-*s%u.%u\n", w, "Data version:", dump_hdr->version_major, dump_hdr->version_minor);
			if (cfg->captured_stack_traces) {
				wprintf("%-*s\n", w, "Stack traces:");
				if (cfg->captured_stack_traces & ST_TIMER)
					wprintf("    --stacks timer\n");
				if (cfg->captured_stack_traces & ST_OFFCPU)
					wprintf("    --stacks offcpu\n");
				if (cfg->captured_stack_traces & ST_WAKER)
					wprintf("    --stacks waker\n");
				if (cfg->captured_stack_traces & ST_CUDA)
					wprintf("    --stacks cuda\n");
				if (cfg->captured_stack_traces & ST_UTRACE)
					wprintf("    --stacks utrace\n");
			} else {
				wprintf("%-*s%s\n", w, "Stack traces:", "NONE");
			}
			if (dump_hdr->pmu_def_real_cnt + dump_hdr->pmu_def_deriv_cnt) {
				wprintf("%-*s\n", w, "PMU counters:");
				for (int i = 0; i < dump_hdr->pmu_def_real_cnt; i++) {
					struct wevent_pmu_def *def = wevent_pmu_def(dump_hdr, i);
					wprintf("    %s\n", wevent_str(dump_hdr, def->name_stroff));
				}
				for (int i = 0; i < dump_hdr->pmu_def_deriv_cnt; i++) {
					struct wevent_pmu_def *def = wevent_pmu_def(dump_hdr, dump_hdr->pmu_def_real_cnt + i);
					wprintf("    %s (derived)\n", wevent_str(dump_hdr, def->name_stroff));
				}
			} else {
				wprintf("%-*s%s\n", w, "PMU counters:", "NONE");
			}

			for (int i = 0; i < ARRAY_SIZE(capture_features); i++) {
				const struct capture_feature *f = &capture_features[i];
				wprintf("%-*s%s\n", w, f->header, (cfg->capture_features & f->cfg_bit) ? "YES" : "NO");
			}

			if (dump_hdr->extra_cnt > 0) {
				bool has_extras = false, has_metadata = false;
				for (u64 i = 0; i < dump_hdr->extra_cnt; i++) {
					struct wprof_extra_param *e = wevent_extra_param(dump_hdr, i);
					if (e->kind == WEXTRA_METADATA)
						has_metadata = true;
					else if (e->kind != WEXTRA_STATS)
						has_extras = true;
				}
				if (env.stats || (cfg->captured_stack_traces & ST_TIMER)) {
					wprintf("%-*s\n", w, "Config:");
					if (env.stats) {
						wprintf("    %-*s%u\n", w - 4, "CPUs:", env.stats->cpu_cnt);
						wprintf("    %-*s%u x %uMB\n", w - 4, "Ringbufs:", env.stats->rb_cnt, env.stats->ringbuf_sz / 1024 / 1024);
						wprintf("    %-*s%u\n", w - 4, "Tasks capacity:", env.stats->task_state_sz);
					}
					if (cfg->captured_stack_traces & ST_TIMER)
						wprintf("    %-*s%dHz\n", w - 4, "Timer frequency:", cfg->timer_freq_hz);
				}
				if (has_metadata) {
					wprintf("%-*s\n", w, "Metadata:");
					for (u64 i = 0; i < dump_hdr->extra_cnt; i++) {
						struct wprof_extra_param *e = wevent_extra_param(dump_hdr, i);
						if (e->kind != WEXTRA_METADATA)
							continue;
						const char *kv = wevent_str(dump_hdr, e->stroff);
						const char *eq = strchr(kv, '=');
						if (eq)
							wprintf("    %.*s = %s\n", (int)(eq - kv), kv, eq + 1);
						else
							wprintf("    %s\n", kv);
					}
				}
				if (has_extras) {
					wprintf("%-*s\n", w, "Extras:");
					for (u64 i = 0; i < dump_hdr->extra_cnt; i++) {
						struct wprof_extra_param *e = wevent_extra_param(dump_hdr, i);
						if (e->kind == WEXTRA_METADATA || e->kind == WEXTRA_STATS)
							continue;
						wprintf("    %s\n", extra_param_str(dump_hdr, e));
					}
				}
			}

			u64 kind_cnt[__EV_KIND_MAX] = {};
			u64 kind_sz[__EV_KIND_MAX] = {};
			struct wevent_record *rec;
			wevent_for_each_event(rec, dump_hdr) {
				if (rec->e->kind) {
					kind_cnt[rec->e->kind]++;
					kind_sz[rec->e->kind] += rec->e->sz;
				}
			}
			wprintf("%-*s%.3lfMB total\n", w, "Data:", worker->dump_sz / MB);
			wprintf("    %-*s%.3lfMB (%llu entries)\n", w - 4, "Thread info:", dump_hdr->threads_sz / MB, dump_hdr->thread_cnt);

			u64 str_cnt = 0;
			for (const char *s = (void *)dump_hdr + sizeof(*dump_hdr) + dump_hdr->strs_off,
					*end = s + dump_hdr->strs_sz;
			     s < end; s++) {
				if (*s == '\0')
					str_cnt++;
			}
			wprintf("    %-*s%.3lfMB (%llu unique strings)\n", w - 4, "Strings:", dump_hdr->strs_sz / MB, str_cnt);
			if (dump_hdr->blobs_sz)
				wprintf("    %-*s%.3lfMB\n", w - 4, "Blobs:", dump_hdr->blobs_sz / MB);

			wprintf("    %-*s%.3lfMB (%llu records)\n", w - 4, "Events:", dump_hdr->events_sz / MB, dump_hdr->event_cnt);
			for (int i = 0; i < __EV_KIND_MAX; i++) {
				if (kind_cnt[i] == 0)
					continue;
				wprintf("        %-*s%.3lfMB (%llu records)\n", w - 8, wevent_kind_name(i), kind_sz[i] / MB, kind_cnt[i]);
			}
			if (cfg->captured_stack_traces) {
				const struct wstack_hdr *shdr = wstack_hdr(dump_hdr);
				wprintf("    %-*s%.3lfMB (%u unique stacks)\n", w - 4, "Stack traces:", dump_hdr->stacks_sz / MB, shdr->stack_cnt);
				wprintf("        %-*s%.3lfMB (%u entries)\n", w - 8, "Call stacks:", shdr->stack_cnt * sizeof(struct wstack_trace) / MB, shdr->stack_cnt);
				wprintf("        %-*s%.3lfMB (%u entries)\n", w - 8, "Frames:", shdr->frame_cnt * sizeof(struct wstack_frame) / MB, shdr->frame_cnt);
				u64 stack_str_cnt = 0;
				for (const char *s = wstack_str(dump_hdr, 0), *end = s + shdr->strs_sz; s < end; s++) {
					if (*s == '\0')
						stack_str_cnt++;
				}
				wprintf("        %-*s%.3lfMB (%llu unique strings)\n", w - 8, "Strings:", shdr->strs_sz / MB, stack_str_cnt);
			}
			if (dump_hdr->pmu_def_real_cnt + dump_hdr->pmu_def_deriv_cnt)
				wprintf("    %-*s%.3lfMB (%llu entries)\n", w - 4, "PMU data:", dump_hdr->pmu_vals_sz / MB, dump_hdr->pmu_val_cnt);
			if (env.stats)
				wprintf("    %-*s%u bytes\n", w - 4, "Stats:", env.stats->sz);

			/*
			 * If --stats is not set, we'll still print all the drops and recursion
			 * misses warnings, just like in normal recording mode.
			 */
			print_stats(env.stats, 0);

			goto cleanup;
		}

		if (env.emit_stats) {
			eprintf("replay: --stats should only be used with --replay-info!\n");
			err = -EINVAL;
			goto cleanup;
		}

		/* handle all the ways to specify time range */
		if (env.duration_ns != 0 && (env.replay_start_offset_ns != 0 || env.replay_end_offset_ns != 0)) {
			eprintf("Time range start/end offsets and duration are mutually exlusive!\n");
			err = -EINVAL;
			goto cleanup;
		}
		/* if unspecified explicitly, derive time range from duration parameter */
		if (env.duration_ns != 0) {
			env.replay_start_offset_ns = 0;
			env.replay_end_offset_ns = env.duration_ns;
		}
		/* if unspecified explicitly, derive replay end from recorded duration */
		if (env.replay_start_offset_ns != 0 && env.replay_end_offset_ns == 0)
			env.replay_end_offset_ns = cfg->duration_ns;
		/* if neither duration nor time range is provided, use recorded time range */
		if (env.replay_start_offset_ns == 0 && env.replay_end_offset_ns == 0) {
			env.replay_start_offset_ns = 0;
			env.replay_end_offset_ns = cfg->duration_ns;
		}
		/* validate requested time range */
		if (env.replay_end_offset_ns <= env.replay_start_offset_ns) {
			eprintf("replay: invalid time range specified: [%.3lfms, %.3lfms)!\n",
				env.replay_start_offset_ns / 1000000.0, env.replay_end_offset_ns / 1000000.0);
			err = -EINVAL;
			goto cleanup;
		}
		if (env.replay_end_offset_ns > cfg->duration_ns) {
			eprintf("replay: requested time range [%.3lfms, %.3lfms) is larger than recorded time range [0ms, %.3lfms)!\n",
				env.replay_start_offset_ns / 1000000.0, env.replay_end_offset_ns / 1000000.0,
				cfg->duration_ns / 1000000.0);
			err = -EINVAL;
			goto cleanup;
		}

		/* setup original (replayed) time markers */
		env.sess_start_ts = cfg->ktime_start_ns + env.replay_start_offset_ns;
		env.sess_end_ts = cfg->ktime_start_ns + env.replay_end_offset_ns;
		set_ktime_off(cfg->ktime_start_ns, cfg->realtime_start_ns);
		env.duration_ns = env.replay_end_offset_ns - env.replay_start_offset_ns;

		env.timer_freq_hz = cfg->timer_freq_hz;
		env.timer_period_ns = 1000000000ULL / env.timer_freq_hz;

		/* validate data capture config compatibility */
		for (int i = 0; i < ARRAY_SIZE(capture_features); i++) {
			const struct capture_feature *f = &capture_features[i];
			enum tristate *flag = (void *)&env + f->env_flag_off;
			bool cfg_flag = !!(cfg->capture_features & f->cfg_bit);

			if (*flag == UNSET)
				*flag = cfg_flag;

			if (*flag == TRUE && !cfg_flag) {
				eprintf("replay: %s requested, but not recorded in data dump!\n", f->name);
				err = -EINVAL;
				goto cleanup;
			}
		}

		if (env.requested_stack_traces == ST_UNSET)
			env.requested_stack_traces = cfg->captured_stack_traces;
		if ((env.requested_stack_traces & cfg->captured_stack_traces) != env.requested_stack_traces) {
			eprintf("replay: some of requested kinds of stack traces were not captured (check --replay-info)!\n");
			err = -EINVAL;
			goto cleanup;
		}

		err = pmu_resolve_replay_defs(dump_hdr);
		if (err)
			goto cleanup;

		/* Restore persisted capture-time filters (additive with CLI filters) */
		for (u64 i = 0; i < dump_hdr->extra_cnt; i++) {
			struct wprof_extra_param *ep = wevent_extra_param(dump_hdr, i);
			const char *val = ep->stroff ? wevent_str(dump_hdr, ep->stroff) : "";

			switch (ep->kind) {
			case WEXTRA_FILTER_PID_ALLOW:
				err = append_num(&env.allow_pids, &env.allow_pid_cnt, val);
				break;
			case WEXTRA_FILTER_PID_DENY:
				err = append_num(&env.deny_pids, &env.deny_pid_cnt, val);
				break;
			case WEXTRA_FILTER_TID_ALLOW:
				err = append_num(&env.allow_tids, &env.allow_tid_cnt, val);
				break;
			case WEXTRA_FILTER_TID_DENY:
				err = append_num(&env.deny_tids, &env.deny_tid_cnt, val);
				break;
			case WEXTRA_FILTER_PNAME_ALLOW:
				err = append_str(&env.allow_pnames, &env.allow_pname_cnt, val);
				break;
			case WEXTRA_FILTER_PNAME_DENY:
				err = append_str(&env.deny_pnames, &env.deny_pname_cnt, val);
				break;
			case WEXTRA_FILTER_TNAME_ALLOW:
				err = append_str(&env.allow_tnames, &env.allow_tname_cnt, val);
				break;
			case WEXTRA_FILTER_TNAME_DENY:
				err = append_str(&env.deny_tnames, &env.deny_tname_cnt, val);
				break;
			case WEXTRA_FILTER_IDLE_ALLOW:
				env.allow_idle = true;
				break;
			case WEXTRA_FILTER_IDLE_DENY:
				env.deny_idle = true;
				break;
			case WEXTRA_FILTER_KTHREAD_ALLOW:
				env.allow_kthread = true;
				break;
			case WEXTRA_FILTER_KTHREAD_DENY:
				env.deny_kthread = true;
				break;
			case WEXTRA_UTRACE_DEF:
				err = utrace_cfg_parse(val);
				break;
			/*
			 * Emit (-e) options keep their CLI value if set, otherwise
			 * inherit the persisted on/off value.
			 */
			case WEXTRA_EMIT_NUMA:
				env.emit_numa = env.emit_numa != UNSET ? env.emit_numa : ep->value;
				break;
			case WEXTRA_EMIT_TIDPID:
				env.emit_tidpid = env.emit_tidpid != UNSET ? env.emit_tidpid : ep->value;
				break;
			case WEXTRA_EMIT_TIMER_TICKS:
				env.emit_timer_ticks = env.emit_timer_ticks != UNSET ? env.emit_timer_ticks : ep->value;
				break;
			case WEXTRA_EMIT_SCHED:
				env.emit_sched_view = env.emit_sched_view != UNSET ? env.emit_sched_view : ep->value;
				break;
			case WEXTRA_EMIT_SCHED_EXTRAS:
				env.emit_sched_extras = env.emit_sched_extras != UNSET ? env.emit_sched_extras : ep->value;
				break;
			case WEXTRA_EMIT_PYSTACKS_ONLY:
				env.emit_pystacks_only = env.emit_pystacks_only != UNSET ? env.emit_pystacks_only : ep->value;
				break;
			case WEXTRA_EMIT_REQ_SPLIT:
				env.emit_req_split = env.emit_req_split != UNSET ? env.emit_req_split : ep->value;
				break;
			case WEXTRA_EMIT_REQ_EMBED:
				env.emit_req_embed = env.emit_req_embed != UNSET ? env.emit_req_embed : ep->value;
				break;
			case WEXTRA_EMIT_EMBED_STACKS:
				env.emit_embed_stacks = env.emit_embed_stacks != UNSET ? env.emit_embed_stacks : ep->value;
				break;
			case WEXTRA_METADATA:
			case WEXTRA_STATS:
			case WEXTRA_PMU:
				break;
			default:
				eprintf("Unrecognized extra param kind %d in data file, skipping\n", ep->kind);
				break;
			}
			if (err)
				goto cleanup;
		}

		/* resolve emit (-e) options not set on the CLI or in the data dump */
		for (int i = 0; i < emit_feature_cnt; i++) {
			const struct emit_feature *f = &emit_features[i];
			enum tristate *flag = (void *)&env + f->env_flag_off;

			if (*flag == UNSET)
				*flag = f->default_val;
		}

		goto skip_data_collection;
	}

	if (env.replay_info) {
		eprintf("Replay information can be printed in replay mode only (specify -R)!\n");
		err = -EINVAL;
		goto cleanup;
	}
	if (env.replay_start_offset_ns || env.replay_end_offset_ns) {
		eprintf("Time range start/end offsets can only be specified in replay mode!\n");
		err = -EINVAL;
		goto cleanup;
	}
	if (env.pmu_unresolved_cnt > 0) {
		for (int i = 0; i < env.pmu_unresolved_cnt; i++)
			eprintf("Failed to resolve PMU counter '%s'!\n", env.pmu_unresolveds[i].name);
		err = -EINVAL;
		goto cleanup;
	}

	/* Init data capture settings defaults, if they were not set */
	if (env.timer_freq_hz == 0)
		env.timer_freq_hz = DEFAULT_TIMER_FREQ_HZ;
	env.timer_period_ns = 1000000000ULL / env.timer_freq_hz;
	if (env.duration_ns == 0)
		env.duration_ns = DEFAULT_DURATION_MS * 1000000ULL;
	if (env.requested_stack_traces == ST_UNSET)
		env.requested_stack_traces = DEFAULT_REQUESTED_STACK_TRACES;
	for (int i = 0; i < ARRAY_SIZE(capture_features); i++) {
		const struct capture_feature *f = &capture_features[i];
		enum tristate *flag = (void *)&env + f->env_flag_off;

		if (*flag == UNSET)
			*flag = f->default_val;
	}
	/* resolve emit (-e) options not set on the CLI */
	for (int i = 0; i < emit_feature_cnt; i++) {
		const struct emit_feature *f = &emit_features[i];
		enum tristate *flag = (void *)&env + f->env_flag_off;

		if (*flag == UNSET)
			*flag = f->default_val;
	}

	/* create workdir specific to this wprof run */
	struct timespec ts_now;
	struct tm *tm_now;
	char tm_str[32];
	char *data_path_copy = strdup(env.data_path);
	char *data_dir = dirname(data_path_copy);
	clock_gettime(CLOCK_REALTIME, &ts_now);
	tm_now = localtime(&ts_now.tv_sec);
	strftime(tm_str, sizeof(tm_str), "%Y-%m-%d_%H%M%S", tm_now);
	snprintf(workdir_name, sizeof(workdir_name), "%s/wprof-session.%d.%s.%06ld",
		 data_dir, getpid(), tm_str, ts_now.tv_nsec / 1000);
	free(data_path_copy);

	if (mkdir(workdir_name, 0755) < 0) {
		err = -errno;
		eprintf("Failed to create session workdir '%s': %d\n", workdir_name, err);
		goto cleanup;
	}
	workdir_fd = open(workdir_name, O_DIRECTORY | O_RDONLY);
	if (workdir_fd < 0) {
		err = -errno;
		eprintf("Failed to open() session workdir at '%s': %d\n", workdir_name, err);
		goto cleanup;
	}
	if (fchmod(workdir_fd, 0777) < 0) {
		err = -errno;
		eprintf("Failed to chmod(0777) session workdir at '%s': %d\n", workdir_name, err);
		goto cleanup;
	}

	for (int i = 0; i < env.ringbuf_cnt; i++) {
		struct worker_state *worker = &workers[i];

		char dump_path[PATH_MAX];
		snprintf(dump_path, sizeof(dump_path), "%s/bpf-rb.%03d.data", workdir_name, i);
		worker->dump_path = strdup(dump_path);
		worker->dump = fopen_buffered(dump_path, "w+");
		if (!worker->dump) {
			err = -errno;
			eprintf("Failed to create data dump at '%s': %d\n", dump_path, err);
			goto cleanup;
		}
		err = wprof_init_data(worker->dump);
		if (err) {
			eprintf("Failed to initialize ringbuf dump #%d at '%s': %d\n", i, dump_path, err);
			fclose(worker->dump);
			return err;
		}
	}

	err = pmu_resolve_derived(env.pmu_reals, env.pmu_real_cnt, env.pmu_derivs, env.pmu_deriv_cnt);
	if (err) {
		eprintf("Failed to resolve derived PMU definitions: %d\n", err);
		goto cleanup;
	}

	/*
	 * Session control loop: a single epoll multiplexes the various
	 * asynchronous sources of control-state transitions (the timerfds and the
	 * signal eventfd) into one place.
	 */
	env.sess_ctl.state = SESS_STANDBY;

	env.sess_ctl.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (env.sess_ctl.epoll_fd < 0) {
		err = -errno;
		eprintf("Failed to create session control epoll: %d\n", err);
		goto cleanup;
	}

	env.sess_ctl.prep_tfd     = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	env.sess_ctl.activate_tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	env.sess_ctl.sess_end_tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	if (env.sess_ctl.prep_tfd < 0 || env.sess_ctl.activate_tfd < 0 || env.sess_ctl.sess_end_tfd < 0) {
		err = -errno;
		eprintf("Failed to create session timerfds: %d\n", err);
		goto cleanup;
	}

	env.sess_ctl.sig_efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (env.sess_ctl.sig_efd < 0) {
		err = -errno;
		eprintf("Failed to create session signal eventfd: %d\n", err);
		goto cleanup;
	}

	if (ctl_epoll_add(env.sess_ctl.epoll_fd, env.sess_ctl.prep_tfd, CTL_PREP_TIMER) ||
	    ctl_epoll_add(env.sess_ctl.epoll_fd, env.sess_ctl.activate_tfd, CTL_ACTIVATE_TIMER) ||
	    ctl_epoll_add(env.sess_ctl.epoll_fd, env.sess_ctl.sess_end_tfd, CTL_END_TIMER) ||
	    ctl_epoll_add(env.sess_ctl.epoll_fd, env.sess_ctl.sig_efd, CTL_SIGNAL)) {
		err = -errno;
		eprintf("Failed to register session control fds: %d\n", err);
		goto cleanup;
	}

	/*
	 * Resolve --prepare/--activate wall-clock specs into absolute ktime
	 * targets; a zero target means "immediately" (prepare at startup, activate
	 * as soon as prepare finishes).
	 */
	if (env.prepare_spec.kind) {
		env.sess_ctl.prepare_target_ts = resolve_timespec(&env.prepare_spec, env.actual_start_ts);
		if (ts_before(env.sess_ctl.prepare_target_ts, ktime_now_ns())) {
			eprintf("Preparation time (--prepare) is in the past!\n");
			err = -EINVAL;
			goto cleanup;
		}
	}
	if (env.activate_spec.kind) {
		env.sess_ctl.activate_target_ts = resolve_timespec(&env.activate_spec, env.actual_start_ts);
		if (ts_before(env.sess_ctl.activate_target_ts, ktime_now_ns())) {
			eprintf("Activation time (--activate) is in the past!\n");
			err = -EINVAL;
			goto cleanup;
		}
	}
	if (env.sess_ctl.prepare_target_ts && env.sess_ctl.activate_target_ts &&
	    ts_before(env.sess_ctl.activate_target_ts, env.sess_ctl.prepare_target_ts)) {
		eprintf("Activation time (--activate) is before preparation time (--prepare)!\n");
		err = -EINVAL;
		goto cleanup;
	}

	arm_timer_abs(env.sess_ctl.prep_tfd, env.sess_ctl.prepare_target_ts ?: ktime_now_ns());
	if (env.prepare_spec.kind)
		wprintf("Pending preparation trigger...\n");

	while (env.sess_ctl.state != SESS_DONE) {
		struct epoll_event evs[8];
		int n = epoll_wait(env.sess_ctl.epoll_fd, evs, ARRAY_SIZE(evs), -1);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			err = -errno;
			eprintf("Session control epoll_wait() failed: %d\n", err);
			goto cleanup;
		}

		for (int i = 0; i < n && env.sess_ctl.state != SESS_DONE; i++) {
			switch (evs[i].data.u32) {
			case CTL_SIGNAL:
				drain_fd(env.sess_ctl.sig_efd);
				env.sess_ctl.state = SESS_DONE;
				break;
			case CTL_PREP_TIMER:
				drain_fd(env.sess_ctl.prep_tfd);
				env.sess_ctl.state = SESS_PREP;
				err = do_prepare(&bpf_state, workers, num_cpus, workdir_fd);
				if (err)
					goto cleanup;
				env.sess_ctl.state = SESS_ARMED;
				if (env.sess_ctl.activate_target_ts &&
				    ts_before(env.sess_ctl.activate_target_ts, ktime_now_ns())) {
					eprintf("Activation time (--activate) already passed during preparation!\n");
					err = -EINVAL;
					goto cleanup;
				}
				arm_timer_abs(env.sess_ctl.activate_tfd, env.sess_ctl.activate_target_ts ?: ktime_now_ns());
				if (env.activate_spec.kind)
					wprintf("Pending activation trigger...\n");
				break;
			case CTL_ACTIVATE_TIMER:
				drain_fd(env.sess_ctl.activate_tfd);
				err = do_activate(&bpf_state);
				if (err)
					goto cleanup;
				env.sess_ctl.session_activated = true;
				env.sess_ctl.sess_end_target_ts = env.sess_end_ts;
				env.sess_ctl.state = SESS_RECORDING;
				arm_timer_abs(env.sess_ctl.sess_end_tfd, env.sess_ctl.sess_end_target_ts);
				break;
			case CTL_END_TIMER:
				drain_fd(env.sess_ctl.sess_end_tfd);
				env.sess_ctl.session_complete = true;
				env.sess_ctl.state = SESS_DONE;
				break;
			}
		}
	}

	exiting = true; /* tell ringbuf worker threads to stop */
	err = wait_bpf(&bpf_state); /* join ringbuf worker threads */
	if (err) {
		eprintf("Failed during collecting BPF-generated data: %d\n", err);
		goto cleanup;
	}

	if (!env.sess_ctl.session_activated) {
		/* interrupted before recording started: unclean exit, nothing to persist */
		err = -EINTR;
		goto cleanup;
	}

	/*
	 * If the session was cut short (signal) rather than reaching its planned
	 * end, clamp the recorded window to now. This is the point past which the
	 * various data sources (BPF ringbufs, CUDA/pytrace tracee dumps) are torn
	 * down at staggered times and can no longer be considered mutually
	 * consistent. When the session-end timerfd fires it signals the planned
	 * end, which already carries the correct session end.
	 */
	if (!env.sess_ctl.session_complete) {
		env.sess_end_ts = ktime_now_ns();
		env.duration_ns = env.sess_end_ts - env.sess_start_ts;
	}

	wprintf("Stopping...\n");
	detach_bpf(&bpf_state, num_cpus);

	if (env.cuda_cnt > 0) {
		cuda_trace_deactivate();
		/*
		 * If we capture CUDA stack traces, we want libwprofinj.so to be loaded during
		 * stack symbolization, so we'll perform final retraction later.
		 */
		if (!(env.requested_stack_traces & ST_CUDA))
			cuda_trace_retract();
	}

	if (env.py_cnt > 0)
		pytrace_trace_deactivate();

	wprintf("Draining...\n");
	drain_bpf(&bpf_state, num_cpus);

	if (env.capture_pystacks && bpf_state.skel) {
		err = pysym_init(bpf_map__fd(bpf_state.skel->maps.pystacks_symbols),
				 bpf_map__fd(bpf_state.skel->maps.pystacks_linetables));
		if (err) {
			eprintf("Failed to initialize Python symbol table: %d\n", err);
			goto cleanup;
		}
	}

	if (env.cuda_cnt == 0) {
		/* ensure we don't record CUDA data as available in wprof.data */
		env.requested_stack_traces &= ~ST_CUDA;
		env.capture_cuda = false;
	}

	if (env.py_cnt == 0) {
		env.capture_pytrace = false;
		env.capture_pytorch = false;
	}

	err = wprof_persist_data(workdir_name, workers);
	if (err) {
		eprintf("Failed to finalize data dump: %d\n", err);
		goto cleanup;
	}

	pysym_free();

	/* we delayed ptrace retraction to symbolize libwprofinj.so stacks */
	if (env.requested_stack_traces && env.cuda_cnt > 0)
		cuda_trace_retract();

	if (env.py_cnt > 0)
		pytrace_trace_retract();

	{
		fflush(workers[0].dump);
		if (fchmod(fileno(workers[0].dump), 0644)) {
			err = -errno;
			eprintf("Failed to chmod() data file '%s': %d\n", env.data_path, err);
			goto cleanup;
		}
		ssize_t file_sz = file_size(workers[0].dump);
		wprintf("Produced %.3lfMB data file at '%s'.\n",
			file_sz / (1024.0 * 1024.0), env.data_path);
	}

skip_data_collection:
	if (env.req_list) {
		err = req_list_output(&workers[0]);
		if (err)
			goto cleanup;
	}

	const char *output_path = env.trace_path ?: env.json_path;
	if (output_path) {
		struct worker_state *w = &workers[0];

		if (env.req_list_cfg && env.req_list_cfg->filter_cnt > 0) {
			err = req_filter_build_allowlist(w, &w->req_allowlist);
			if (err)
				goto cleanup;
		}

		if (strcmp(output_path, "-") == 0) {
			w->trace = stdout;
			signal(SIGPIPE, SIG_IGN);
		} else {
			w->trace = fopen_buffered(output_path, "w+");
			if (!w->trace) {
				err = -errno;
				eprintf("Failed to create trace file '%s': %d\n", output_path, err);
				goto cleanup;
			}
		}

		if (!env.json_path) {
			w->wpb_writer = wpb_writer_new(wpb_stream_write, w->trace);
		}

		err = init_emit(w);
		if (err) {
			eprintf("Failed to init trace emitting logic: %d\n", err);
			goto cleanup;
		}

		if (!env.json_path) {
			if (init_pb_trace(w->wpb_writer, w->dump_hdr)) {
				err = -1;
				eprintf("Failed to init protobuf!\n");
				goto cleanup;
			}
		}

		/* process dumped events, and generate trace */
		err = emit_trace(w);
		if (err) {
			eprintf("Failed to generate trace: %d\n", err);
			goto cleanup;
		}

		fflush(w->trace);
		if (w->trace != stdout) {
			ssize_t file_sz = file_size(w->trace);
			wprintf("Produced %.3lfMB trace file at '%s'.\n",
				file_sz / (1024.0 * 1024.0), output_path);
		}
	}
	print_stats(env.stats, err);

cleanup:
	if (env.cuda_cnt > 0)
		cuda_trace_teardown();
	if (env.py_cnt > 0)
		pytrace_trace_teardown();
	cleanup_workers(workers, worker_cnt);
	detach_bpf(&bpf_state, num_cpus);
	drain_bpf(&bpf_state, num_cpus);
	cleanup_bpf(&bpf_state);
	if (workdir_fd >= 0)
		close(workdir_fd);
	if (!env.keep_workdir && workdir_name[0])
		delete_dir(workdir_name);
	wprintf("Exited %s (after %.3lfs).\n",
		err ? "with errors" : "cleanly",
		(ktime_now_ns() - env.actual_start_ts) / 1000000000.0);
	return -err;
}
