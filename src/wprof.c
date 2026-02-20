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
#include "bpf_utils.h"
#include "sys.h"
#include "inject.h"
#include "inj_common.h"
#include "merge.h"
#include "../libbpf/src/strset.h"

static bool ignore_libbpf_warns;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !(env.log_set & LOG_LIBBPF))
		return 0;
	if (ignore_libbpf_warns)
		return 0;
	return vfprintf(stderr, format, args);
}

const struct capture_feature capture_features[] = {
	{"IPIs", "IPIs:", DEFAULT_CAPTURE_IPIS,
	 offsetof(struct env, capture_ipis), cfg_get_capture_ipis, cfg_set_capture_ipis},
	{"requests", "Requests:", DEFAULT_CAPTURE_REQUESTS,
	 offsetof(struct env, capture_requests), cfg_get_capture_reqs, cfg_set_capture_reqs},
	{"request experimental extras", "Requests (experimental):", FALSE,
	 offsetof(struct env, capture_req_experimental), cfg_get_capture_req_experimental, cfg_set_capture_req_experimental},
	{"sched-ext info", "SCX info:", DEFAULT_CAPTURE_SCX,
	  offsetof(struct env, capture_scx),
	  cfg_get_capture_scx, cfg_set_capture_scx},
	{"CUDA", "CUDA:", DEFAULT_CAPTURE_CUDA,
	 offsetof(struct env, capture_cuda), cfg_get_capture_cuda, cfg_set_capture_cuda},
};

const int capture_feature_cnt = ARRAY_SIZE(capture_features);

static volatile bool exiting;

static void sig_timer(int sig)
{
	exiting = true;
}

static void sig_term(int sig)
{
	exiting = true;
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

	if (fwrite(&size, sizeof(size), 1, w->dump) != 1 ||
	    fwrite(data, size, 1, w->dump) != 1) {
		int err = -errno;

		eprintf("Failed to write raw data dump: %d\n", err);
		return err;
	}

	w->rb_handled_cnt++;
	w->rb_handled_sz += size;

	return 0;
}

static void print_exit_summary(struct worker_state *workers, int worker_cnt,
			       struct wprof_bpf *skel, int num_cpus, int exit_code)
{
	int err;
	u64 rb_handled_cnt = 0;
	u64 rb_handled_sz = 0;
	struct wprof_stats stats_by_cpu[num_cpus];
	struct wprof_stats stats_by_rb[env.ringbuf_cnt];
	struct wprof_stats s = {};
	double dur_s = env.duration_ns / 1000000000.0;

	memset(&stats_by_cpu, 0, sizeof(stats_by_cpu));
	memset(&stats_by_rb, 0, sizeof(stats_by_rb));

	if (!skel)
		goto skip_prog_stats;

	if (env.stats)
		wprintf("BPF program stats:\n");

	struct bpf_program *prog;
	u64 total_run_cnt = 0, total_run_ns = 0;
	bpf_object__for_each_program(prog, skel->obj) {
		struct bpf_prog_info info;
		u32 info_sz = sizeof(info);

		if (bpf_program__fd(prog) < 0) /* optional inactive program */
			continue;

		memset(&info, 0, sizeof(info));
		err = bpf_prog_get_info_by_fd(bpf_program__fd(prog), &info, &info_sz);
		if (err) {
			eprintf("!!! %s: failed to fetch prog info: %d\n",
				bpf_program__name(prog), err);
			continue;
		}

		if (info.recursion_misses) {
			eprintf("!!! %s: %llu recursion misses!\n",
				bpf_program__name(prog), info.recursion_misses);
		}

		if (env.stats) {
			wprintf("\t%s%-*s %8llu (%6.0lf/CPU/s) runs for total of %.3lfms (%.3lfms/CPU/s).\n",
				bpf_program__name(prog),
				(int)max(1UL, 24 - strlen(bpf_program__name(prog))), ":",
				info.run_cnt,
				info.run_cnt / num_cpus / dur_s,
				info.run_time_ns / 1000000.0,
				info.run_time_ns / 1000000.0 / num_cpus / dur_s);
			total_run_cnt += info.run_cnt;
			total_run_ns += info.run_time_ns;
		}
	}

	if (env.stats) {
		wprintf("\t%-24s %8llu (%6.0lf/CPU/s) runs for total of %.3lfms (%.3lfms/CPU/s).\n",
			"TOTAL:", total_run_cnt,
			total_run_cnt / num_cpus / dur_s,
			total_run_ns / 1000000.0,
			total_run_ns / 1000000.0 / num_cpus / dur_s);
	}

skip_prog_stats:
	if (!skel || bpf_map__fd(skel->maps.stats) < 0)
		goto skip_rb_stats;

	if (env.stats)
		wprintf("Data procesing stats:\n");

	for (int i = 0; i < worker_cnt; i++) {
		struct worker_state *w = &workers[i];
		rb_handled_cnt += w->rb_handled_cnt;
		rb_handled_sz += w->rb_handled_sz;
	}

	int zero = 0;
	err = bpf_map__lookup_elem(skel->maps.stats, &zero, sizeof(int),
				   stats_by_cpu, sizeof(stats_by_cpu[0]) * num_cpus, 0);
	if (err) {
		eprintf("Failed to fetch BPF-side stats: %d\n", err);
		goto skip_rb_stats;
	}

	for (int i = 0; i < num_cpus; i++) {
		s.task_state_drops += stats_by_cpu[i].task_state_drops;
		s.req_state_drops += stats_by_cpu[i].req_state_drops;

		s.rb_rescues += stats_by_cpu[i].rb_rescues;
		s.rb_misses += stats_by_cpu[i].rb_misses;
		s.rb_drops += stats_by_cpu[i].rb_drops;

		int rb_id = skel->data_rb_cpu_map->rb_cpu_map[i];
		stats_by_rb[rb_id].rb_rescues += stats_by_cpu[i].rb_rescues;
		stats_by_rb[rb_id].rb_drops += stats_by_cpu[i].rb_drops;
		stats_by_rb[rb_id].rb_misses += stats_by_cpu[i].rb_misses;
	}

	if (env.stats) {
		for (int i = 0; i < env.ringbuf_cnt; i++) {
			struct worker_state *w = &workers[i];

			char rb_name[32];
			snprintf(rb_name, sizeof(rb_name), "RB #%d:", i);

			wprintf("\t%-8s %8llu (%.3lf%%) records (%.3lfMB, %.3lfMB/s) processed, %llu rescued (%.3lf%%), %llu dropped (%.3lf%%).\n",
				rb_name,
				w->rb_handled_cnt, w->rb_handled_cnt * 100.0 / (w->rb_handled_cnt + stats_by_rb[i].rb_drops),
				w->rb_handled_sz / 1024.0 / 1024.0, w->rb_handled_sz / 1024.0 / 1024.0 / dur_s,
				stats_by_rb[i].rb_rescues, stats_by_rb[i].rb_rescues * 100.0 / (w->rb_handled_cnt + stats_by_rb[i].rb_drops),
				stats_by_rb[i].rb_drops, stats_by_rb[i].rb_drops * 100.0 / (w->rb_handled_cnt + stats_by_rb[i].rb_drops));
		}
		wprintf("\t%-8s %8llu (%.3lf%%) records (%.3lfMB, %.3lfMB/s, %.3lfMB/RB/s) processed, %llu rescued (%.3lf%%), %llu dropped (%.3lf%%).\n",
			"TOTAL:",
			rb_handled_cnt, rb_handled_cnt * 100.0 / (rb_handled_cnt + s.rb_drops),
			rb_handled_sz / 1024.0 / 1024.0, rb_handled_sz / 1024.0 / 1024.0 / dur_s,
			rb_handled_sz / 1024.0 / 1024.0 / dur_s / env.ringbuf_cnt,
			s.rb_rescues, s.rb_rescues * 100.0 / (rb_handled_cnt + s.rb_drops),
			s.rb_drops, s.rb_drops * 100.0 / (rb_handled_cnt + s.rb_drops));
	}

skip_rb_stats:
	if (!env.stats)
		goto skip_rusage;

	struct rusage ru;
	if (getrusage(RUSAGE_SELF, &ru)) {
		eprintf("Failed to get wprof's resource usage data!..\n");
		goto skip_rusage;
	}

	wprintf("wprof's own resource usage:\n");
	wprintf("\tCPU time (user/system, s):\t\t%.3lf/%.3lf\n",	ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1000000.0,
									ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1000000.0);
	wprintf("\tMemory (max RSS, MB):\t\t\t%.3lf\n", 		ru.ru_maxrss / 1024.0);
	wprintf("\tPage faults (maj/min, K)\t\t%.3lf/%.3lf\n", 		ru.ru_majflt / 1000.0, ru.ru_minflt / 1000.0);
	wprintf("\tBlock I/Os (K):\t\t\t\t%.3lf/%.3lf\n", 		ru.ru_inblock / 1000.0, ru.ru_oublock / 1000.0);
	wprintf("\tContext switches (vol/invol, K):\t%.3lf/%.3lf\n", 	ru.ru_nvcsw / 1000.0, ru.ru_nivcsw / 1000.0);

skip_rusage:
	for (int i = 0; i < env.cuda_cnt; i++) {
		struct cuda_tracee *cuda = &env.cudas[i];

		if (cuda->state == TRACEE_IGNORED)
			continue;

		if (cuda->state != TRACEE_INACTIVE) {
			eprintf("!!! CUDA tracee #%d (%s) encountered problem. Last state: %s\n",
				i, cuda_str(cuda), cuda_tracee_state_str(cuda->state));
			continue;
		}

		if (cuda->ctx->cupti_err_cnt + cuda->ctx->cupti_drop_cnt > 0) {
			eprintf("!!! CUDA tracee #%d (%s): %ld records dropped, %ld errors.\n",
				i, cuda_str(cuda),
				cuda->ctx->cupti_drop_cnt, cuda->ctx->cupti_err_cnt);
		}
		if (env.verbose || env.stats) {
			eprintf("CUDA tracee #%d (%s): %ld records (%ld ignored), %ld buffers, %.3lfMBs.\n",
				i, cuda_str(cuda),
				cuda->ctx->cupti_rec_cnt, cuda->ctx->cupti_ignore_cnt,
				cuda->ctx->cupti_buf_cnt, cuda->ctx->cupti_data_sz / 1024.0 / 1024.0);
		}
	}

	if (s.rb_misses)
		eprintf("!!! Ringbuf fetch misses: %llu\n", s.rb_misses);
	if (s.rb_drops) {
		for (int i = 0; i < num_cpus; i++) {
			if (stats_by_cpu[i].rb_drops == 0)
				continue;

			eprintf("!!! Drops (CPU #%d): %llu (%.3lf%% handled, %.3lf%% rescued, %.3lf%% dropped)\n",
				i, stats_by_cpu[i].rb_drops,
				stats_by_cpu[i].rb_handled * 100.0 / (stats_by_cpu[i].rb_handled + stats_by_cpu[i].rb_drops),
				stats_by_cpu[i].rb_rescues * 100.0 / (stats_by_cpu[i].rb_handled + stats_by_cpu[i].rb_drops),
				stats_by_cpu[i].rb_drops * 100.0 / (stats_by_cpu[i].rb_handled + stats_by_cpu[i].rb_drops));
		}
		for (int i = 0; i < env.ringbuf_cnt; i++) {
			if (stats_by_rb[i].rb_drops == 0)
				continue;

			struct worker_state *w = &workers[i];
			eprintf("!!! Drops (RB #%d): %llu (%.3lf%% handled, %.3lf%% rescued, %.3lf%% dropped)\n",
				i, stats_by_rb[i].rb_drops,
				w->rb_handled_cnt * 100.0 / (w->rb_handled_cnt + stats_by_rb[i].rb_drops),
				stats_by_rb[i].rb_rescues * 100.0 / (w->rb_handled_cnt + stats_by_rb[i].rb_drops),
				stats_by_rb[i].rb_drops * 100.0 / (w->rb_handled_cnt + stats_by_rb[i].rb_drops));
		}
		eprintf("!!! Drops (TOTAL): %llu (%.3lf%% handled, %.3lf%% rescued, %.3lf%% dropped)\n",
			s.rb_drops,
			rb_handled_cnt * 100.0 / (rb_handled_cnt + s.rb_drops),
			s.rb_rescues * 100.0 / (rb_handled_cnt + s.rb_drops),
			s.rb_drops * 100.0 / (rb_handled_cnt + s.rb_drops));
	}
	if (s.task_state_drops)
		eprintf("!!! Task state drops: %llu\n", s.task_state_drops);
	if (s.req_state_drops)
		eprintf("!!! Request state drops: %llu\n", s.req_state_drops);

	wprintf("Exited %s (after %.3lfs).\n",
		exit_code ? "with errors" : "cleanly",
		(ktime_now_ns() - env.actual_start_ts) / 1000000000.0);
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

#ifndef __x86_64__
	if (env.capture_ipis) {
		eprintf("IPI capture is supported only on x86-64 architecture!\n");
		return -EOPNOTSUPP;
	}
#endif /* __x86_64 */

	libbpf_set_print(libbpf_print_fn);

	err = parse_cpu_mask(online_cpus_file, &st->online_mask, &st->num_online_cpus);
	if (err) {
		eprintf("Failed to get online CPU numbers: %d\n", err);
		return -EINVAL;
	}

	calibrate_ktime();

	st->skel = skel = wprof_bpf__open();
	if (!skel) {
		err = -errno;
		eprintf("Failed to open and load BPF skeleton: %d\n", err);
		return err;
	}

#ifdef __x86_64__
	if (env.capture_ipis) {
		bpf_program__set_autoload(skel->progs.wprof_ipi_send_cpu, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_send_mask, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_single_entry, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_single_exit, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_multi_entry, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_multi_exit, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_resched_entry, true);
		bpf_program__set_autoload(skel->progs.wprof_ipi_resched_exit, true);
	}
#endif

	if (env.req_pid_cnt > 0 || env.req_path_cnt > 0 || env.req_global_discovery) {
		err = setup_req_tracking_discovery();
		if (err) {
			eprintf("Request tracking discovery step failed: %d\n", err);
			return err;
		}
	}

	if (env.req_binaries) {
		bpf_program__set_autoload(skel->progs.wprof_req_ctx, true);
		if (env.capture_req_experimental) {
			bpf_program__set_autoload(skel->progs.wprof_req_task_enqueue, true);
			bpf_program__set_autoload(skel->progs.wprof_req_task_dequeue, true);
			bpf_program__set_autoload(skel->progs.wprof_req_task_stats, true);
		}
		bpf_map__set_max_entries(skel->maps.req_states, max(16 * 1024, env.task_state_sz));
	} else {
		bpf_map__set_autocreate(skel->maps.req_states, false);
		env.capture_requests = false;
		env.capture_req_experimental = false;
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

	if (env.capture_scx) {
		struct btf *vmlinux_btf = btf__parse("/sys/kernel/btf/vmlinux", NULL);

		if (!vmlinux_btf) {
			eprintf("Failed to parse /sys/kernel/btf/vmlinux, disabling SCX layer/DSQ capture\n");
			env.capture_scx = FALSE;
		} else {
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
			btf__free(vmlinux_btf);
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

	 /* force RB notification when at least 2.0MB or 25% of ringbuf (whichever is less) is full */
	skel->rodata->rb_submit_threshold_bytes = min(2 * 1024 * 1024, env.ringbuf_sz / 4);

	if (env.stats) {
		st->stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
		if (st->stats_fd < 0)
			eprintf("Failed to enable BPF run stats tracking: %d!\n", st->stats_fd);
	}

	err = wprof_bpf__load(skel);
	if (err) {
		eprintf("Failed to load BPF skeleton: %d\n", err);
		return err;
	}

	st->rb_map_fds = calloc(env.ringbuf_cnt, sizeof(*st->rb_map_fds));
	for (int i = 0; i < env.ringbuf_cnt; i++) {
		int map_fd;

		map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, sfmt("wprof_rb_%d", i), 0, 0, env.ringbuf_sz, NULL);
		if (map_fd < 0) {
			eprintf("Failed to create BPF ringbuf #%d: %d\n", i, map_fd);
			return map_fd;
		}

		err = bpf_map_update_elem(bpf_map__fd(skel->maps.rbs), &i, &map_fd, BPF_NOEXIST);
		if (err < 0) {
			eprintf("Failed to set BPF ringbuf #%d into ringbuf map-of-maps: %d\n", i, err);
			close(map_fd);
			return err;
		}

		st->rb_map_fds[i] = map_fd;
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

	/* given we don't know for sure if requested binary
	 * does have our USDT, we just silence libbpf's
	 * warning and move on if there is an error
	 */
	ignore_libbpf_warns = true;
	link = bpf_program__attach_usdt(prog, -1, binary_attach_path,
					usdt_provider, usdt_name,
					NULL);
	ignore_libbpf_warns = false;
	if (!link) {
		dlogf(USDT, 2, "Failed to attach USDT %s:%s to %s (%s), ignoring...\n",
		      usdt_provider, usdt_name, binary_path, binary_attach_path);
		return -ENOENT;
	} else {
		dlogf(USDT, 1, "Attached USDT %s:%s to %s (%s).\n",
			usdt_provider, usdt_name, binary_path, binary_attach_path);
	}

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

static int run_bpf(struct bpf_state *st)
{
	st->skel->bss->session_start_ts = env.sess_start_ts;
	st->skel->bss->session_end_ts = env.sess_end_ts;

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
	if (st->perf_timer_fds) {
		for (int i = 0; i < num_cpus; i++) {
			if (st->perf_timer_fds[i] >= 0)
				close(st->perf_timer_fds[i]);
		}
		free(st->perf_timer_fds);
	}
	if (st->perf_counter_fds) {
		for (int i = 0; i < st->perf_counter_fd_cnt; i++) {
			if (st->perf_counter_fds[i] >= 0) {
				(void)ioctl(st->perf_counter_fds[i], PERF_EVENT_IOC_DISABLE, 0);
				close(st->perf_counter_fds[i]);
			}
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

		if (w->trace)
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

		w->dump_mem = NULL;
		w->dump = NULL;
	}
}

int main(int argc, char **argv)
{
	struct bpf_state bpf_state = {};
	int num_cpus = 0, err = 0;
	struct itimerval timer_ival = {};
	int worker_cnt = 0;
	struct worker_state *workers = NULL;
	char workdir_name[PATH_MAX] = {};
	int workdir_fd = -1;

	env.actual_start_ts = ktime_now_ns();

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) {
		err = -1;
		goto cleanup;
	}

	vprintf("wprof v%s (PID %d) started!\n", WPROF_VERSION, getpid());

	num_cpus = libbpf_num_possible_cpus();
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

		if (env.replay_info) {
			const int w = 26;
			const double MB = 1024.0 * 1024.0;
			const double S = 1000000000.0;
			const double ms = 1000000.0;

			wprintf("Replay info:\n");
			wprintf("============\n");
			wprintf("%-*s%u.%u\n", w, "Data version:", dump_hdr->version_major, dump_hdr->version_minor);
			wprintf("%-*s%.3lfs (%.3lfms)\n", w, "Duration:", cfg->duration_ns / S, cfg->duration_ns / ms);
			if (cfg->captured_stack_traces) {
				wprintf("%-*s\n", w, "Stack traces:");
				if (cfg->captured_stack_traces & ST_TIMER)
					wprintf("%-*s%s\n", w, "", "timer");
				if (cfg->captured_stack_traces & ST_OFFCPU)
					wprintf("%-*s%s\n", w,"",  "offcpu");
				if (cfg->captured_stack_traces & ST_WAKER)
					wprintf("%-*s%s\n", w, "", "waker");
				if (cfg->captured_stack_traces & ST_CUDA)
					wprintf("%-*s%s\n", w, "", "cuda");

			} else {
				wprintf("%-*s%s\n", w, "Stack traces:", "NONE");
			}
			if (cfg->captured_stack_traces & ST_TIMER)
				wprintf("%-*s%dHz\n", w, "Timer frequency:", cfg->timer_freq_hz);

			if (dump_hdr->pmu_def_real_cnt + dump_hdr->pmu_def_deriv_cnt) {
				wprintf("%-*s\n", w, "PMU counters:");
				for (int i = 0; i < dump_hdr->pmu_def_real_cnt; i++) {
					struct wevent_pmu_def *def = wevent_pmu_def(dump_hdr, i);
					wprintf("%-*s%s\n", w, "", wevent_str(dump_hdr, def->name_stroff));
				}
				for (int i = 0; i < dump_hdr->pmu_def_deriv_cnt; i++) {
					struct wevent_pmu_def *def = wevent_pmu_def(dump_hdr, dump_hdr->pmu_def_real_cnt + i);
					wprintf("%-*s%s (derived)\n", w, "", wevent_str(dump_hdr, def->name_stroff));
				}
			} else {
				wprintf("%-*s%s\n", w, "PMU counters:", "NONE");
			}

			for (int i = 0; i < ARRAY_SIZE(capture_features); i++) {
				const struct capture_feature *f = &capture_features[i];
				wprintf("%-*s%s\n", w, f->header, f->cfg_get_flag(cfg) ? "YES" : "NO");
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

			wprintf("    %-*s%.3lfMB (%llu records)\n", w - 4, "Events:", dump_hdr->events_sz / MB, dump_hdr->event_cnt);
			for (int i = 0; i < __EV_KIND_MAX; i++) {
				if (kind_cnt[i] == 0)
					continue;
				wprintf("        %-*s%.3lfMB (%llu records)\n", w - 8, wevent_kind_name(i), kind_sz[i] / MB, kind_cnt[i]);
			}
			if (cfg->captured_stack_traces) {
				const struct wprof_stacks_hdr *shdr = wprof_stacks_hdr(dump_hdr);
				wprintf("    %-*s%.3lfMB (%u unique stacks)\n", w - 4, "Stack traces:", dump_hdr->stacks_sz / MB, shdr->stack_cnt);
				wprintf("        %-*s%.3lfMB (%u entries)\n", w - 8, "Call stacks:", shdr->stack_cnt * sizeof(struct wprof_stack_trace) / MB, shdr->stack_cnt);
				wprintf("        %-*s%.3lfMB (%u entries)\n", w - 8, "Frames:", shdr->frame_cnt * sizeof(struct wprof_stack_frame) / MB, shdr->frame_cnt);
				wprintf("        %-*s%.3lfMB\n", w - 8, "Strings:", shdr->strs_sz / MB);
			}
			if (dump_hdr->pmu_def_real_cnt + dump_hdr->pmu_def_deriv_cnt)
				wprintf("    %-*s%.3lfMB (%llu entries)\n", w - 4, "PMU data:", dump_hdr->pmu_vals_sz / MB, dump_hdr->pmu_val_cnt);

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

		env.timer_freq_hz = cfg->timer_freq_hz;

		/* validate data capture config compatibility */
		for (int i = 0; i < ARRAY_SIZE(capture_features); i++) {
			const struct capture_feature *f = &capture_features[i];
			enum tristate *flag = (void *)&env + f->env_flag_off;
			bool cfg_flag = f->cfg_get_flag(cfg);

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
		eprintf("Unresolved PMU counters are only valid in replay mode (check -RI for a list)!\n");
		err = -EINVAL;
		goto cleanup;
	}

	/* Init data capture settings defaults, if they were not set */
	if (env.timer_freq_hz == 0)
		env.timer_freq_hz = DEFAULT_TIMER_FREQ_HZ;
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

	err = setup_bpf(&bpf_state, workers, num_cpus, workdir_fd);
	if (err) {
		eprintf("Failed to setup BPF parts: %d\n", err);
		goto cleanup;
	}

	err = attach_bpf(&bpf_state, workers, num_cpus);
	if (err) {
		eprintf("Failed to attach BPF parts: %d\n", err);
		goto cleanup;
	}

	if (env.cuda_cnt > 0) {
		wprintf("Preparing CUDA tracees...\n");
		/* give 2 seconds extra time for auto-timeout within tracee */
		err = cuda_trace_prepare(workdir_fd,
					 env.duration_ns / 1000000 + LIBWPROFINJ_SESSION_TIMEOUT_MS);
		if (err) {
			eprintf("Failed to active CUDA tracing sessions: %d\n", err);
			goto cleanup;
		}
	}

	wprintf("Running...\n");

	env.ktime_start_ns = ktime_now_ns();
	env.realtime_start_ns = ktime_to_realtime_ns(env.ktime_start_ns);
	/* env.duration_ns is already properly set */
	env.sess_start_ts = env.ktime_start_ns;
	env.sess_end_ts = env.ktime_start_ns + env.duration_ns;

	if (env.cuda_cnt > 0) {
		wprintf("Activating CUDA tracees...\n");
		err = cuda_trace_activate(env.sess_start_ts, env.sess_end_ts);
		if (err) {
			eprintf("Failed to active CUDA tracing sessions: %d\n", err);
			goto cleanup;
		}

		if (env.requested_stack_traces & ST_CUDA) {
			wprintf("Attaching CUDA USDTs...\n");
			err = cuda_trace_attach_usdts(&bpf_state, bpf_state.skel->progs.wprof_cuda_call);
			if (err) {
				eprintf("Failed to attach CUDA tracking USDTs: %d\n", err);
				return err;
			}
		}
	}

	signal(SIGALRM, sig_timer);
	timer_ival.it_value.tv_sec = env.duration_ns / 1000000000;
	timer_ival.it_value.tv_usec = env.duration_ns / 1000 % 1000000;
	err = setitimer(ITIMER_REAL, &timer_ival, NULL);
	if (err < 0) {
		eprintf("Failed to setup run duration timeout timer: %d\n", err);
		goto cleanup;
	}

	err = run_bpf(&bpf_state);
	if (err) {
		eprintf("Failed during collecting BPF-generated data: %d\n", err);
		goto cleanup;
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

	wprintf("Draining...\n");
	drain_bpf(&bpf_state, num_cpus);

	if (env.cuda_cnt == 0) {
		/* ensure we don't record CUDA data as available in wprof.data */
		env.requested_stack_traces &= ~ST_CUDA;
		env.capture_cuda = false;
	}

	err = wprof_merge_data(workdir_name, workers);
	if (err) {
		eprintf("Failed to finalize data dump: %d\n", err);
		goto cleanup;
	}

	/* we delayed ptrace retraction to symbolize libwprofinj.so stacks */
	if (env.requested_stack_traces && env.cuda_cnt > 0)
		cuda_trace_retract();

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
	if (env.trace_path) {
		struct worker_state *w = &workers[0];

		w->trace = fopen_buffered(env.trace_path, "w+");
		if (!w->trace) {
			err = -errno;
			eprintf("Failed to create trace file '%s': %d\n", env.trace_path, err);
			goto cleanup;
		}
		w->stream = (pb_ostream_t){&file_stream_cb, w->trace, SIZE_MAX, 0};

		err = init_emit(w);
		if (err) {
			eprintf("Failed to init trace emitting logic: %d\n", err);
			goto cleanup;
		}

		if (init_pb_trace(&w->stream)) {
			err = -1;
			eprintf("Failed to init protobuf!\n");
			goto cleanup;
		}

		/* process dumped events, and generate trace */
		err = emit_trace(w);
		if (err) {
			eprintf("Failed to generate Perfetto trac: %d\n", err);
			goto cleanup;
		}

		fflush(w->trace);
		ssize_t file_sz = file_size(w->trace);
		wprintf("Produced %.3lfMB trace file at '%s'.\n",
			file_sz / (1024.0 * 1024.0), env.trace_path);
	}
cleanup:
	if (env.cuda_cnt > 0)
		cuda_trace_teardown();
	cleanup_workers(workers, worker_cnt);
	detach_bpf(&bpf_state, num_cpus);
	drain_bpf(&bpf_state, num_cpus);
	print_exit_summary(workers, worker_cnt, bpf_state.skel, num_cpus, err);
	cleanup_bpf(&bpf_state);
	if (workdir_fd >= 0)
		close(workdir_fd);
	if (!env.keep_workdir && workdir_name[0])
		delete_dir(workdir_name);
	return -err;
}
