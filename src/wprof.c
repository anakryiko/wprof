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
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <time.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <pthread.h>

#include "utils.h"
#include "wprof.h"
#include "wprof.skel.h"

#include "env.h"
#include "protobuf.h"
#include "emit.h"
#include "stacktrace.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.libbpf_logs)
		return 0;
	return vfprintf(stderr, format, args);
}

const struct perf_counter_def perf_counter_defs[] = {
	{ "cpu-cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, 1e-3, "cpu_cycles_kilo", IID_ANNK_PERF_CPU_CYCLES },
	{ "cpu-insns", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS, 1e-3, "cpu_insns_kilo", IID_ANNK_PERF_CPU_INSNS },
	{ "cache-hits", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES, 1e-3, "cache_hits_kilo", IID_ANNK_PERF_CACHE_HITS },
	{ "cache-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES, 1e-3, "cache_misses_kilo", IID_ANNK_PERF_CACHE_MISSES },
	{ "stall-cycles-fe", PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_FRONTEND, 1e-3, "stalled_cycles_fe_kilo", IID_ANNK_PERF_STALL_CYCLES_FE },
	{ "stall-cycles-be", PERF_TYPE_HARDWARE, PERF_COUNT_HW_STALLED_CYCLES_BACKEND, 1e-3, "stalled_cycles_be_kilo", IID_ANNK_PERF_STALL_CYCLES_BE },
	{},
};

static volatile bool exiting;

static void sig_timer(int sig)
{
	if (env.run_dur_ms) {
		exiting = true;
		return;
	}
}

static void sig_term(int sig)
{
	exiting = true;
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
}

static struct worker_state *worker;

/* Receive events from the ring buffer. */
static int handle_rb_event(void *ctx, void *data, size_t size)
{
	struct wprof_event *e = data;
	struct worker_state *w = ctx;

	if (exiting)
		return -EINTR;

	if (env.sess_end_ts && (long long)(env.sess_end_ts - e->ts) <= 0) {
		w->rb_ignored_cnt++;
		w->rb_ignored_sz += size;
		return 0;
	}

	if (fwrite(&size, sizeof(size), 1, w->dump) != 1 ||
	    fwrite(data, size, 1, w->dump) != 1) {
		int err = -errno;

		fprintf(stderr, "Failed to write raw data dump: %d\n", err);
		return err;
	}

	w->rb_handled_cnt++;
	w->rb_handled_sz += size;

	return 0;
}

static int process_raw_dump(struct worker_state *w)
{
	void *dump_mem;
	struct wprof_event *rec;
	size_t dump_sz, rec_sz, off, idx;
	int err;

	fflush(w->dump);
	dump_sz = file_size(w->dump);

	dump_mem = mmap(NULL, dump_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(w->dump), 0);
	if (dump_mem == MAP_FAILED) {
		err = -errno;
		fprintf(stderr, "Failed to mmap dump file '%s': %d\n", w->dump_path, err);
		return err;
	}

	err = process_stack_traces(w, dump_mem, dump_sz);
	if (err) {
		fprintf(stderr, "Failed to process stack traces: %d\n", err);
		return err;
	}

	fprintf(stderr, "Processing...\n");

	off = 0;
	idx = 0;
	while (off < dump_sz) {
		rec_sz = *(size_t *)(dump_mem + off);
		rec = (struct wprof_event *)(dump_mem + off + sizeof(rec_sz));
		err = process_event(w, rec, rec_sz);
		if (err) {
			fprintf(stderr, "Failed to process event #%zu (kind %d, size %zu, offset %zu): %d\n",
				idx, rec->kind, rec_sz, off, err);
			return err; /* YEAH, I know about all the clean up, whatever */
		}
		off += sizeof(rec_sz) + rec_sz;
		idx += 1;
	}

	err = munmap(dump_mem, dump_sz);
	if (err < 0) {
		err = -errno;
		fprintf(stderr, "Failed to munmap() dump file '%s': %d\n", w->dump_path, err);
		return err;
	}
	fclose(w->dump);
	w->dump = NULL;
	unlink(w->dump_path);
	return 0;
}

static void print_exit_summary(struct wprof_bpf *skel, int num_cpus, int exit_code)
{
	int err;
	u64 total_run_cnt = 0, total_run_ns = 0;
	u64 rb_handled_cnt = 0, rb_ignored_cnt = 0;
	u64 rb_handled_sz = 0, rb_ignored_sz = 0;

	if (worker) {
		rb_handled_cnt += worker->rb_handled_cnt;
		rb_handled_sz += worker->rb_handled_sz;
		rb_ignored_cnt += worker->rb_ignored_cnt;
		rb_ignored_sz += worker->rb_ignored_sz;
	}

	if (!skel)
		goto skip_prog_stats;

	struct bpf_program *prog;

	fprintf(stderr, "BPF program runtime stats:\n");
	bpf_object__for_each_program(prog, skel->obj) {
		struct bpf_prog_info info;
		u32 info_sz = sizeof(info);

		if (bpf_program__fd(prog) < 0) /* optional inactive program */
			continue;

		memset(&info, 0, sizeof(info));
		err = bpf_prog_get_info_by_fd(bpf_program__fd(prog), &info, &info_sz);
		if (err) {
			fprintf(stderr, "!!! %s: failed to fetch prog info: %d\n",
				bpf_program__name(prog), err);
			continue;
		}

		if (info.recursion_misses) {
			fprintf(stderr, "!!! %s: %llu execution misses!\n",
				bpf_program__name(prog), info.recursion_misses);
		}

		if (env.bpf_stats) {
			fprintf(stderr, "\t%s%-*s %8llu (%6llu/CPU) runs for total of %.3lfms (%.3lfms/CPU).\n",
				bpf_program__name(prog),
				(int)max(1, 24 - strlen(bpf_program__name(prog))), ":",
				info.run_cnt, info.run_cnt / num_cpus,
				info.run_time_ns / 1000000.0, info.run_time_ns / 1000000.0 / num_cpus);
			total_run_cnt += info.run_cnt;
			total_run_ns += info.run_time_ns;
		}
	}

	if (env.bpf_stats) {
		fprintf(stderr, "\t%-24s %8llu (%6llu/CPU) runs for total of %.3lfms (%.3lfms/CPU).\n",
			"TOTAL:", total_run_cnt, total_run_cnt / num_cpus,
			total_run_ns / 1000000.0, total_run_ns / 1000000.0 / num_cpus);
		fprintf(stderr, "\t%-24s %8llu records (%.3lfMBs) processed, %llu records (%.3lfMBs) ignored.\n",
			"DATA:", rb_handled_cnt, rb_handled_sz / 1024.0 / 1024.0,
			rb_ignored_cnt, rb_ignored_sz / 1024.0 / 1024.0);
	}

skip_prog_stats:
	struct rusage ru;

	if (getrusage(RUSAGE_SELF, &ru)) {
		fprintf(stderr, "Failed to get wprof's resource usage data!..\n");
		goto skip_rusage;
	}

	fprintf(stderr, "wprof's own resource usage:\n");
	fprintf(stderr, "\tCPU time (user/system, s):\t\t%.3lf/%.3lf\n",
		ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1000000.0,
		ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1000000.0);
	fprintf(stderr, "\tMemory (max RSS, MB):\t\t\t%.3lf\n",
		ru.ru_maxrss / 1024.0);
	fprintf(stderr, "\tPage faults (maj/min, K)\t\t%.3lf/%.3lf\n",
		ru.ru_majflt / 1000.0, ru.ru_minflt / 1000.0);
	fprintf(stderr, "\tBlock I/Os (K):\t\t\t\t%.3lf/%.3lf\n",
		ru.ru_inblock / 1000.0, ru.ru_oublock / 1000.0);
	fprintf(stderr, "\tContext switches (vol/invol, K):\t%.3lf/%.3lf\n",
		ru.ru_nvcsw / 1000.0, ru.ru_nivcsw / 1000.0);

skip_rusage:
	struct wprof_stats *stats;
	struct wprof_stats s = {};
	int zero = 0;

	if (!skel || bpf_map__fd(skel->maps.stats) < 0)
		goto skip_drop_stats;

	stats = calloc(num_cpus, sizeof(*stats));
	err = bpf_map__lookup_elem(skel->maps.stats, &zero, sizeof(int),
				   stats, sizeof(*stats) * num_cpus, 0);
	if (err) {
		fprintf(stderr, "Failed to fetch BPF-side stats: %d\n", err);
		goto skip_drop_stats;
	}

	for (int i = 0; i < num_cpus; i++) {
		s.rb_misses += stats[i].rb_misses;
		s.rb_drops += stats[i].rb_drops;
		s.task_state_drops += stats[i].task_state_drops;
	}
	free(stats);

	if (s.rb_misses)
		fprintf(stderr, "!!! Ringbuf fetch misses: %llu\n", s.rb_misses);
	if (s.rb_drops) {
		fprintf(stderr, "!!! Ringbuf drops: %llu (%llu handled, %.3lf%% drop rate)\n",
			s.rb_drops, rb_handled_cnt, s.rb_drops * 100.0 / (rb_handled_cnt + s.rb_drops));
	}
	if (s.task_state_drops)
		fprintf(stderr, "!!! Task state drops: %llu\n", s.task_state_drops);

skip_drop_stats:
	fprintf(stderr, "Exited %s (after %.3lfs).\n",
		exit_code ? "with errors" : "cleanly",
		(ktime_now_ns() - env.sess_start_ts) / 1000000000.0);
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

int main(int argc, char **argv)
{
	const char *online_cpus_file = "/sys/devices/system/cpu/online";
	struct wprof_bpf *skel = NULL;
	struct perf_event_attr attr;
	struct bpf_link **links = NULL;
	struct ring_buffer *ring_buf = NULL;
	int num_cpus = 0, num_online_cpus;
	int *perf_timer_fds = NULL, *perf_counter_fds = NULL, perf_counter_fd_cnt = 0, pefd;
	int *ringbuf_fds = NULL;
	int i, err = 0;
	bool *online_mask = NULL;
	struct itimerval timer_ival;
	int stats_fd = -1;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) {
		err = -1;
		goto cleanup;
	}

	if (env.print_stats && env.run_dur_ms) {
		fprintf(stderr, "Can't specify --print-stats and --run-dur-ms at the same time!\n");
		err = -1;
		goto cleanup;
	}

	libbpf_set_print(libbpf_print_fn);

	err = parse_cpu_mask_file(online_cpus_file, &online_mask, &num_online_cpus);
	if (err) {
		fprintf(stderr, "Failed to get online CPU numbers: %d\n", err);
		goto cleanup;
	}

	num_cpus = libbpf_num_possible_cpus();
	if (num_cpus <= 0) {
		fprintf(stderr, "Failed to get the number of processors\n");
		err = -1;
		goto cleanup;
	}

	calibrate_ktime();

	skel = wprof_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		err = -1;
		goto cleanup;
	}

	bpf_map__set_max_entries(skel->maps.rbs, env.ringbuf_cnt);
	bpf_map__set_max_entries(skel->maps.task_states, env.task_state_sz);

	/* FILTERING */
	for (int i = 0; i < env.allow_cpu_cnt; i++) {
		int cpu = env.allow_cpus[i];

		if (cpu < 0 || cpu >= num_cpus || cpu >= 4096) {
			fprintf(stderr, "Invalid CPU specified: %d\n", cpu);
			err = -1;
			goto cleanup;
		}
		skel->rodata->filt_mode |= FILT_ALLOW_CPU;
		skel->data_allow_cpus->allow_cpus[cpu / 64] |= 1ULL << (cpu % 64);
	}
	if (env.allow_pid_cnt > 0) {
		size_t _sz;

		skel->rodata->filt_mode |= FILT_ALLOW_PID;
		skel->rodata->allow_pid_cnt = env.allow_pid_cnt;
		if ((err = bpf_map__set_value_size(skel->maps.data_allow_pids, env.allow_pid_cnt * 4))) {
			fprintf(stderr, "Failed to size BPF-side PID allowlist: %d\n", err);
			goto cleanup;
		}
		skel->data_allow_pids = bpf_map__initial_value(skel->maps.data_allow_pids, &_sz);
		for (int i = 0; i < env.allow_pid_cnt; i++) {
			skel->data_allow_pids->allow_pids[i] = env.allow_pids[i];
		}
	}

	perf_counter_fd_cnt = num_cpus * env.counter_cnt;
	skel->rodata->perf_ctr_cnt = env.counter_cnt;
	bpf_map__set_max_entries(skel->maps.perf_cntrs, perf_counter_fd_cnt);

	skel->rodata->rb_cnt_bits = 0;
	while ((1ULL << skel->rodata->rb_cnt_bits) < env.ringbuf_cnt)
		skel->rodata->rb_cnt_bits++;

	skel->rodata->capture_stack_traces = env.stack_traces;

	if (env.bpf_stats) {
		stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
		if (stats_fd < 0)
			fprintf(stderr, "Failed to enable BPF run stats tracking: %d!\n", stats_fd);
	}

	err = wprof_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Fail to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	ringbuf_fds = calloc(env.ringbuf_cnt, sizeof(*ringbuf_fds));
	for (int i = 0; i < env.ringbuf_cnt; i++) {
		int map_fd;

		map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, sfmt("wprof_rb_%d", i), 0, 0, env.ringbuf_sz, NULL);
		if (map_fd < 0) {
			fprintf(stderr, "Failed to create BPF ringbuf #%d: %d\n", i, map_fd);
			err = map_fd;
			goto cleanup;
		}

		err = bpf_map_update_elem(bpf_map__fd(skel->maps.rbs), &i, &map_fd, BPF_NOEXIST);
		if (err < 0) {
			fprintf(stderr, "Failed to set BPF ringbuf #%d into ringbuf map-of-maps: %d\n", i, err);
			close(map_fd);
			goto cleanup;
		}

		ringbuf_fds[i] = map_fd;
	}

	struct worker_state *w = calloc(1, sizeof(*w));

	w->name_iids = (struct str_iid_domain) {
		.str_iids = hashmap__new(str_hash_fn, str_equal_fn, NULL),
		.next_str_iid = IID_FIXED_LAST_ID,
		.domain_desc = "dynamic",
	};

	const char *tmp_path = "wprof.dump";
	w->dump_path = strdup(tmp_path);
	fprintf(stderr, "Using '%s' for raw data dump...\n", w->dump_path);
	w->dump = fopen(tmp_path, "w+");
	if (!w->dump) {
		err = -errno;
		fprintf(stderr, "Failed to create data dump file '%s': %d\n", w->dump_path, err);
		goto cleanup;
	}

	worker = w;

	if (env.replay_dump)
		goto replay_dump;

	/* Prepare ring buffer to receive events from the BPF program. */
	ring_buf = ring_buffer__new(ringbuf_fds[0], handle_rb_event, worker, NULL);
	if (!ring_buf) {
		err = -1;
		goto cleanup;
	}
	for (i = 1; i < env.ringbuf_cnt; i++) {
		err = ring_buffer__add(ring_buf, ringbuf_fds[i], handle_rb_event, worker);
		if (err) {
			fprintf(stderr, "Failed to create ring buffer manager for ringbuf #%d: %d\n", i, err);
			goto cleanup;
		}
	}

	perf_timer_fds = malloc(num_cpus * sizeof(int));
	perf_counter_fds = malloc(perf_counter_fd_cnt * sizeof(int));
	for (i = 0; i < num_cpus; i++) {
		perf_timer_fds[i] = -1;
		for (int j = 0; j < env.counter_cnt; j++)
			perf_counter_fds[i * env.counter_cnt + j] = -1;
	}

	/* determine randomized spread-out "plan" for attaching to timers to
	 * avoid too aligned (in time) triggerings across all CPUs
	 */
	u64 timer_start_ts = ktime_now_ns();
	struct timer_plan *timer_plan = calloc(num_cpus, sizeof(*timer_plan));

	for (int cpu = 0; cpu < num_cpus; cpu++) {
		timer_plan[cpu].cpu = cpu;
		timer_plan[cpu].delay_ns = 1000000000ULL / env.freq * ((double)rand() / RAND_MAX);
	}
	qsort(timer_plan, num_cpus, sizeof(*timer_plan), timer_plan_cmp);

	for (int i = 0; i < num_cpus; i++) {
		int cpu = timer_plan[i].cpu;

		/* skip offline/not present CPUs */
		if (cpu >= num_online_cpus || !online_mask[cpu])
			continue;

		/* timer perf event */
		memset(&attr, 0, sizeof(attr));
		attr.size = sizeof(attr);
		attr.type = PERF_TYPE_SOFTWARE;
		attr.config = PERF_COUNT_SW_CPU_CLOCK;
		attr.sample_freq = env.freq;
		attr.freq = 1;

		u64 now = ktime_now_ns();
		if (now < timer_start_ts + timer_plan[i].delay_ns)
			usleep((timer_start_ts + timer_plan[i].delay_ns - now) / 1000);

		pefd = perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (pefd < 0) {
			fprintf(stderr, "Fail to set up performance monitor on a CPU/Core\n");
			err = -1;
			goto cleanup;
		}
		perf_timer_fds[cpu] = pefd;

		/* CPU cycles perf event, if supported */
		/* set up requested perf counters */
		for (int j = 0; j < env.counter_cnt; j++) {
			const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[j]];
			int pe_idx = cpu * env.counter_cnt + j;

			memset(&attr, 0, sizeof(attr));
			attr.size = sizeof(attr);
			attr.type = def->perf_type;
			attr.config = def->perf_cfg;

			pefd = perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
			if (pefd < 0) {
				fprintf(stderr, "Failed to create %s PMU for CPU #%d, skipping...\n", def->alias, cpu);
			} else {
				perf_counter_fds[pe_idx] = pefd;
				err = bpf_map__update_elem(skel->maps.perf_cntrs,
							   &pe_idx, sizeof(pe_idx),
							   &pefd, sizeof(pefd), 0);
				if (err) {
					fprintf(stderr, "Failed to set up %s PMU on CPU#%d for BPF: %d\n", def->alias, cpu, err);
					goto cleanup;
				}
				err = ioctl(pefd, PERF_EVENT_IOC_ENABLE, 0);
				if (err) {
					fprintf(stderr, "Failed to enable %s PMU on CPU#%d: %d\n", def->alias, cpu, err);
					goto cleanup;
				}
			}
		}
	}

	links = calloc(num_cpus, sizeof(struct bpf_link *));
	for (int cpu = 0; cpu < num_cpus; cpu++) {
		if (perf_timer_fds[cpu] < 0)
			continue;

		links[cpu] = bpf_program__attach_perf_event(skel->progs.wprof_timer_tick, perf_timer_fds[cpu]);
		if (!links[cpu]) {
			err = -1;
			goto cleanup;
		}
	}

	if (env.trace_path) {
		struct worker_state *w = worker;

		w->trace = fopen(env.trace_path, "w+");
		if (!w->trace) {
			err = -errno;
			fprintf(stderr, "Failed to create trace file '%s': %d\n", env.trace_path, err);
			goto cleanup;
		}
		w->stream = (pb_ostream_t){&file_stream_cb, w->trace, SIZE_MAX, 0};

		err = init_emit(w);
		if (err) {
			fprintf(stderr, "Failed to init trace emitting logic: %d\n", err);
			goto cleanup;
		}

		if (init_pb_trace(&w->stream)) {
			err = -1;
			fprintf(stderr, "Failed to init protobuf!\n");
			goto cleanup;
		}
	}

	err = wprof_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach skeleton: %d\n", err);
		goto cleanup;
	}

	signal(SIGALRM, sig_timer);
	signal(SIGINT, sig_term);
	signal(SIGTERM, sig_term);

	timer_ival.it_value.tv_sec = (env.print_stats ? env.stats_period_ms : env.run_dur_ms) / 1000;
	timer_ival.it_value.tv_usec = (env.print_stats ? env.stats_period_ms : env.run_dur_ms) * 1000 % 1000000;
	timer_ival.it_interval = env.print_stats ? timer_ival.it_value : (struct timeval){};
	err = setitimer(ITIMER_REAL, &timer_ival, NULL);
	if (err < 0) {
		fprintf(stderr, "Failed to setup stats timer: %d\n", err);
		goto cleanup;
	}

	fprintf(stderr, "Running...\n");
	env.sess_start_ts = ktime_now_ns();
	if (env.run_dur_ms)
		env.sess_end_ts = env.sess_start_ts + env.run_dur_ms * 1000000ULL;
	skel->bss->session_start_ts = env.sess_start_ts;

	/* Wait and receive stack traces */
	while ((err = ring_buffer__poll(ring_buf, -1)) >= 0 || err == -EINTR) {
		if (exiting) {
			err = 0;
			break;
		}
	}

	fprintf(stderr, "Stopping...\n");

cleanup:
	if (skel)
		wprof_bpf__detach(skel);
	if (stats_fd >= 0)
		close(stats_fd);
	if (links) {
		for (int cpu = 0; cpu < num_cpus; cpu++)
			bpf_link__destroy(links[cpu]);
		free(links);
	}
	if (perf_timer_fds || perf_counter_fds) {
		for (i = 0; i < num_cpus; i++) {
			if (perf_timer_fds[i] >= 0)
				close(perf_timer_fds[i]);
		}
		for (i = 0; i < perf_counter_fd_cnt; i++) {
			if (perf_counter_fds[i] >= 0) {
				(void)ioctl(perf_counter_fds[i], PERF_EVENT_IOC_DISABLE, 0);
				close(perf_counter_fds[i]);
			}
		}
		free(perf_timer_fds);
		free(perf_counter_fds);
	}

	fprintf(stderr, "Draining...\n");
	if (ring_buf) { /* drain ringbuf */
		exiting = false; /* ringbuf callback will stop early, if exiting is set */
		(void)ring_buffer__consume(ring_buf);
	}

	ring_buffer__free(ring_buf);
	if (ringbuf_fds) {
		for (i = 0; i < env.ringbuf_cnt; i++)
			if (ringbuf_fds[i])
				close(ringbuf_fds[i]);
	}

replay_dump:
	/* process dumped events, if no error happened */
	if (err == 0) {
		ssize_t file_sz;

		err = process_raw_dump(worker);
		if (err) {
			fprintf(stderr, "Failed to process raw data dump: %d\n", err);
			goto cleanup2;
		}

		fflush(worker->trace);
		file_sz = file_size(worker->trace);
		fprintf(stderr, "Produced %.3lfMB trace file at '%s'.\n",
			file_sz / (1024.0 * 1024.0), env.trace_path);

		fclose(worker->trace);
	}

cleanup2:
	print_exit_summary(skel, num_cpus, err);

	wprof_bpf__destroy(skel);
	free(online_mask);
	return -err;
}
