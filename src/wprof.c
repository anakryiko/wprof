// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#include "bpf/libbpf_common.h"
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
#include <limits.h>
#include <linux/fs.h>
#include <dirent.h>

#include "utils.h"
#include "wprof.h"
#include "data.h"
#include "wprof.skel.h"

#include "env.h"
#include "protobuf.h"
#include "emit.h"
#include "stacktrace.h"

#define FILE_BUF_SZ (64 * 1024)

static bool ignore_libbpf_warns;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.libbpf_logs)
		return 0;
	if (ignore_libbpf_warns)
		return 0;
	return vfprintf(stderr, format, args);
}

/* The order of these definition matters as the position determines
 * a persisted ID stored in wprof.data, so when adding/removing definitions,
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

static void init_data_header(struct wprof_data_hdr *hdr)
{
	memset(hdr, 0, sizeof(*hdr));
	memcpy(hdr->magic, "WPROF", 6);
	hdr->hdr_sz = sizeof(*hdr);
	hdr->flags = 0;
	hdr->version_major = WPROF_DATA_MAJOR;
	hdr->version_minor = WPROF_DATA_MINOR;
}

static int init_data_dump(struct worker_state *w)
{
	int err;

	err = fseek(w->dump, 0, SEEK_SET);
	if (err) {
		err = -errno;
		fprintf(stderr, "Failed to fseek(0): %d\n", err);
		return err;
	}

	struct wprof_data_hdr hdr;
	init_data_header(&hdr);
	hdr.flags = WPROF_DATA_FLAG_INCOMPLETE;

	if (fwrite(&hdr, sizeof(hdr), 1, w->dump) != 1) {
		err = -errno;
		fprintf(stderr, "Failed to fwrite() header: %d\n", err);
		return err;
	}

	fflush(w->dump);
	fsync(fileno(w->dump));
	return 0;
}

static int finalize_events_dump(struct worker_state *w)
{
	int err;
	long pos;

	pos = ftell(w->dump);
	if (pos < 0) {
		err = -errno;
		fprintf(stderr, "Failed to get file postiion: %d\n", -err);
		return err;
	}

	err = fseek(w->dump, 0, SEEK_SET);
	if (err) {
		err = -errno;
		fprintf(stderr, "Failed to fseek(0): %d\n", err);
		return err;
	}

	struct wprof_data_hdr hdr;
	init_data_header(&hdr);

	hdr.cfg.ktime_start_ns = env.ktime_start_ns;
	hdr.cfg.realtime_start_ns = env.realtime_start_ns;
	hdr.cfg.duration_ns = env.duration_ns;

	hdr.cfg.capture_stack_traces = env.capture_stack_traces == TRUE;
	hdr.cfg.capture_ipis = env.capture_ipis == TRUE;
	hdr.cfg.capture_requests = env.capture_requests == TRUE;

	hdr.cfg.timer_freq_hz = env.timer_freq_hz;
	hdr.cfg.counter_cnt = env.counter_cnt;
	memcpy(&hdr.cfg.counter_ids, env.counter_ids, sizeof(env.counter_ids));

	hdr.events_off = 0;
	hdr.events_sz = pos - sizeof(hdr);
	hdr.event_cnt = w->rb_handled_cnt;

	if (fwrite(&hdr, sizeof(hdr), 1, w->dump) != 1) {
		err = -errno;
		fprintf(stderr, "Failed to fwrite() header: %d\n", err);
		return err;
	}

	fflush(w->dump);
	fsync(fileno(w->dump));

	w->dump_sz = pos;
	w->dump_mem = mmap(NULL, w->dump_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(w->dump), 0);
	if (w->dump_mem == MAP_FAILED) {
		err = -errno;
		fprintf(stderr, "Failed to mmap data dump: %d\n", err);
		w->dump_mem = NULL;
		return err;
	}
	w->dump_hdr = w->dump_mem;

	err = fseek(w->dump, pos, SEEK_SET);
	if (err) {
		err = -errno;
		fprintf(stderr, "Failed to fseek() to end: %d\n", err);
		return err;
	}

	return 0;
}

static int load_data_dump(struct worker_state *w)
{
	int err;

	err = fseek(w->dump, 0, SEEK_SET);
	if (err) {
		err = -errno;
		fprintf(stderr, "Failed to fseek(0): %d\n", err);
		return err;
	}

	w->dump_sz = file_size(w->dump);
	w->dump_mem = mmap(NULL, w->dump_sz, PROT_READ, MAP_SHARED, fileno(w->dump), 0);
	if (w->dump_mem == MAP_FAILED) {
		err = -errno;
		fprintf(stderr, "Failed to mmap data dump: %d\n", err);
		w->dump_mem = NULL;
		return err;
	}
	w->dump_hdr = w->dump_mem;

	if (w->dump_hdr->flags == WPROF_DATA_FLAG_INCOMPLETE) {
		fprintf(stderr, "wprof data file is incomplete!\n");
		return -EINVAL;
	}

	if (w->dump_hdr->version_major != WPROF_DATA_MAJOR) {
		fprintf(stderr, "wprof data file MAJOR version mismatch: ACTUAL is v%d.%d vs EXPECTED v%d.%d!\n",
			w->dump_hdr->version_major, w->dump_hdr->version_minor,
			WPROF_DATA_MAJOR, WPROF_DATA_MINOR);
		return -EINVAL;
	}
	/* XXX: backwards compat in the future? */
	if (w->dump_hdr->version_minor != WPROF_DATA_MINOR) {
		fprintf(stderr, "wprof data file MINOR version mismatch: ACTUAL is v%d.%d vs EXPECTED v%d.%d!\n",
			w->dump_hdr->version_major, w->dump_hdr->version_minor,
			WPROF_DATA_MAJOR, WPROF_DATA_MINOR);
		return -EINVAL;
	}

	return 0;
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

		fprintf(stderr, "Failed to write raw data dump: %d\n", err);
		return err;
	}

	w->rb_handled_cnt++;
	w->rb_handled_sz += size;

	return 0;
}

static void print_exit_summary(struct worker_state *worker, struct wprof_bpf *skel, int num_cpus, int exit_code)
{
	int err;
	u64 total_run_cnt = 0, total_run_ns = 0;
	u64 rb_handled_cnt = 0, rb_ignored_cnt = 0;
	u64 rb_handled_sz = 0, rb_ignored_sz = 0;

	rb_handled_cnt += worker->rb_handled_cnt;
	rb_handled_sz += worker->rb_handled_sz;
	rb_ignored_cnt += worker->rb_ignored_cnt;
	rb_ignored_sz += worker->rb_ignored_sz;

	if (!skel)
		goto skip_prog_stats;

	if (env.stats)
		fprintf(stderr, "BPF program runtime stats:\n");

	struct bpf_program *prog;
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

		if (env.stats) {
			fprintf(stderr, "\t%s%-*s %8llu (%6llu/CPU) runs for total of %.3lfms (%.3lfms/CPU).\n",
				bpf_program__name(prog),
				(int)max(1UL, 24 - strlen(bpf_program__name(prog))), ":",
				info.run_cnt, info.run_cnt / num_cpus,
				info.run_time_ns / 1000000.0, info.run_time_ns / 1000000.0 / num_cpus);
			total_run_cnt += info.run_cnt;
			total_run_ns += info.run_time_ns;
		}
	}

	if (env.stats) {
		fprintf(stderr, "\t%-24s %8llu (%6llu/CPU) runs for total of %.3lfms (%.3lfms/CPU).\n",
			"TOTAL:", total_run_cnt, total_run_cnt / num_cpus,
			total_run_ns / 1000000.0, total_run_ns / 1000000.0 / num_cpus);
		fprintf(stderr, "\t%-24s %8llu records (%.3lfMBs) processed, %llu records (%.3lfMBs) ignored.\n",
			"DATA:", rb_handled_cnt, rb_handled_sz / 1024.0 / 1024.0,
			rb_ignored_cnt, rb_ignored_sz / 1024.0 / 1024.0);
	}

skip_prog_stats:
	if (!env.stats)
		goto skip_rusage;

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
		s.req_state_drops += stats[i].req_state_drops;
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
	if (s.req_state_drops)
		fprintf(stderr, "!!! Request state drops: %llu\n", s.req_state_drops);

skip_drop_stats:
	fprintf(stderr, "Exited %s (after %.3lfs).\n",
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

struct req_binary {
	int pid;
	char *path;
	char *attach_path;
};

static unsigned long hash_combine(unsigned long h, unsigned long value)
{
	return h * 31 + value;
}

static size_t req_binary_hash_fn(long key, void *ctx)
{
	struct req_binary *binary = (void *)key;

	return hash_combine(str_hash(binary->path), binary->pid);
}

static bool req_binary_equal_fn(long a, long b, void *ctx)
{
	struct req_binary *binary_a = (void *)a;
	struct req_binary *binary_b = (void *)b;

	return binary_a->pid == binary_b->pid && strcmp(binary_a->path, binary_b->path) == 0;
}

static int add_req_binary(const char *path, int pid, int vma_pid, long vma_start, long vma_end)
{
	struct req_binary *binary, key;

	if (!env.req_binaries) {
		env.req_binaries = hashmap__new(req_binary_hash_fn, req_binary_equal_fn, NULL);
		if (!env.req_binaries)
			return -ENOMEM;
	}

	key.pid = pid;
	key.path = strdup(path);
	if (!key.path)
		return -ENOMEM;

	if (hashmap__find(env.req_binaries, &key, NULL)) {
		free(key.path);
		return 0;
	}

	binary = malloc(sizeof(*binary));
	if (!binary) {
		free(key.path);
		return -ENOMEM;
	}

	binary->pid = pid;
	binary->path = key.path;

	if (vma_pid) {
		char tmp[1024];
		snprintf(tmp, sizeof(tmp), "/proc/%d/map_files/%lx-%lx", vma_pid, vma_start, vma_end);
		binary->attach_path = strdup(tmp);
	} else {
		binary->attach_path = strdup(key.path);
	}

	hashmap__set(env.req_binaries, binary, binary, NULL, NULL);
	// printf("Added binary: %s (PID %d)\n", path, pid);

	return 0;
}

static int discover_pid_req_binaries(int pid, int target_pid)
{
	struct procmap_query query;
	char proc_path[64], path_buf[PATH_MAX];
	int err = 0, fd;
	u64 addr = 0;

	snprintf(proc_path, sizeof(proc_path), "/proc/%d/maps", pid);
	fd = open(proc_path, O_RDONLY);
	if (fd < 0) {
		err = -errno;
		if (err == -ENOENT)
			return 0; /* process is gone now */
		eprintf("Failed to open '%s': %d\n", proc_path, err);
		return err;
	}

	memset(&query, 0, sizeof(query));

	while (true) {
		query.size = sizeof(query);
		query.query_flags = PROCMAP_QUERY_COVERING_OR_NEXT_VMA |
				    PROCMAP_QUERY_VMA_EXECUTABLE |
				    PROCMAP_QUERY_FILE_BACKED_VMA;
		query.query_addr = addr;
		query.vma_name_addr = (__u64)path_buf;
		query.vma_name_size = sizeof(path_buf);

		err = ioctl(fd, PROCMAP_QUERY, &query);
		if (err && (errno == ENOENT || errno == ESRCH)) {
			err = 0;
			break;
		}
		if (err) {
			err = -errno;
			eprintf("PROCMAP_QUERY failed for PID %d: %d\n", pid, err);
			break;
		}

		if (path_buf[0] == '/') {
			err = add_req_binary(path_buf, target_pid, pid, query.vma_start, query.vma_end);
			if (err)
				break;
		}

		addr = query.vma_end;
	}

	close(fd);
	return err;
}

static int setup_req_tracking_discovery(void)
{
	int err = 0;

	for (int i = 0; i < env.req_pid_cnt; i++) {
		int pid = env.req_pids[i];

		err = discover_pid_req_binaries(pid, pid);
		if (err) {
			eprintf("Failed to discover request tracking binaries for PID %d: %d\n", pid, err);
			return err;
		}
	}

	for (int i = 0; i < env.req_path_cnt; i++) {
		err = add_req_binary(env.req_paths[i], -1, 0, 0, 0);
		if (err) {
			eprintf("Failed to record binary path '%s' for request tracking: %d\n", env.req_paths[i], err);
			return err;
		}
	}


	if (env.req_global_discovery) {
		struct dirent *entry;
		DIR *proc_dir;

		proc_dir = opendir("/proc");
		if (!proc_dir) {
			err = -errno;
			eprintf("Failed to open /proc directory: %d\n", err);
			return err;
		}

		while ((entry = readdir(proc_dir)) != NULL) {
			int pid, n;

			if (sscanf(entry->d_name, "%d%n", &pid, &n) != 1 || entry->d_name[n] != '\0')
				continue;

			err = discover_pid_req_binaries(pid, -1);
			if (err) {
				eprintf("Failed to discover request tracking binaries for PID %d: %d\n", pid, err);
				break;
			}
		}

		closedir(proc_dir);
		if (err)
			return err;
	}

	return 0;
}

struct bpf_state {
	bool detached;
	bool drained;
	struct wprof_bpf *skel;
	struct bpf_link **links;
	struct ring_buffer *ring_buf;
	int *perf_timer_fds;
	int *perf_counter_fds;
	int perf_counter_fd_cnt;
	int *rb_map_fds;
	int stats_fd;
	bool *online_mask;
	int num_online_cpus;
};

static int setup_bpf(struct bpf_state *st, struct worker_state *worker, int num_cpus)
{
	const char *online_cpus_file = "/sys/devices/system/cpu/online";
	struct perf_event_attr attr;
	struct wprof_bpf *skel;
	int pefd, i, err = 0;

#ifndef __x86_64__
	if (env.capture_ipis) {
		fprintf(stderr, "IPI capture is supported only on x86-64 architecture!\n");
		return -EOPNOTSUPP;
	}
#endif /* __x86_64 */

	libbpf_set_print(libbpf_print_fn);

	err = parse_cpu_mask_file(online_cpus_file, &st->online_mask, &st->num_online_cpus);
	if (err) {
		fprintf(stderr, "Failed to get online CPU numbers: %d\n", err);
		return -EINVAL;
	}

	calibrate_ktime();

	st->skel = skel = wprof_bpf__open();
	if (!skel) {
		err = -errno;
		fprintf(stderr, "Failed to open and load BPF skeleton: %d\n", err);
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
		bpf_map__set_max_entries(skel->maps.req_states, max(16 * 1024, env.task_state_sz));
	} else {
		bpf_map__set_autocreate(skel->maps.req_states, false);
	}

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
			fprintf(stderr, "Failed to size BPF-side %s: %d\n", f->name, err);
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
			fprintf(stderr, "Failed to size BPF-side %s: %d\n", f->name, err);
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

	st->perf_counter_fd_cnt = num_cpus * env.counter_cnt;
	skel->rodata->perf_ctr_cnt = env.counter_cnt;
	bpf_map__set_max_entries(skel->maps.perf_cntrs, st->perf_counter_fd_cnt);

	skel->rodata->rb_cnt_bits = 0;
	while ((1ULL << skel->rodata->rb_cnt_bits) < env.ringbuf_cnt)
		skel->rodata->rb_cnt_bits++;

	skel->rodata->capture_stack_traces = env.capture_stack_traces == TRUE;

	if (env.stats) {
		st->stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
		if (st->stats_fd < 0)
			fprintf(stderr, "Failed to enable BPF run stats tracking: %d!\n", st->stats_fd);
	}

	err = wprof_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Fail to load BPF skeleton: %d\n", err);
		return err;
	}

	st->rb_map_fds = calloc(env.ringbuf_cnt, sizeof(*st->rb_map_fds));
	for (int i = 0; i < env.ringbuf_cnt; i++) {
		int map_fd;

		map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, sfmt("wprof_rb_%d", i), 0, 0, env.ringbuf_sz, NULL);
		if (map_fd < 0) {
			fprintf(stderr, "Failed to create BPF ringbuf #%d: %d\n", i, map_fd);
			return map_fd;
		}

		err = bpf_map_update_elem(bpf_map__fd(skel->maps.rbs), &i, &map_fd, BPF_NOEXIST);
		if (err < 0) {
			fprintf(stderr, "Failed to set BPF ringbuf #%d into ringbuf map-of-maps: %d\n", i, err);
			close(map_fd);
			return err;
		}

		st->rb_map_fds[i] = map_fd;
	}

	/* Prepare ring buffer to receive events from the BPF program. */
	st->ring_buf = ring_buffer__new(st->rb_map_fds[0], handle_rb_event, worker, NULL);
	if (!st->ring_buf) {
		err = -errno;
		return err;
	}
	for (i = 1; i < env.ringbuf_cnt; i++) {
		err = ring_buffer__add(st->ring_buf, st->rb_map_fds[i], handle_rb_event, worker);
		if (err) {
			fprintf(stderr, "Failed to create ring buffer manager for ringbuf #%d: %d\n", i, err);
			return err;
		}
	}

	st->perf_timer_fds = calloc(num_cpus, sizeof(int));
	st->perf_counter_fds = calloc(st->perf_counter_fd_cnt, sizeof(int));
	for (i = 0; i < num_cpus; i++) {
		st->perf_timer_fds[i] = -1;
		for (int j = 0; j < env.counter_cnt; j++)
			st->perf_counter_fds[i * env.counter_cnt + j] = -1;
	}

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

		pefd = perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (pefd < 0) {
			err = -errno;
			fprintf(stderr, "Failed to set up performance monitor on CPU %d: %d\n", cpu, err);
			return err;
		}
		st->perf_timer_fds[cpu] = pefd;

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
				st->perf_counter_fds[pe_idx] = pefd;
				err = bpf_map__update_elem(skel->maps.perf_cntrs,
							   &pe_idx, sizeof(pe_idx),
							   &pefd, sizeof(pefd), 0);
				if (err) {
					fprintf(stderr, "Failed to set up %s PMU on CPU#%d for BPF: %d\n", def->alias, cpu, err);
					return err;
				}
				err = ioctl(pefd, PERF_EVENT_IOC_ENABLE, 0);
				if (err) {
					err = -errno;
					fprintf(stderr, "Failed to enable %s PMU on CPU#%d: %d\n", def->alias, cpu, err);
					return err;
				}
			}
		}
	}

	return 0;
}

static int attach_bpf(struct bpf_state *st, int num_cpus)
{
	int err = 0;

	st->links = calloc(num_cpus, sizeof(struct bpf_link *));
	for (int cpu = 0; cpu < num_cpus; cpu++) {
		if (st->perf_timer_fds[cpu] < 0)
			continue;

		st->links[cpu] = bpf_program__attach_perf_event(st->skel->progs.wprof_timer_tick,
								st->perf_timer_fds[cpu]);
		if (!st->links[cpu]) {
			err = -errno;
			return err;
		}
	}

	err = wprof_bpf__attach(st->skel);
	if (err) {
		fprintf(stderr, "Failed to attach skeleton: %d\n", err);
		return err;
	}

	if (env.req_binaries) {
		struct hashmap_entry *entry;
		size_t bkt;
		int link_idx = num_cpus;

		hashmap__for_each_entry(env.req_binaries, entry, bkt) {
			struct req_binary *binary = (struct req_binary *)entry->value;
			struct bpf_link *link, **tmp;

			/* given we don't know for sure if requested binary
			 * does have our USDT, we just silence libbpf's
			 * warning and move on if there is an error
			 */
			ignore_libbpf_warns = true;
			link = bpf_program__attach_usdt(st->skel->progs.wprof_req_ctx,
							binary->pid, binary->attach_path,
							"thrift", "crochet_request_data_context",
							NULL);
			ignore_libbpf_warns = false;
			if (!link) {
				if (env.verbose) {
					eprintf("Failed to attach USDT to %s (%s) (PID %d), ignoring...\n",
					       binary->path, binary->attach_path, binary->pid);
				}
				continue;
			}

			tmp = realloc(st->links, (link_idx + 1) * sizeof(struct bpf_link *));
			if (!tmp) {
				err = -ENOMEM;
				return err;
			}
			st->links = tmp;
			st->links[link_idx] = link;
			link_idx++;
		}
	}

	return 0;
}

static int run_bpf(struct bpf_state *st)
{
	int err = 0;

	st->skel->bss->session_start_ts = env.sess_start_ts;

	/* Wait and receive stack traces */
	while ((err = ring_buffer__poll(st->ring_buf, -1)) >= 0 || err == -EINTR) {
		if (exiting) {
			err = 0;
			break;
		}
	}

	return err;
}

static void detach_bpf(struct bpf_state *st, int num_cpus)
{
	if (st->detached)
		return;

	if (st->skel)
		wprof_bpf__detach(st->skel);
	if (st->stats_fd >= 0)
		close(st->stats_fd);
	if (st->links) {
		for (int cpu = 0; cpu < num_cpus; cpu++)
			bpf_link__destroy(st->links[cpu]);
		free(st->links);
	}
	if (st->perf_timer_fds || st->perf_counter_fds) {
		for (int i = 0; i < num_cpus; i++) {
			if (st->perf_timer_fds[i] >= 0)
				close(st->perf_timer_fds[i]);
		}
		for (int i = 0; i < st->perf_counter_fd_cnt; i++) {
			if (st->perf_counter_fds[i] >= 0) {
				(void)ioctl(st->perf_counter_fds[i], PERF_EVENT_IOC_DISABLE, 0);
				close(st->perf_counter_fds[i]);
			}
		}
		free(st->perf_timer_fds);
		free(st->perf_counter_fds);
	}

	st->detached = true;
}

static void drain_bpf(struct bpf_state *st, int num_cpus)
{
	if (st->drained)
		return;

	if (st->ring_buf) { /* drain ringbuf */
		exiting = false; /* ringbuf callback will stop early, if exiting is set */
		(void)ring_buffer__consume(st->ring_buf);
	}

	ring_buffer__free(st->ring_buf);

	if (st->rb_map_fds) {
		for (int i = 0; i < env.ringbuf_cnt; i++)
			if (st->rb_map_fds[i])
				close(st->rb_map_fds[i]);
	}

	st->drained = true;
}

static void cleanup_bpf(struct bpf_state *st)
{
	wprof_bpf__destroy(st->skel);
	st->skel = NULL;

	free(st->online_mask);
	st->online_mask = NULL;
}

static void cleanup_worker(struct worker_state *w)
{
	if (!w)
		return;
	if (w->trace)
		fclose(w->trace);
	if (w->dump_mem && w->dump_mem != MAP_FAILED) {
		int err = munmap(w->dump_mem, w->dump_sz);
		if (err < 0) {
			err = -errno;
			fprintf(stderr, "Failed to munmap() dump file '%s': %d\n", env.data_path, err);
		}
	}
	if (w->dump)
		fclose(w->dump);
	w->dump_mem = NULL;
	w->dump = NULL;
}

int main(int argc, char **argv)
{
	struct worker_state *worker = calloc(1, sizeof(*worker));
	struct bpf_state bpf_state = {};
	int num_cpus = 0, err = 0;
	struct itimerval timer_ival = {};

	env.actual_start_ts = ktime_now_ns();

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) {
		err = -1;
		goto cleanup;
	}

	num_cpus = libbpf_num_possible_cpus();
	if (num_cpus <= 0) {
		fprintf(stderr, "Failed to get the number of processors\n");
		err = -1;
		goto cleanup;
	}

	signal(SIGINT, sig_term);
	signal(SIGTERM, sig_term);

	worker->name_iids = (struct str_iid_domain) {
		.str_iids = hashmap__new(str_hash_fn, str_equal_fn, NULL),
		.next_str_iid = IID_FIXED_LAST_ID,
		.domain_desc = "dynamic",
	};

	if (env.replay) {
		worker->dump = fopen(env.data_path, "r");
		if (!worker->dump) {
			err = -errno;
			fprintf(stderr, "Failed to open data dump at '%s': %d\n", env.data_path, err);
			goto cleanup;
		}
		err = load_data_dump(worker);
		if (err) {
			fprintf(stderr, "Failed to load data dump at '%s': %d\n", env.data_path, err);
			goto cleanup;
		}
		const struct wprof_data_hdr *dump_hdr = worker->dump_hdr;
		const struct wprof_data_cfg *cfg = &dump_hdr->cfg;

		if (env.replay_info) {
			const int w = 20;

			printf("Replay info:\n");
			printf("============\n");
			printf("Data version: %u.%u\n", dump_hdr->version_major, dump_hdr->version_minor);
			printf("%-*s%.3lfs (%.3lfms)\n", w, "Duration:",
			       cfg->duration_ns / 1000000000.0, cfg->duration_ns / 1000000.0);
			printf("%-*s%llu (%.3lfMBs)\n", w, "Events:",
			       dump_hdr->event_cnt, dump_hdr->events_sz / 1024.0 / 1024.0);
			if (cfg->capture_stack_traces) {
				const struct wprof_stacks_hdr *shdr = (void *)dump_hdr + dump_hdr->hdr_sz + dump_hdr->stacks_off;
				printf("%-*s%u (%.3lfMBs data, %.3lfMBs strings)\n", w, "Stack traces:",
				       shdr->stack_cnt,
				       (dump_hdr->stacks_sz - shdr->strs_sz) / 1024.0 / 1024.0,
				       shdr->strs_sz / 1024.0 / 1024.0);
			} else {
				printf("%-*s%s\n", w, "Stack traces:", "NOT CAPTURED");
			}
			printf("%-*s%s\n", w, "IPIs:", cfg->capture_ipis ? "true" : "false");
			printf("%-*s%s\n", w, "Requests:", cfg->capture_requests ? "true" : "false");
			printf("%-*s%dHz\n", w, "Timer frequency:", cfg->timer_freq_hz);
			printf("%-*s", w, "Perf counters:");
			if (cfg->counter_cnt == 0) {
				printf("NONE");
			} else {
				for (int i = 0; i < cfg->counter_cnt; i++) {
					printf("%s%s", i == 0 ? "" : ", ",
					       perf_counter_defs[cfg->counter_ids[i]].alias);
				}
			}
			printf("\n");
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

		/* validate data capture config compatibility */
		if (env.capture_stack_traces == TRUE && !cfg->capture_stack_traces) {
			eprintf("replay: stack traces requested, but were not captured!\n");
			err = -EINVAL;
			goto cleanup;
		}
		if (env.capture_ipis == TRUE && !cfg->capture_ipis) {
			eprintf("replay: IPIs requested, but were not captured!\n");
			err = -EINVAL;
			goto cleanup;
		}
		if (env.capture_requests == TRUE && !cfg->capture_requests) {
			eprintf("replay: request data requested, but were not captured!\n");
			err = -EINVAL;
			goto cleanup;
		}

		/* check if all requested counters were captured and determine
		 * their actual positions in data dump
		 */
		for (int i = 0; i < env.counter_cnt; i++) {
			int pos = -1;
			for (int j = 0; j < cfg->counter_cnt; j++) {
				if (env.counter_ids[i] != cfg->counter_ids[j])
					continue;
				pos = j;
				break;
			}

			if (pos < 0) {
				eprintf("replay: counter '%s' requested, but wasn't captured\n",
					perf_counter_defs[env.counter_ids[i]].alias);
				err = -EINVAL;
				goto cleanup;
			}

			env.counter_pos[i] = pos;
		}

		env.timer_freq_hz = cfg->timer_freq_hz;

		goto skip_data_collection;
	} else {
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

		/* Init data capture settings defaults, if they were not set */
		if (env.timer_freq_hz == 0)
			env.timer_freq_hz = DEFAULT_TIMER_FREQ_HZ;
		if (env.duration_ns == 0)
			env.duration_ns = DEFAULT_DURATION_MS * 1000000ULL;
		if (env.capture_stack_traces == UNSET)
			env.capture_stack_traces = DEFAULT_CAPTURE_STACK_TRACES;
		if (env.capture_ipis == UNSET)
			env.capture_ipis = DEFAULT_CAPTURE_IPIS;
		if (env.capture_requests == UNSET)
			env.capture_requests = DEFAULT_CAPTURE_REQUESTS;
		for (int i = 0; i < env.counter_cnt; i++)
			env.counter_pos[i] = i;

		worker->dump = fopen(env.data_path, "w+");
		if (!worker->dump) {
			err = -errno;
			fprintf(stderr, "Failed to create data dump at '%s': %d\n", env.data_path, err);
			goto cleanup;
		}
		err = init_data_dump(worker);
		if (err) {
			fprintf(stderr, "Failed to initialize data dump at '%s': %d\n", env.data_path, err);
			goto cleanup;
		}
	}
	if (setvbuf(worker->dump, NULL, _IOFBF, FILE_BUF_SZ)) {
		err = -errno;
		fprintf(stderr, "Failed to set data file buffer size to %dKB: %d\n", FILE_BUF_SZ / 1024, err);
		goto cleanup;
	}

	err = setup_bpf(&bpf_state, worker, num_cpus);
	if (err) {
		fprintf(stderr, "Failed to setup BPF parts: %d\n", err);
		goto cleanup;
	}

	err = attach_bpf(&bpf_state, num_cpus);
	if (err) {
		fprintf(stderr, "Failed to attach BPF parts: %d\n", err);
		goto cleanup;
	}

	signal(SIGALRM, sig_timer);
	timer_ival.it_value.tv_sec = env.duration_ns / 1000000000;
	timer_ival.it_value.tv_usec = env.duration_ns / 1000 % 1000000;
	err = setitimer(ITIMER_REAL, &timer_ival, NULL);
	if (err < 0) {
		fprintf(stderr, "Failed to setup run duration timeout timer: %d\n", err);
		goto cleanup;
	}

	fprintf(stderr, "Running...\n");

	env.ktime_start_ns = ktime_now_ns();
	env.realtime_start_ns = ktime_to_realtime_ns(env.ktime_start_ns);
	/* env.duration_ns is already properly set */
	env.sess_start_ts = env.ktime_start_ns;
	env.sess_end_ts = env.ktime_start_ns + env.duration_ns;

	err = run_bpf(&bpf_state);
	if (err) {
		fprintf(stderr, "Failed during collecting BPF-generated data: %d\n", err);
		goto cleanup;
	}

	fprintf(stderr, "Stopping...\n");
	detach_bpf(&bpf_state, num_cpus);

	fprintf(stderr, "Draining...\n");
	drain_bpf(&bpf_state, num_cpus);

	err = finalize_events_dump(worker);
	if (err) {
		fprintf(stderr, "Failed to finalize data dump: %d\n", err);
		goto cleanup;
	}

	if (env.capture_stack_traces) {
		err = process_stack_traces(worker);
		if (err) {
			fprintf(stderr, "Failed to symbolize and dump stack traces: %d\n", err);
			goto cleanup;
		}
	}

	{
		fflush(worker->dump);
		if (fchmod(fileno(worker->dump), 0644)) {
			err = -errno;
			fprintf(stderr, "Failed to chmod() data file '%s': %d\n", env.data_path, err);
			goto cleanup;
		}
		ssize_t file_sz = file_size(worker->dump);
		fprintf(stderr, "Produced %.3lfMB data file at '%s'.\n",
			file_sz / (1024.0 * 1024.0), env.data_path);
	}

skip_data_collection:
	if (env.trace_path) {
		struct worker_state *w = worker;

		w->trace = fopen(env.trace_path, "w+");
		if (!w->trace) {
			err = -errno;
			fprintf(stderr, "Failed to create trace file '%s': %d\n", env.trace_path, err);
			goto cleanup;
		}
		if (setvbuf(w->trace, NULL, _IOFBF, FILE_BUF_SZ)) {
			err = -errno;
			fprintf(stderr, "Failed to set trace file buffer size to %dKB: %d\n", FILE_BUF_SZ / 1024, err);
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

		/* process dumped events, and generate trace */
		err = emit_trace(worker);
		if (err) {
			fprintf(stderr, "Failed to generate Perfetto trac: %d\n", err);
			goto cleanup;
		}

		fflush(worker->trace);
		ssize_t file_sz = file_size(worker->trace);
		fprintf(stderr, "Produced %.3lfMB trace file at '%s'.\n",
			file_sz / (1024.0 * 1024.0), env.trace_path);
	}
cleanup:
	cleanup_worker(worker);
	detach_bpf(&bpf_state, num_cpus);
	drain_bpf(&bpf_state, num_cpus);
	print_exit_summary(worker, bpf_state.skel, num_cpus, err);
	cleanup_bpf(&bpf_state);
	return -err;
}
