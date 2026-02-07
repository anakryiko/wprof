// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "merge.h"
#include "utils.h"
#include "wprof.h"
#include "data.h"
#include "env.h"
#include "pmu.h"
#include "cuda.h"
#include "cuda_data.h"
#include "proc.h"
#include "persist.h"
#include "stacktrace.h"
#include "../libbpf/src/strset.h"
#include "../libbpf/src/hashmap.h"

static void init_data_header(struct wprof_data_hdr *hdr)
{
	memset(hdr, 0, sizeof(*hdr));
	memcpy(hdr->magic, "WPROF", 6);
	hdr->hdr_sz = sizeof(*hdr);
	hdr->flags = 0;
	hdr->version_major = WPROF_DATA_MAJOR;
	hdr->version_minor = WPROF_DATA_MINOR;
}

int wprof_init_data(FILE *dump)
{
	int err;

	err = fseek(dump, 0, SEEK_SET);
	if (err) {
		err = -errno;
		eprintf("Failed to fseek(0): %d\n", err);
		return err;
	}

	struct wprof_data_hdr hdr;
	init_data_header(&hdr);
	hdr.flags = WPROF_DATA_FLAG_INCOMPLETE;

	if (fwrite(&hdr, sizeof(hdr), 1, dump) != 1) {
		err = -errno;
		eprintf("Failed to fwrite() header: %d\n", err);
		return err;
	}

	fflush(dump);
	fsync(fileno(dump));
	return 0;
}

int wprof_load_data_dump(struct worker_state *w)
{
	int err;

	err = fseek(w->dump, 0, SEEK_SET);
	if (err) {
		err = -errno;
		eprintf("Failed to fseek(0): %d\n", err);
		return err;
	}

	w->dump_sz = file_size(w->dump);
	w->dump_mem = mmap(NULL, w->dump_sz, PROT_READ, MAP_SHARED, fileno(w->dump), 0);
	if (w->dump_mem == MAP_FAILED) {
		err = -errno;
		eprintf("Failed to mmap data dump: %d\n", err);
		w->dump_mem = NULL;
		return err;
	}
	w->dump_hdr = w->dump_mem;

	if (w->dump_hdr->flags == WPROF_DATA_FLAG_INCOMPLETE) {
		eprintf("wprof data file is incomplete!\n");
		return -EINVAL;
	}

	if (w->dump_hdr->version_major != WPROF_DATA_MAJOR) {
		eprintf("wprof data file MAJOR version mismatch: ACTUAL is v%d.%d vs EXPECTED v%d.%d!\n",
			w->dump_hdr->version_major, w->dump_hdr->version_minor,
			WPROF_DATA_MAJOR, WPROF_DATA_MINOR);
		return -EINVAL;
	}
	/* XXX: backwards compat in the future? */
	if (w->dump_hdr->version_minor != WPROF_DATA_MINOR) {
		eprintf("wprof data file MINOR version mismatch: ACTUAL is v%d.%d vs EXPECTED v%d.%d!\n",
			w->dump_hdr->version_major, w->dump_hdr->version_minor,
			WPROF_DATA_MAJOR, WPROF_DATA_MINOR);
		return -EINVAL;
	}

	return 0;
}

static int bpf_event_cmp(const void *a, const void *b)
{
	const struct bpf_event_record *x = a;
	const struct bpf_event_record *y = b;

	if (x->e->ts == y->e->ts)
		return 0;

	return (s64)(x->e->ts - y->e->ts) < 0 ? -1 : 1;
}

static int wcuda_event_cmp(const void *a, const void *b)
{
	const struct wcuda_event *x = *(const struct wcuda_event **)a;
	const struct wcuda_event *y = *(const struct wcuda_event **)b;

	if (x->ts == y->ts)
		return 0;

	return (s64)(x->ts - y->ts) < 0 ? -1 : 1;
}

int wprof_merge_data(const char *workdir_name, struct worker_state *workers)
{
	struct hashmap *tid_cache = hashmap__new(hash_identity_fn, hash_equal_fn, NULL);
	struct persist_state ps;
	int err;

	err = persist_state_init(&ps, env.pmu_event_cnt);
	if (err)
		return err;

	for (int i = 0; i < env.pmu_event_cnt; i++) {
		persist_add_pmu_def(&ps, &env.pmu_events[i]);
	}

	/* Finalize and mmap() per-ringbuf dumps */
	for (int i = 0; i < env.ringbuf_cnt; i++) {
		struct worker_state *w = &workers[i];

		long pos = ftell(w->dump);
		fflush(w->dump);
		fsync(fileno(w->dump));

		w->dump_sz = pos;
		w->dump_mem = mmap(NULL, w->dump_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(w->dump), 0);
		if (w->dump_mem == MAP_FAILED) {
			err = -errno;
			eprintf("Failed to mmap ringbuf #%d dump file '%s': %d\n", i, w->dump_path, err);
			w->dump_mem = NULL;
			return err;
		}
		w->dump_hdr = w->dump_mem;
	}

	FILE *stacks_dump = NULL;
	char stacks_path[PATH_MAX] = "";
	if (env.requested_stack_traces) {
		snprintf(stacks_path, sizeof(stacks_path), "%s/stacks.data", workdir_name);
		stacks_dump = fopen_buffered(stacks_path, "w+");
		if (!stacks_dump) {
			err = -errno;
			eprintf("Failed to create stacks dump file '%s': %d\n", stacks_path, err);
			return err;
		}

		err = process_stack_traces(workers, env.ringbuf_cnt, stacks_dump);
		if (err) {
			eprintf("Failed to symbolize and dump stack traces: %d\n", err);
			return err;
		}
	}

	wprintf("Merging...\n");

	/* Init data dump header placeholder */
	FILE *data_dump = fopen_buffered(env.data_path, "w+");
	if (!data_dump) {
		err = -errno;
		eprintf("Failed to create final data dump at '%s': %d\n", env.data_path, err);
		return err;
	}
	err = wprof_init_data(data_dump);
	if (err) {
		eprintf("Failed to initialize data dump at '%s': %d\n", env.data_path, err);
		fclose(data_dump);
		return err;
	}

	/* Prepare per-ringbuf event streams */
	u64 events_sz = 0;
	u64 event_cnt = 0;
	struct wmerge_state {
		struct bpf_event_record *recs;
		const struct bpf_event_record *next_rec;
		u64 rec_cnt;
		u64 rec_idx;
	} *wmerges = calloc(env.ringbuf_cnt, sizeof(*wmerges));

	for (int i = 0; i < env.ringbuf_cnt; i++) {
		struct worker_state *w = &workers[i];
		struct wmerge_state *wmerge = &wmerges[i];

		void *data = w->dump_mem + sizeof(struct wprof_data_hdr);
		size_t data_sz = w->dump_sz - sizeof(struct wprof_data_hdr);

		/* re-sort events by timestamp, they can be a bit out of order */
		wmerge->rec_idx = 0;
		wmerge->rec_cnt = w->rb_handled_cnt;
		wmerge->recs = calloc(wmerge->rec_cnt, sizeof(*wmerge->recs));

		const struct bpf_event_record *rec;
		u64 idx = 0;
		for_each_bpf_event(rec, data, data_sz) {
			wmerge->recs[idx++] = *rec;
		}

		qsort(wmerge->recs, wmerge->rec_cnt, sizeof(*wmerge->recs), bpf_event_cmp);
		wmerge->next_rec = wmerge->rec_cnt > 0 ? &wmerge->recs[0] : NULL;
	}

	/* Prepare per-process CUDA event streams */
	struct wcuda_state {
		struct wcuda_data_hdr *dump_hdr;
		size_t dump_sz;
		const char *strs;
		const struct wcuda_event **recs;
		const struct wcuda_event *next_rec;
		u64 rec_cnt;
		u64 rec_idx;
	} *wcudas = calloc(env.cuda_cnt, sizeof(*wcudas));

	for (int i = 0; i < env.cuda_cnt; i++) {
		struct cuda_tracee *cuda = &env.cudas[i];
		struct wcuda_state *wcuda = &wcudas[i];

		if (cuda->state == TRACEE_INACTIVE) {
			/* expected clean shutdown case */
		} else if (cuda->state == TRACEE_SHUTDOWN_TIMEOUT) {
			eprintf("Tracee #%d (%s) timed out its shutdown, but we'll try to collect its data nevertheless!..\n",
				i, cuda_str(cuda));
		} else if (cuda->state == TRACEE_IGNORED) {
			/* expected uninteresting case, don't pollute logs */
			continue;
		} else {
			eprintf("Skipping CUDA tracing data from tracee #%d (%s, %s) as it had problems...\n",
				i, cuda_str(cuda), cuda_tracee_state_str(cuda->state));
			continue;
		}

		struct stat st;
		if (fstat(cuda->dump_fd, &st) < 0) {
			err = -errno;
			eprintf("Failed to fstat() CUDA data dump for tracee %s at '%s': %d\n",
				cuda_str(cuda), cuda->dump_path, err);
			continue;
		}

		wcuda->dump_sz = st.st_size;
		wcuda->dump_hdr = mmap(NULL, wcuda->dump_sz, PROT_READ | PROT_WRITE, MAP_SHARED, cuda->dump_fd, 0);
		if (wcuda->dump_hdr == MAP_FAILED) {
			err = -errno;
			eprintf("Failed to mmap() CUDA data dump for tracee %s at '%s': %d\n",
				cuda_str(cuda), cuda->dump_path, err);
			continue;
		}

		wcuda->strs = (void *)wcuda->dump_hdr + wcuda->dump_hdr->hdr_sz + wcuda->dump_hdr->strs_off;

		/* re-sort CUDA events because they don't come completely ordered out of CUPTI */
		wcuda->rec_idx = 0;
		wcuda->rec_cnt = wcuda->dump_hdr->event_cnt;
		wcuda->recs = calloc(wcuda->rec_cnt, sizeof(*wcuda->recs));

		struct wcuda_event_record *rec;
		u64 idx = 0;
		wcuda_for_each_event(rec, wcuda->dump_hdr) {
			wcuda->recs[idx++] = rec->e;
		}

		qsort(wcuda->recs, wcuda->rec_cnt, sizeof(*wcuda->recs), wcuda_event_cmp);
		wcuda->next_rec = wcuda->rec_cnt > 0 ? wcuda->recs[0] : NULL;
	}

	/* Merge and convert events in timestamp order */
	struct wevent wevent_buf;
	while (true) {
		int widx = -1;
		u64 ts = 0;

		for (int i = 0; i < env.ringbuf_cnt; i++) {
			const struct bpf_event_record *r = wmerges[i].next_rec;
			if (!r)
				continue;
			/* find event with smallest timestamp */
			if (widx < 0 || (s64)(r->e->ts - ts) < 0) {
				widx = i;
				ts = r->e->ts;
			}
		}
		for (int i = 0; i < env.cuda_cnt; i++) {
			const struct wcuda_event *r = wcudas[i].next_rec;
			if (!r)
				continue;
			/* find event with smallest timestamp */
			if (widx < 0 || (s64)(r->ts - ts) < 0) {
				widx = env.ringbuf_cnt + i;
				ts = r->ts;
			}
		}

		if (widx < 0) /* we are done */
			break;

		int wevent_sz;
		if (widx < env.ringbuf_cnt) {
			struct wmerge_state *wmerge = &wmerges[widx];
			const struct bpf_event_record *r = wmerge->next_rec;

			wevent_sz = persist_bpf_event(&ps, r->e, &wevent_buf);

			wmerge->rec_idx++;
			wmerge->next_rec = wmerge->rec_idx < wmerge->rec_cnt ? &wmerge->recs[wmerge->rec_idx] : NULL;
		} else {
			int cidx = widx - env.ringbuf_cnt;

			struct wcuda_state *wcuda = &wcudas[cidx];
			const struct wcuda_event *r = wcuda->next_rec;
			struct cuda_tracee *cuda = &env.cudas[cidx];

			wevent_sz = persist_cuda_event(&ps, r, &wevent_buf,
						       cuda->pid, cuda->proc_name, wcuda->strs, tid_cache);
			if (wevent_sz < 0) {
				eprintf("Failed to convert CUDA event for tracee %s: %d\n", cuda_str(cuda), wevent_sz);
				return wevent_sz;
			}

			wcuda->rec_idx++;
			wcuda->next_rec = wcuda->rec_idx < wcuda->rec_cnt ? wcuda->recs[wcuda->rec_idx] : NULL;
		}

		event_cnt += 1;
		events_sz += wevent_sz;

		if (fwrite(&wevent_buf, wevent_sz, 1, data_dump) != 1) {
			err = -errno;
			if (widx < env.ringbuf_cnt) {
				eprintf("Failed to fwrite() event from ringbuf #%d ('%s'): %d\n",
					widx, workers[widx].dump_path, err);
			} else {
				int cidx = widx - env.ringbuf_cnt;
				struct cuda_tracee *cuda = &env.cudas[cidx];
				eprintf("Failed to fwrite() event from CUDA tracee %s: %d\n",
					cuda_str(cuda), err);
			}
			return err;
		}
	}

	/* Cleanup BPF ringbuf dumps */
	for (int i = 0; i < env.ringbuf_cnt; i++) {
		struct worker_state *w = &workers[i];
		struct wmerge_state *wmerge = &wmerges[i];

		munmap(w->dump_mem, w->dump_sz);
		fclose(w->dump);
		if (!env.keep_workdir)
			unlink(w->dump_path);

		w->dump = NULL;
		free(w->dump_path);
		w->dump_path = NULL;
		w->dump_sz = 0;
		w->dump_mem = NULL;
		w->dump_hdr = NULL;

		free(wmerge->recs);
	}
	free(wmerges);

	/* Cleanup CUDA dumps */
	for (int i = 0; i < env.cuda_cnt; i++) {
		struct cuda_tracee *cuda = &env.cudas[i];
		struct wcuda_state *w = &wcudas[i];

		if (w->dump_hdr)
			munmap(w->dump_hdr, w->dump_sz);

		if (!env.keep_workdir)
			unlink(cuda->dump_path);

		free(cuda->dump_path);
		cuda->dump_path = NULL;

		zclose(cuda->dump_fd);

		free(w->recs);
		w->dump_hdr = NULL;
		w->dump_sz = 0;
	}
	free(wcudas);

	/* Cleanup tid cache */
	if (tid_cache) {
		size_t bkt;
		struct hashmap_entry *entry;

		hashmap__for_each_entry(tid_cache, entry, bkt)
			free(entry->pvalue);
		hashmap__free(tid_cache);
	}

	/* Write thread table section */
	file_pad(data_dump, 8);
	long threads_off = ftell(data_dump) - sizeof(struct wprof_data_hdr);
	size_t thread_cnt = ps.threads.count;
	size_t threads_sz = thread_cnt * sizeof(struct wevent_task);
	if (fwrite(ps.threads.entries, sizeof(struct wevent_task), thread_cnt, data_dump) != thread_cnt) {
		err = -errno;
		eprintf("Failed to fwrite() thread table: %d\n", err);
		return err;
	}

	/* Write PMU definitions section */
	file_pad(data_dump, 8);
	long pmu_defs_off = ftell(data_dump) - sizeof(struct wprof_data_hdr);
	size_t pmu_def_cnt = ps.pmu_def_cnt;
	size_t pmu_defs_sz = pmu_def_cnt * sizeof(struct wevent_pmu_def);
	if (pmu_def_cnt > 0 && fwrite(ps.pmu_defs, sizeof(struct wevent_pmu_def),
				      pmu_def_cnt, data_dump) != pmu_def_cnt) {
		err = -errno;
		eprintf("Failed to fwrite() PMU definitions: %d\n", err);
		return err;
	}

	/* Write PMU counter values section */
	file_pad(data_dump, 8);
	long pmu_vals_off = ftell(data_dump) - sizeof(struct wprof_data_hdr);
	size_t pmu_vals_cnt = ps.pmu_vals.count;
	size_t pmu_vals_item_sz = ps.pmu_def_cnt * sizeof(u64);
	size_t pmu_vals_sz = pmu_vals_cnt * pmu_vals_item_sz;
	if (pmu_vals_cnt > 0 && fwrite(ps.pmu_vals.data, pmu_vals_item_sz,
				       pmu_vals_cnt, data_dump) != pmu_vals_cnt) {
		err = -errno;
		eprintf("Failed to fwrite() PMU values: %d\n", err);
		return err;
	}

	/* Write string pool section */
	file_pad(data_dump, 8);
	long strs_off = ftell(data_dump) - sizeof(struct wprof_data_hdr);
	const char *strs_data = strset__data(ps.strs);
	size_t strs_sz = strset__data_size(ps.strs);
	if (strs_sz > 0 && fwrite(strs_data, strs_sz, 1, data_dump) != 1) {
		err = -errno;
		eprintf("Failed to fwrite() string pool: %d\n", err);
		return err;
	}

	/* ensure string section ends at 8 byte alignment, just in case */
	file_pad(data_dump, 8);

	fflush(data_dump);
	fsync(fileno(data_dump));

	/* Append stacks dump into final data dump */
	off_t stacks_off = 0;
	size_t stacks_sz = 0;
	if (stacks_dump) {
		err = file_splice_into(stacks_dump, data_dump, &stacks_off, &stacks_sz);
		if (err) {
			eprintf("Failed to merge stacks into final dump: %d\n", err);
			return err;
		}
		stacks_off -= sizeof(struct wprof_data_hdr);

		fclose(stacks_dump);
		stacks_dump = NULL;

		if (!env.keep_workdir)
			unlink(stacks_path);
	}

	persist_state_free(&ps);

	long dump_sz = ftell(data_dump);
	if (dump_sz < 0) {
		err = -errno;
		eprintf("Failed to get data dump file position: %d\n", -err);
		return err;
	}

	/* Finalize data dump header */
	struct wprof_data_hdr hdr;
	init_data_header(&hdr);

	hdr.cfg.ktime_start_ns = env.ktime_start_ns;
	hdr.cfg.realtime_start_ns = env.realtime_start_ns;
	hdr.cfg.duration_ns = env.duration_ns;

	hdr.cfg.captured_stack_traces = env.requested_stack_traces;

	for (int i = 0; i < capture_feature_cnt; i++) {
		const struct capture_feature *f = &capture_features[i];
		enum tristate *flag = (void *)&env + f->env_flag_off;

		f->cfg_set_flag(&hdr.cfg, *flag == TRUE);
	}

	hdr.cfg.timer_freq_hz = env.timer_freq_hz;
	hdr.cfg.pmu_event_cnt = env.pmu_event_cnt;

	hdr.events_off = 0;
	hdr.events_sz = events_sz;
	hdr.event_cnt = event_cnt;

	hdr.threads_off = threads_off;
	hdr.threads_sz = threads_sz;
	hdr.thread_cnt = thread_cnt;

	hdr.pmu_defs_off = pmu_defs_off;
	hdr.pmu_defs_sz = pmu_defs_sz;
	hdr.pmu_def_cnt = pmu_def_cnt;

	hdr.pmu_vals_off = pmu_vals_off;
	hdr.pmu_vals_sz = pmu_vals_sz;
	hdr.pmu_val_cnt = pmu_vals_cnt;

	hdr.strs_off = strs_off;
	hdr.strs_sz = strs_sz;

	hdr.stacks_off = stacks_off;
	hdr.stacks_sz = stacks_sz;

	err = fseek(data_dump, 0, SEEK_SET);
	if (err) {
		err = -errno;
		eprintf("Failed to fseek(0): %d\n", err);
		return err;
	}

	if (fwrite(&hdr, sizeof(hdr), 1, data_dump) != 1) {
		err = -errno;
		eprintf("Failed to fwrite() header: %d\n", err);
		return err;
	}

	fflush(data_dump);
	fsync(fileno(data_dump));

	struct worker_state *w = &workers[0];

	w->dump = data_dump;
	w->dump_path = strdup(env.data_path);
	w->dump_sz = dump_sz;
	w->dump_mem = mmap(NULL, w->dump_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(data_dump), 0);
	if (w->dump_mem == MAP_FAILED) {
		err = -errno;
		eprintf("Failed to mmap data dump '%s': %d\n", env.data_path, err);
		w->dump_mem = NULL;
		return err;
	}
	w->dump_hdr = w->dump_mem;

	err = fseek(data_dump, dump_sz, SEEK_SET);
	if (err) {
		err = -errno;
		eprintf("Failed to fseek() to end: %d\n", err);
		return err;
	}

#if DEBUG_SYMBOLIZATION
	debug_dump_stack_traces(w);
#endif

	return 0;
}
