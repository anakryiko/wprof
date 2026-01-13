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
#include "cuda.h"
#include "cuda_data.h"
#include "proc.h"
#include "../libbpf/src/strset.h"

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

static int wcuda_remap_strs(struct wcuda_event *e, enum wcuda_event_kind kind,
			    const char *strs, struct strset *strs_new)
{
	switch (kind) {
	case WCK_CUDA_MEMCPY:
		break;
	case WCK_CUDA_KERNEL:
		e->cuda_kernel.name_off = strset__add_str(strs_new, strs + e->cuda_kernel.name_off);
		break;
	case WCK_CUDA_API:
	case WCK_CUDA_MEMSET:
	case WCK_CUDA_SYNC:
		break;
	case WCK_INVALID:
		eprintf("Unrecognized wprof CUDA event kind %d!\n", e->kind);
		return -EINVAL;
	}

	return 0;
}

struct tid_cache_value {
	int host_tid;
	char thread_name[16];
};

static int wcuda_fill_task_info(struct wprof_event *w, struct wcuda_event *e,
				int pid, const char *proc_name, struct hashmap *tid_cache)
{
	w->cpu = 0;
	w->numa_node = 0;
	w->task.flags = 0;

	w->task.pid = pid;
	snprintf(w->task.pcomm, sizeof(w->task.pcomm), "%s", proc_name);

	w->task.tid = 0;
	w->task.comm[0] = '\0';

	/*
	 * For CUDA API events, resolve namespaced TID to host-level TID.
	 * Also fill out thread name, while at it.
	 */
	if (e->kind != WCK_CUDA_API)
		return 0;

	long key = ((u64)pid << 32) | (u32)e->cuda_api.tid;
	struct tid_cache_value *ti = NULL;

	if (hashmap__find(tid_cache, key, &ti)) {
		w->task.tid = ti->host_tid;
		snprintf(w->task.comm, sizeof(w->task.comm), "%s", ti->thread_name);
		return 0;
	}

	ti = calloc(1, sizeof(*ti));

	if (pid == e->cuda_api.pid) {
		/* no namespacing, no need to resolve TID */
		ti->host_tid = e->cuda_api.tid;
	} else  {
		ti->host_tid = host_tid_by_ns_tid(pid, e->cuda_api.tid);
		if (ti->host_tid < 0) {
			eprintf("FAILED to resolve host-level TID by namespaced TID %d (PID %d, %s): %d\n",
				e->cuda_api.tid, pid, proc_name, ti->host_tid);
			/* negative cache this TID so we don't do expensive look ups again */
			ti->host_tid = 0;
			ti->thread_name[0] = '\0';
			goto cache;
		}
	}

	(void)thread_name_by_tid(pid, ti->host_tid, ti->thread_name, sizeof(ti->thread_name));
cache:
	hashmap__add(tid_cache, key, ti);

	w->task.tid = ti->host_tid;
	snprintf(w->task.comm, sizeof(w->task.comm), "%s", ti->thread_name);

	return 0;
}

int wprof_merge_data(int workdir_fd, struct worker_state *workers)
{
	struct hashmap *tid_cache = hashmap__new(hash_identity_fn, hash_equal_fn, NULL);
	int err;

	/* Init data dump header placeholder */
	FILE *data_dump = fopen(env.data_path, "w+");
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
	if (setvbuf(data_dump, NULL, _IOFBF, FILE_BUF_SZ)) {
		err = -errno;
		eprintf("Failed to set data file buffer size to %dKB: %d\n", FILE_BUF_SZ / 1024, err);
		fclose(data_dump);
		return err;
	}

	/* Merge per-ringbuf and per-process CUDA dumps */
	u64 events_sz = 0;
	u64 event_cnt = 0;
	struct wprof_event_iter *iters = calloc(env.ringbuf_cnt, sizeof(*iters));
	struct wprof_event_record **recs = calloc(env.ringbuf_cnt, sizeof(*recs));

	for (int i = 0; i < env.ringbuf_cnt; i++) {
		struct worker_state *w = &workers[i];

		long pos = ftell(w->dump);
		if (pos < 0) {
			err = -errno;
			eprintf("Failed to get ringbuf #%d file position for '%s': %d\n", i, w->dump_path, err);
			return err;
		}

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

		w->dump_hdr->events_off = 0;
		w->dump_hdr->events_sz = pos - sizeof(*w->dump_hdr);
		w->dump_hdr->event_cnt = w->rb_handled_cnt;

		iters[i] = wprof_event_iter_new(w->dump_hdr);
		recs[i] = wprof_event_iter_next(&iters[i]);
	}

	struct wcuda_state {
		struct wcuda_event_iter iter;
		struct wcuda_data_hdr *dump_hdr;
		size_t dump_sz;
		const char *strs;
	} *wcudas = calloc(env.cuda_cnt, sizeof(*wcudas));
	struct wcuda_event_record **wcuda_recs = calloc(env.cuda_cnt, sizeof(*wcuda_recs));
	struct strset *wcuda_strs = strset__new(UINT_MAX, "", 1);
	for (int i = 0; i < env.cuda_cnt; i++) {
		struct cuda_tracee *cuda = &env.cudas[i];

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

		wcudas[i].dump_sz = st.st_size;
		wcudas[i].dump_hdr = mmap(NULL, wcudas[i].dump_sz, PROT_READ | PROT_WRITE, MAP_SHARED, cuda->dump_fd, 0);
		if (wcudas[i].dump_hdr == MAP_FAILED) {
			err = -errno;
			eprintf("Failed to mmap() CUDA data dump for tracee %s at '%s': %d\n",
				cuda_str(cuda), cuda->dump_path, err);
			continue;
		}

		wcudas[i].strs = (void *)wcudas[i].dump_hdr + wcudas[i].dump_hdr->hdr_sz + wcudas[i].dump_hdr->strs_off;
		wcudas[i].iter = wcuda_event_iter_new(wcudas[i].dump_hdr);
		wcuda_recs[i] = wcuda_event_iter_next(&wcudas[i].iter);
	}

	while (true) {
		int widx = -1;
		u64 ts = 0;

		for (int i = 0; i < env.ringbuf_cnt; i++) {
			struct wprof_event_record *r = recs[i];
			if (!r)
				continue;
			/* find event with smallest timestamp */
			if (widx < 0 || (s64)(r->e->ts - ts) < 0) {
				widx = i;
				ts = r->e->ts;
			}
		}
		for (int i = 0; i < env.cuda_cnt; i++) {
			struct wcuda_event_record *r = wcuda_recs[i];
			if (!r)
				continue;
			/* find event with smallest timestamp */
			if (widx < 0 || (s64)(r->e->ts - ts) < 0) {
				widx = env.ringbuf_cnt + i;
				ts = r->e->ts;
			}
		}

		if (widx < 0) /* we are done */
			break;

		char data_buf[sizeof(size_t) + max(sizeof(struct wprof_event), sizeof(struct wcuda_event))];
		const void *data;
		size_t data_sz;

		if (widx < env.ringbuf_cnt) {
			struct wprof_event_record *r = recs[widx];

			event_cnt += 1;
			events_sz += r->sz;

			data = (const void *)r->e - sizeof(size_t);
			data_sz = r->sz + sizeof(size_t);

			recs[widx] = wprof_event_iter_next(&iters[widx]);
		} else {
			int cidx = widx - env.ringbuf_cnt;
			struct wcuda_event_record *r = wcuda_recs[cidx];
			struct cuda_tracee *cuda = &env.cudas[cidx];

			const size_t wcuda_data_off = offsetof(struct wcuda_event, __wcuda_data);
			const size_t wprof_data_off = offsetof(struct wprof_event, __wprof_data);

			/* prepare wcuda event with 8 byte length prefix */
			data_sz = r->e->sz + wprof_data_off - wcuda_data_off;
			memcpy(data_buf, &data_sz, sizeof(data_sz));

			event_cnt += 1;
			events_sz += data_sz;

			/*
			 * Copy CUDA-specific parts over wprof_event layout,
			 * skipping common fields and task-identification data
			 */

			void *wcuda_payload = (void *)data_buf + sizeof(size_t) + wprof_data_off;
			memcpy(wcuda_payload, (void *)r->e + wcuda_data_off, r->e->sz - wcuda_data_off);
			struct wcuda_event *e = wcuda_payload - wcuda_data_off;
			err = wcuda_remap_strs(e, r->e->kind, wcudas[cidx].strs, wcuda_strs);
			if (err) {
				eprintf("Failed to remap strings for CUDA dump event tracee %s at '%s': %d\n",
					cuda_str(cuda), cuda->dump_path, err);
				return err;
			}

			struct wprof_event *w = (void *)data_buf + sizeof(size_t);
			w->sz = data_sz;
			w->flags = 0;
			w->kind = (int)r->e->kind;
			w->ts = r->e->ts;

			err = wcuda_fill_task_info(w, r->e, cuda->pid, cuda->proc_name, tid_cache);
			if (err) {
				eprintf("Failed to fill out CUDA event task info for tracee %s at '%s': %d\n",
					cuda_str(cuda), cuda->dump_path, err);
				return err;
			}

			data = data_buf;
			data_sz = r->e->sz + sizeof(size_t) + wprof_data_off - wcuda_data_off;

			wcuda_recs[cidx] = wcuda_event_iter_next(&wcudas[cidx].iter);
		}

		/* we prepend each with size prefix */
		if (fwrite(data, data_sz, 1, data_dump) != 1) {
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

	for (int i = 0; i < env.ringbuf_cnt; i++) {
		struct worker_state *w = &workers[i];
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
	}
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

		w->dump_hdr = NULL;
		w->dump_sz = 0;
	}

	if (tid_cache) {
		size_t bkt;
		struct hashmap_entry *entry;

		hashmap__for_each_entry(tid_cache, entry, bkt)
			free(entry->pvalue);
		hashmap__free(tid_cache);
	}

	long strs_off = ftell(data_dump);
	if (strs_off < 0) {
		err = -errno;
		eprintf("Failed to get data dump file position: %d\n", -err);
		return err;
	}

	const char *strs_data = strset__data(wcuda_strs);
	size_t strs_sz = strset__data_size(wcuda_strs);
	if (fwrite(strs_data, 1, strs_sz, data_dump) != strs_sz) {
		err = -errno;
		eprintf("Failed to fwrite() final strings dump: %d\n", err);
		return err;
	}

	fflush(data_dump);
	fsync(fileno(data_dump));

	long dump_sz;
	dump_sz = ftell(data_dump);
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
	hdr.cfg.counter_cnt = env.counter_cnt;
	memcpy(&hdr.cfg.counter_ids, env.counter_ids, sizeof(env.counter_ids));

	hdr.events_off = 0;
	hdr.events_sz = events_sz;
	hdr.event_cnt = event_cnt;

	hdr.strs_off = strs_off - sizeof(struct wprof_data_hdr);
	hdr.strs_sz = strs_sz;

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

	return 0;
}
