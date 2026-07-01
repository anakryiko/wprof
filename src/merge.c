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
#include <sys/utsname.h>
#include <sys/resource.h>
#include <bpf/bpf.h>

#include "merge.h"
#include "wprof.skel.h"
#include "utils.h"
#include "wprof.h"
#include "data.h"
#include "env.h"
#include "pmu.h"
#include "cuda_data.h"
#include "pytrace.h"
#include "pytrace_data.h"
#include "pytorch_data.h"
#include "injmgr.h"
#include "proc.h"
#include "persist.h"
#include "stacktrace.h"
#include "ksyms.h"
#include "utrace_cfg.h"
#include "strs.h"
#include "../libbpf/src/strset.h"
#include "../libbpf/src/hashmap.h"
#include "blobset.h"
#include "wrust.h"

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
	hdr.flags = WDF_INCOMPLETE;

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

	if (w->dump_hdr->flags == WDF_INCOMPLETE) {
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

/* arg is the kind-specific union payload: a stroff, bloboff, or on/off value. */
static void add_extra(struct wprof_extra_param **extras, u64 *cnt,
		      enum wprof_extra_param_kind kind, u32 arg)
{
	*extras = realloc(*extras, (*cnt + 1) * sizeof(**extras));
	(*extras)[*cnt] = (struct wprof_extra_param){ .kind = kind, .stroff = arg };
	*cnt += 1;
}

static void collect_extras(struct persist_state *ps, struct wprof_extra_param **extras, u64 *cnt)
{
	for (int i = 0; i < env.allow_pid_cnt; i++)
		add_extra(extras, cnt, WEXTRA_FILTER_PID_ALLOW, persist_stroff(ps, sfmt("%d", env.allow_pids[i])));
	for (int i = 0; i < env.deny_pid_cnt; i++)
		add_extra(extras, cnt, WEXTRA_FILTER_PID_DENY, persist_stroff(ps, sfmt("%d", env.deny_pids[i])));
	for (int i = 0; i < env.allow_tid_cnt; i++)
		add_extra(extras, cnt, WEXTRA_FILTER_TID_ALLOW, persist_stroff(ps, sfmt("%d", env.allow_tids[i])));
	for (int i = 0; i < env.deny_tid_cnt; i++)
		add_extra(extras, cnt, WEXTRA_FILTER_TID_DENY, persist_stroff(ps, sfmt("%d", env.deny_tids[i])));
	for (int i = 0; i < env.allow_pname_cnt; i++)
		add_extra(extras, cnt, WEXTRA_FILTER_PNAME_ALLOW, persist_stroff(ps, env.allow_pnames[i]));
	for (int i = 0; i < env.deny_pname_cnt; i++)
		add_extra(extras, cnt, WEXTRA_FILTER_PNAME_DENY, persist_stroff(ps, env.deny_pnames[i]));
	for (int i = 0; i < env.allow_tname_cnt; i++)
		add_extra(extras, cnt, WEXTRA_FILTER_TNAME_ALLOW, persist_stroff(ps, env.allow_tnames[i]));
	for (int i = 0; i < env.deny_tname_cnt; i++)
		add_extra(extras, cnt, WEXTRA_FILTER_TNAME_DENY, persist_stroff(ps, env.deny_tnames[i]));
	if (env.allow_idle)
		add_extra(extras, cnt, WEXTRA_FILTER_IDLE_ALLOW, 0);
	if (env.deny_idle)
		add_extra(extras, cnt, WEXTRA_FILTER_IDLE_DENY, 0);
	if (env.allow_kthread)
		add_extra(extras, cnt, WEXTRA_FILTER_KTHREAD_ALLOW, 0);
	if (env.deny_kthread)
		add_extra(extras, cnt, WEXTRA_FILTER_KTHREAD_DENY, 0);

	if (env.utrace_cfg_cnt > 0) {
		struct sbuf sb = sbuf_new();

		for (int i = 0; i < env.utrace_cfg_cnt; i++) {
			sbuf_reset(&sb);
			utrace_cfg_format(&env.utrace_cfgs[i], &sb);
			add_extra(extras, cnt, WEXTRA_UTRACE_DEF, persist_stroff(ps, sbuf_str(&sb)));
		}

		sbuf_free(&sb);
	}

	for (int i = 0; i < env.pmu_real_cnt; i++) {
		if (env.pmu_reals[i].spec)
			add_extra(extras, cnt, WEXTRA_PMU, persist_stroff(ps, env.pmu_reals[i].spec));
	}
	for (int i = 0; i < env.pmu_deriv_cnt; i++) {
		if (env.pmu_derivs[i].spec)
			add_extra(extras, cnt, WEXTRA_PMU, persist_stroff(ps, env.pmu_derivs[i].spec));
	}
	for (int i = 0; i < env.pmu_event_cnt; i++) {
		if (env.pmu_events[i].spec)
			add_extra(extras, cnt, WEXTRA_PMU_EVENT, persist_stroff(ps, env.pmu_events[i].spec));
	}

	if (env.prepare_spec_str)
		add_extra(extras, cnt, WEXTRA_PREPARE_SPEC, persist_stroff(ps, env.prepare_spec_str));
	if (env.activate_spec_str)
		add_extra(extras, cnt, WEXTRA_ACTIVATE_SPEC, persist_stroff(ps, env.activate_spec_str));
	if (env.flightrec) {
		char spec[64];
		int n = 0;
		if (env.fr_keep_time_ns)
			n += snprintf(spec + n, sizeof(spec) - n, "%s", fmt_time_units(env.fr_keep_time_ns));
		if (env.fr_keep_size)
			n += snprintf(spec + n, sizeof(spec) - n, "%s%s", n ? "," : "", fmt_size_units(env.fr_keep_size));
		if (n == 0)
			snprintf(spec, sizeof(spec), "0s,0b");	/* both unlimited */
		add_extra(extras, cnt, WEXTRA_FR_SPEC, persist_stroff(ps, spec));
	}

	/* persist emit (-e) options that differ from default, storing the on/off value */
	for (int i = 0; i < emit_feature_cnt; i++) {
		const struct emit_feature *f = &emit_features[i];
		enum tristate *flag = (void *)&env + f->env_flag_off;

		if (*flag != f->default_val)
			add_extra(extras, cnt, f->kind, *flag == TRUE);
	}

	/* Persist built-in and user-provided metadata */
	char hostname[256], uuid[UUID_STR_LEN];
	struct utsname uts;

	gen_uuid(uuid);
	add_extra(extras, cnt, WEXTRA_METADATA, persist_stroff(ps, sfmt("uuid=%s", uuid)));

	if (gethostname(hostname, sizeof(hostname)) == 0)
		add_extra(extras, cnt, WEXTRA_METADATA, persist_stroff(ps, sfmt("hostname=%s", hostname)));

	if (uname(&uts) == 0) {
		add_extra(extras, cnt, WEXTRA_METADATA, persist_stroff(ps, sfmt("kernel=%s", uts.release)));
		add_extra(extras, cnt, WEXTRA_METADATA, persist_stroff(ps, sfmt("arch=%s", uts.machine)));
	}

	for (int i = 0; i < env.metadata_cnt; i++)
		add_extra(extras, cnt, WEXTRA_METADATA, persist_stroff(ps, env.metadata[i]));
}

static int stat_elem_cnt(enum wprof_stat_id id, int rb_cnt, int cpu_cnt,
			 int prog_cnt, int cuda_cnt, int py_cnt, int pmu_cnt)
{
	switch (id) {
	case WSTAT_INVALID:
		return __WSTAT_CNT + 1;
	/* global + per-rb + per-cpu */
	case WSTAT_RB_DROPS:
	case WSTAT_RB_RESCUES:
	case WSTAT_RB_MISSES:
	case WSTAT_RB_HANDLED_CNT:
		return 1 + rb_cnt + cpu_cnt;
	/* global + per-rb */
	case WSTAT_RB_HANDLED_SZ:
	case WSTAT_RB_IGNORED_CNT:
	case WSTAT_RB_IGNORED_SZ:
		return 1 + rb_cnt;
	/* global + per-cpu */
	case WSTAT_TASK_STATE_DROPS:
	case WSTAT_TASK_STORAGE_FALLBACKS:
	case WSTAT_REQ_STATE_DROPS:
	case WSTAT_PYSTACKS_ATTEMPTED:
	case WSTAT_PYSTACKS_FOUND:
		return 1 + cpu_cnt;
	/* global only */
	case WSTAT_RUSAGE_UTIME_US:
	case WSTAT_RUSAGE_STIME_US:
	case WSTAT_RUSAGE_MAXRSS_KB:
	case WSTAT_RUSAGE_MAJFLT:
	case WSTAT_RUSAGE_MINFLT:
	case WSTAT_RUSAGE_INBLOCK:
	case WSTAT_RUSAGE_OUBLOCK:
	case WSTAT_RUSAGE_NVCSW:
	case WSTAT_RUSAGE_NIVCSW:
		return 1;
	/* per-program */
	case WSTAT_PROG_NAME:
	case WSTAT_PROG_RUN_CNT:
	case WSTAT_PROG_RUN_TIME_NS:
	case WSTAT_PROG_RECURSION_MISSES:
		return 1 + prog_cnt;
	/* per-CUDA tracee */
	case WSTAT_CUDA_NAME:
	case WSTAT_CUDA_STATE:
	case WSTAT_CUDA_REC_CNT:
	case WSTAT_CUDA_DROP_CNT:
	case WSTAT_CUDA_ERR_CNT:
	case WSTAT_CUDA_IGNORE_CNT:
	case WSTAT_CUDA_BUF_CNT:
	case WSTAT_CUDA_DATA_SZ:
		return 1 + cuda_cnt;
	/* per-pytrace tracee */
	case WSTAT_PYTRACE_NAME:
	case WSTAT_PYTRACE_STATE:
	case WSTAT_PYTRACE_EVENT_CNT:
	case WSTAT_PYTRACE_CODE_CACHE_CNT:
	case WSTAT_PYTORCH_EVENT_CNT:
		return 1 + py_cnt;
	/* per-PMU (real counters only); index 0 is global/unused */
	case WSTAT_PMU_ACTIVE_FRAC:
		return 1 + pmu_cnt;
	default:
		BUG("unknown stat id %d\n", id);
	}
}

static struct wprof_stats *prepare_stats(struct persist_state *ps, struct worker_state *workers)
{
	struct wprof_bpf *skel = env.skel;
	int rb_cnt = env.ringbuf_cnt;
	int cpu_cnt = env.num_cpus;
	int cuda_cnt = 0, py_cnt = 0;
	for (int i = 0; i < env.injectee_cnt; i++) {
		if (env.injectees[i].detect_feats & INJ_FEAT_CUDA)
			cuda_cnt++;
		if (env.injectees[i].detect_feats & (INJ_FEAT_PYTRACE | INJ_FEAT_PYTORCH))
			py_cnt++;
	}
	int pmu_cnt = env.pmu_real_cnt;
	int prog_cnt = 0;

	struct bpf_program *p;
	bpf_object__for_each_program(p, skel->obj) {
		if (bpf_program__fd(p) >= 0)
			prog_cnt++;
	}

	/*
	 * s->stats[0] is always zero
	 * s->stats[__WSTAT_CNT] is total count of stats in s->stats[]
	 */
	int offs[__WSTAT_CNT + 1];
	offs[0] = 0;
	for (int i = 1; i <= __WSTAT_CNT; i++)
		offs[i] = offs[i - 1] + stat_elem_cnt(i - 1, rb_cnt, cpu_cnt, prog_cnt, cuda_cnt, py_cnt, pmu_cnt);

	u32 sz = sizeof(struct wprof_stats) + offs[__WSTAT_CNT] * sizeof(u64);
	struct wprof_stats *s = calloc(1, sz);
	s->sz = sz;
	s->stat_cnt = __WSTAT_CNT;
	s->cpu_cnt = cpu_cnt;
	s->rb_cnt = rb_cnt;
	s->prog_cnt = prog_cnt;
	s->cuda_cnt = cuda_cnt;
	s->py_cnt = py_cnt;
	s->pmu_cnt = pmu_cnt;
	s->ringbuf_sz = env.ringbuf_sz;
	s->task_state_sz = env.task_state_sz;

	for (int i = 1; i <= __WSTAT_CNT; i++)
		s->stats[i] = offs[i];

	/* Worker stats (per-rb) */
	u64 *rb_handled_sz = wstats(s, WSTAT_RB_HANDLED_SZ, NULL);
	u64 *rb_ignored_cnt = wstats(s, WSTAT_RB_IGNORED_CNT, NULL);
	u64 *rb_ignored_sz = wstats(s, WSTAT_RB_IGNORED_SZ, NULL);

	for (int i = 0; i < rb_cnt; i++) {
		struct worker_state *w = &workers[i];

		/* global */
		rb_handled_sz[0] += w->rb_handled_sz;
		rb_ignored_cnt[0] += w->rb_ignored_cnt;
		rb_ignored_sz[0] += w->rb_ignored_sz;

		/* per-rb */
		rb_handled_sz[1 + i] = w->rb_handled_sz;
		rb_ignored_cnt[1 + i] = w->rb_ignored_cnt;
		rb_ignored_sz[1 + i] = w->rb_ignored_sz;
	}

	/* BPF map stats (per-cpu) */
	int zero = 0;
	struct wprof_bpf_stats bpf_stats[cpu_cnt];
	int err = bpf_map__lookup_elem(skel->maps.stats, &zero, sizeof(int),
				       bpf_stats, sizeof(bpf_stats[0]) * cpu_cnt, 0);
	if (err) {
		eprintf("Failed to fetch BPF-side stats for persistence: %d\n", err);
		goto skip_bpf_stats;
	}

	u64 *rb_handled_cnt = wstats(s, WSTAT_RB_HANDLED_CNT, NULL);
	u64 *rb_drops = wstats(s, WSTAT_RB_DROPS, NULL);
	u64 *rb_rescues = wstats(s, WSTAT_RB_RESCUES, NULL);
	u64 *rb_misses = wstats(s, WSTAT_RB_MISSES, NULL);
	u64 *task_drops = wstats(s, WSTAT_TASK_STATE_DROPS, NULL);
	u64 *task_fallbacks = wstats(s, WSTAT_TASK_STORAGE_FALLBACKS, NULL);
	u64 *req_drops = wstats(s, WSTAT_REQ_STATE_DROPS, NULL);
	u64 *pystacks_attempted = wstats(s, WSTAT_PYSTACKS_ATTEMPTED, NULL);
	u64 *pystacks_found = wstats(s, WSTAT_PYSTACKS_FOUND, NULL);

	for (int i = 0; i < cpu_cnt; i++) {
		struct wprof_bpf_stats *bs = &bpf_stats[i];
		int rb_id = skel->data_rb_cpu_map->rb_cpu_map[i];

		/* global */
		rb_handled_cnt[0] += bs->rb_handled;
		rb_drops[0] += bs->rb_drops;
		rb_rescues[0] += bs->rb_rescues;
		rb_misses[0] += bs->rb_misses;

		/* per-rb */
		rb_handled_cnt[1 + rb_id] += bs->rb_handled;
		rb_drops[1 + rb_id] += bs->rb_drops;
		rb_rescues[1 + rb_id] += bs->rb_rescues;
		rb_misses[1 + rb_id] += bs->rb_misses;

		/* per-cpu */
		rb_handled_cnt[1 + rb_cnt + i] = bs->rb_handled;
		rb_drops[1 + rb_cnt + i] = bs->rb_drops;
		rb_rescues[1 + rb_cnt + i] = bs->rb_rescues;
		rb_misses[1 + rb_cnt + i] = bs->rb_misses;

		/* global */
		task_drops[0] += bs->task_state_drops;
		task_fallbacks[0] += bs->task_storage_fallbacks;
		req_drops[0] += bs->req_state_drops;
		pystacks_attempted[0] += bs->pystacks_attempted;
		pystacks_found[0] += bs->pystacks_found;

		/* per-cpu */
		task_drops[1 + i] = bs->task_state_drops;
		task_fallbacks[1 + i] = bs->task_storage_fallbacks;
		req_drops[1 + i] = bs->req_state_drops;
		pystacks_attempted[1 + i] = bs->pystacks_attempted;
		pystacks_found[1 + i] = bs->pystacks_found;
	}
skip_bpf_stats:

	/* BPF program stats (per-prog) */
	u64 *prog_name = wstats(s, WSTAT_PROG_NAME, NULL);
	u64 *prog_run_cnt = wstats(s, WSTAT_PROG_RUN_CNT, NULL);
	u64 *prog_run_time = wstats(s, WSTAT_PROG_RUN_TIME_NS, NULL);
	u64 *prog_rec_misses = wstats(s, WSTAT_PROG_RECURSION_MISSES, NULL);

	int idx = 0;
	struct bpf_program *prog;
	bpf_object__for_each_program(prog, skel->obj) {
		if (bpf_program__fd(prog) < 0)
			continue;

		prog_name[1 + idx] = persist_stroff(ps, bpf_program__name(prog));

		struct bpf_prog_info info;
		u32 info_sz = sizeof(info);
		memset(&info, 0, sizeof(info));
		err = bpf_prog_get_info_by_fd(bpf_program__fd(prog), &info, &info_sz);
		if (err) {
			eprintf("!!! %s: failed to fetch prog info: %d\n",
				bpf_program__name(prog), err);
			idx++;
			continue;
		}

		/* per-prog */
		prog_run_cnt[1 + idx] = info.run_cnt;
		prog_run_time[1 + idx] = info.run_time_ns;
		prog_rec_misses[1 + idx] = info.recursion_misses;

		/* global */
		prog_run_cnt[0] += info.run_cnt;
		prog_run_time[0] += info.run_time_ns;
		prog_rec_misses[0] += info.recursion_misses;
		idx++;
	}

	/* CUDA tracee stats (per-tracee) */
	u64 *cuda_name = wstats(s, WSTAT_CUDA_NAME, NULL);
	u64 *cuda_state = wstats(s, WSTAT_CUDA_STATE, NULL);
	u64 *cuda_rec_cnt = wstats(s, WSTAT_CUDA_REC_CNT, NULL);
	u64 *cuda_drop_cnt = wstats(s, WSTAT_CUDA_DROP_CNT, NULL);
	u64 *cuda_err_cnt = wstats(s, WSTAT_CUDA_ERR_CNT, NULL);
	u64 *cuda_ignore_cnt = wstats(s, WSTAT_CUDA_IGNORE_CNT, NULL);
	u64 *cuda_buf_cnt = wstats(s, WSTAT_CUDA_BUF_CNT, NULL);
	u64 *cuda_data_sz = wstats(s, WSTAT_CUDA_DATA_SZ, NULL);

	int ci = 0;
	for (int i = 0; i < env.injectee_cnt; i++) {
		struct injectee *inj = &env.injectees[i];

		if (!(inj->detect_feats & INJ_FEAT_CUDA))
			continue;

		/* per-tracee */
		cuda_name[1 + ci] = persist_stroff(ps, injectee_str(inj));
		cuda_state[1 + ci] = inj->state;

		if (inj->state == INJECTEE_IGNORED || !inj->ctx) {
			ci++;
			continue;
		}

		cuda_rec_cnt[1 + ci] = inj->ctx->cupti_rec_cnt;
		cuda_drop_cnt[1 + ci] = inj->ctx->cupti_drop_cnt;
		cuda_err_cnt[1 + ci] = inj->ctx->cupti_err_cnt;
		cuda_ignore_cnt[1 + ci] = inj->ctx->cupti_ignore_cnt;
		cuda_buf_cnt[1 + ci] = inj->ctx->cupti_buf_cnt;
		cuda_data_sz[1 + ci] = inj->ctx->cupti_data_sz;

		/* global */
		cuda_rec_cnt[0] += inj->ctx->cupti_rec_cnt;
		cuda_drop_cnt[0] += inj->ctx->cupti_drop_cnt;
		cuda_err_cnt[0] += inj->ctx->cupti_err_cnt;
		cuda_ignore_cnt[0] += inj->ctx->cupti_ignore_cnt;
		cuda_buf_cnt[0] += inj->ctx->cupti_buf_cnt;
		cuda_data_sz[0] += inj->ctx->cupti_data_sz;

		ci++;
	}

	/* PyTrace tracee stats (per-tracee) */
	u64 *pytrace_name = wstats(s, WSTAT_PYTRACE_NAME, NULL);
	u64 *pytrace_state = wstats(s, WSTAT_PYTRACE_STATE, NULL);
	u64 *pytrace_event_cnt = wstats(s, WSTAT_PYTRACE_EVENT_CNT, NULL);
	u64 *pytrace_code_cache_cnt = wstats(s, WSTAT_PYTRACE_CODE_CACHE_CNT, NULL);
	u64 *pytorch_event_cnt = wstats(s, WSTAT_PYTORCH_EVENT_CNT, NULL);

	int pi = 0;
	for (int i = 0; i < env.injectee_cnt; i++) {
		struct injectee *inj = &env.injectees[i];

		if (!(inj->detect_feats & (INJ_FEAT_PYTRACE | INJ_FEAT_PYTORCH)))
			continue;

		/* per-tracee */
		pytrace_name[1 + pi] = persist_stroff(ps, injectee_str(inj));
		pytrace_state[1 + pi] = inj->state;

		if (!inj->ctx) {
			pi++;
			continue;
		}

		pytrace_event_cnt[1 + pi] = inj->ctx->pytrace_event_cnt;
		pytrace_code_cache_cnt[1 + pi] = inj->ctx->pytrace_code_cache_cnt;
		pytorch_event_cnt[1 + pi] = inj->ctx->pytorch_event_cnt;

		/* global */
		pytrace_event_cnt[0] += inj->ctx->pytrace_event_cnt;
		pytrace_code_cache_cnt[0] += inj->ctx->pytrace_code_cache_cnt;
		pytorch_event_cnt[0] += inj->ctx->pytorch_event_cnt;

		pi++;
	}

	double *pmu_active_frac = (double *)wstats(s, WSTAT_PMU_ACTIVE_FRAC, NULL);
	for (int i = 0; i < pmu_cnt; i++)
		pmu_active_frac[1 + i] = env.pmu_reals[i].active_frac;

	return s;
}

static void finalize_stats(struct wprof_stats *s)
{
	struct rusage ru;
	if (getrusage(RUSAGE_SELF, &ru)) {
		eprintf("Failed to get wprof's resource usage data!..\n");
		return;
	}

	u64 *utime_us = wstats(s, WSTAT_RUSAGE_UTIME_US, NULL);
	u64 *stime_us = wstats(s, WSTAT_RUSAGE_STIME_US, NULL);
	u64 *maxrss_kb = wstats(s, WSTAT_RUSAGE_MAXRSS_KB, NULL);
	u64 *majflt = wstats(s, WSTAT_RUSAGE_MAJFLT, NULL);
	u64 *minflt = wstats(s, WSTAT_RUSAGE_MINFLT, NULL);
	u64 *inblock = wstats(s, WSTAT_RUSAGE_INBLOCK, NULL);
	u64 *oublock = wstats(s, WSTAT_RUSAGE_OUBLOCK, NULL);
	u64 *nvcsw = wstats(s, WSTAT_RUSAGE_NVCSW, NULL);
	u64 *nivcsw = wstats(s, WSTAT_RUSAGE_NIVCSW, NULL);

	/* global */
	utime_us[0] = (u64)ru.ru_utime.tv_sec * 1000000 + ru.ru_utime.tv_usec;
	stime_us[0] = (u64)ru.ru_stime.tv_sec * 1000000 + ru.ru_stime.tv_usec;
	maxrss_kb[0] = ru.ru_maxrss;
	majflt[0] = ru.ru_majflt;
	minflt[0] = ru.ru_minflt;
	inblock[0] = ru.ru_inblock;
	oublock[0] = ru.ru_oublock;
	nvcsw[0] = ru.ru_nvcsw;
	nivcsw[0] = ru.ru_nivcsw;
}

int wprof_persist_data(const char *workdir_name, struct worker_state *workers,
		       struct wppq *fr_pq, u64 sess_min_ts, u64 sess_max_ts)
{
	struct persist_state ps;
	int err;

	err = persist_state_init(&ps, env.pmu_real_cnt);
	if (err)
		return err;

	for (int i = 0; i < env.pmu_real_cnt; i++)
		persist_add_pmu_def(&ps, &env.pmu_reals[i]);
	for (int i = 0; i < env.pmu_deriv_cnt; i++)
		persist_add_pmu_def(&ps, &env.pmu_derivs[i]);
	for (int i = 0; i < env.pmu_event_cnt; i++)
		persist_add_pmu_def(&ps, &env.pmu_events[i]);

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
	}

	/*
	 * Drain the flight-recorder's retained chunks into per-worker buckets,
	 * chained intrusively via c->next. Each worker's events then come from
	 * its current chunk PLUS these completed ones. Non-flightrec passes a
	 * NULL PQ, so fr_lists stays all-NULL and merge behaves as before.
	 */
	struct fr_chunk **fr_lists = calloc(env.ringbuf_cnt, sizeof(*fr_lists));
	while (fr_pq && !wppq_empty(fr_pq)) {
		struct fr_chunk *c = wppq_pop(fr_pq);

		c->next = fr_lists[c->worker_idx];
		fr_lists[c->worker_idx] = c;
	}

	/* Collect and symbolize stack traces, dump to separate file */
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

	/* Create PMU values dump file */
	FILE *pmu_vals_dump = NULL;
	char pmu_vals_path[PATH_MAX] = "";
	if (env.pmu_real_cnt > 0) {
		snprintf(pmu_vals_path, sizeof(pmu_vals_path), "%s/pmu_vals.data", workdir_name);
		pmu_vals_dump = fopen_buffered(pmu_vals_path, "w+");
		if (!pmu_vals_dump) {
			err = -errno;
			eprintf("Failed to create PMU values dump file '%s': %s\n", pmu_vals_path, errstr(err));
			return err;
		}
		/* write null entry (index 0 reserved) */
		u64 zeros[MAX_REAL_PMU_COUNTERS] = {};
		if (fwrite(zeros, env.pmu_real_cnt * sizeof(u64), 1, pmu_vals_dump) != 1) {
			err = -errno;
			eprintf("Failed to write null PMU values entry: %s\n", errstr(err));
			return err;
		}
		ps.pmu_vals.dump = pmu_vals_dump;
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

	/* Sparse timestamp index, built as events stream out in sorted order */
	struct wprof_tsidx_ent *tsidx = NULL;
	u64 tsidx_cnt = 0, tsidx_cap = 0;
	u64 tsidx_next_ts = env.ktime_start_ns;
	struct wmerge_state {
		struct wrust_ts_ptr *recs;
		const struct wrust_ts_ptr *next_rec;
		u64 rec_cnt;
		u64 rec_idx;
	} *wmerges = calloc(env.ringbuf_cnt, sizeof(*wmerges));

	for (int i = 0; i < env.ringbuf_cnt; i++) {
		struct worker_state *w = &workers[i];
		struct wmerge_state *wmerge = &wmerges[i];

		void *data = w->dump_mem;
		size_t data_sz = w->dump_sz;

		/*
		 * re-sort events by timestamp, they can be a bit out of order.
		 * Size from the current chunk's own event count, not the worker's
		 * cumulative rb_handled_cnt: with flight-recorder rotation only the
		 * current chunk is mmap()ed here, so rb_handled_cnt over-counts (it
		 * spans handed-off chunks too). Without rotation the two are equal,
		 * so non-flightrec output is unchanged.
		 *
		 * With flight-recorder, also fold in the completed chunks the FR
		 * thread retained for this worker; size recs[] by the summed
		 * per-chunk event_cnt.
		 */
		wmerge->rec_idx = 0;
		wmerge->rec_cnt = w->cur_chunk->event_cnt;
		for (struct fr_chunk *c = fr_lists[i]; c; c = c->next)
			wmerge->rec_cnt += c->event_cnt;
		wmerge->recs = calloc(wmerge->rec_cnt, sizeof(*wmerge->recs));

		const struct bpf_event_record *rec;
		u64 idx = 0;
		for_each_bpf_event(rec, data, data_sz) {
			wmerge->recs[idx++] = (struct wrust_ts_ptr){ .ts = rec->e->ts, .ptr = rec->e };
		}

		/*
		 * Completed chunks are headerless raw event streams, same format as
		 * the current chunk. mmap each read-only and read its events; keep
		 * the mapping alive (c->mmap) because recs[].ptr points into it --
		 * the merge loop below dereferences those pointers. Unmapped in the
		 * cleanup loop.
		 */
		for (struct fr_chunk *c = fr_lists[i]; c; c = c->next) {
			int fd = open(c->path, O_RDONLY);
			if (fd < 0) {
				err = -errno;
				eprintf("Failed to open flight-recorder chunk '%s': %d\n", c->path, err);
				return err;
			}

			c->mmap = mmap(NULL, c->byte_sz, PROT_READ, MAP_SHARED, fd, 0);
			close(fd);
			if (c->mmap == MAP_FAILED) {
				err = -errno;
				eprintf("Failed to mmap flight-recorder chunk '%s': %d\n", c->path, err);
				c->mmap = NULL;
				return err;
			}

			for_each_bpf_event(rec, c->mmap, c->byte_sz)
				wmerge->recs[idx++] = (struct wrust_ts_ptr){ .ts = rec->e->ts, .ptr = rec->e };
		}

		/* chunks are NOT time-disjoint, so sort the combined stream */
		wrust_sort_events_by_ts(wmerge->recs, wmerge->rec_cnt);
		wmerge->next_rec = wmerge->rec_cnt > 0 ? &wmerge->recs[0] : NULL;
	}

	/*
	 * Prepare per-process event streams (CUDA, PyTrace, PyTorch), each keyed
	 * back to the injectee it came from. A single injectee contributes to
	 * several streams when it was injected for multiple features.
	 */
	struct wcuda_state {
		struct wcuda_data_hdr *dump_hdr;
		size_t dump_sz;
		const char *strs;
		struct wrust_ts_ptr *recs;
		const struct wrust_ts_ptr *next_rec;
		u64 rec_cnt;
		u64 rec_idx;
		int tracee_idx;		/* index into env.injectees[] */
	} *wcudas = calloc(env.injectee_cnt, sizeof(*wcudas));
	int wcuda_cnt = 0;

	struct wpytrace_state {
		struct wpytrace_data_hdr *dump_hdr;
		size_t dump_sz;
		const char *strs;
		struct wpytrace_code_entry *code_map;
		u64 code_map_cnt;
		struct wrust_ts_ptr *recs;
		const struct wrust_ts_ptr *next_rec;
		u64 rec_cnt;
		u64 rec_idx;
		int tracee_idx;		/* index into env.injectees[] */
	} *wpytraces = calloc(env.injectee_cnt, sizeof(*wpytraces));
	int wpytrace_cnt = 0;

	struct wpytorch_state {
		struct wpytorch_data_hdr *dump_hdr;
		size_t dump_sz;
		const char *strs;
		struct wrust_ts_ptr *recs;
		const struct wrust_ts_ptr *next_rec;
		u64 rec_cnt;
		u64 rec_idx;
		int tracee_idx;		/* index into env.injectees[] */
	} *wpytorches = calloc(env.injectee_cnt, sizeof(*wpytorches));
	int wpytorch_cnt = 0;

	for (int i = 0; i < env.injectee_cnt; i++) {
		struct injectee *inj = &env.injectees[i];
		struct stat st;

		if (inj->state == INJECTEE_INACTIVE) {
			/* expected clean shutdown case */
		} else if (inj->state == INJECTEE_SHUTDOWN_TIMEOUT) {
			eprintf("%s timed out its shutdown, but we'll try to collect its data nevertheless!..\n",
				injectee_str(inj));
		} else if (inj->state == INJECTEE_IGNORED) {
			/* expected uninteresting case, don't pollute logs */
			continue;
		} else {
			eprintf("Skipping tracing data from %s (%s) as it had problems...\n",
				injectee_str(inj), injectee_state_str(inj->state));
			continue;
		}

		/* CUDA event stream */
		if (inj->cuda_dump_fd >= 0) {
			struct wcuda_state *wcuda = &wcudas[wcuda_cnt];

			if (fstat(inj->cuda_dump_fd, &st) < 0) {
				err = -errno;
				eprintf("Failed to fstat() CUDA data dump for %s at '%s': %d\n",
					injectee_str(inj), inj->cuda_dump_path, err);
				goto skip_cuda;
			}

			wcuda->dump_sz = st.st_size;
			wcuda->dump_hdr = mmap(NULL, wcuda->dump_sz, PROT_READ | PROT_WRITE, MAP_SHARED, inj->cuda_dump_fd, 0);
			if (wcuda->dump_hdr == MAP_FAILED) {
				err = -errno;
				eprintf("Failed to mmap() CUDA data dump for %s at '%s': %d\n",
					injectee_str(inj), inj->cuda_dump_path, err);
				wcuda->dump_hdr = NULL;
				goto skip_cuda;
			}

			wcuda->strs = (void *)wcuda->dump_hdr + wcuda->dump_hdr->hdr_sz + wcuda->dump_hdr->strs_off;

			/* re-sort CUDA events because they don't come completely ordered out of CUPTI */
			wcuda->tracee_idx = i;
			wcuda->rec_idx = 0;
			wcuda->rec_cnt = wcuda->dump_hdr->event_cnt;
			wcuda->recs = calloc(wcuda->rec_cnt, sizeof(*wcuda->recs));

			struct wcuda_event_record *rec;
			u64 idx = 0;
			wcuda_for_each_event(rec, wcuda->dump_hdr) {
				wcuda->recs[idx++] = (struct wrust_ts_ptr){ .ts = rec->e->ts, .ptr = rec->e };
			}

			wrust_sort_events_by_ts(wcuda->recs, wcuda->rec_cnt);
			wcuda->next_rec = wcuda->rec_cnt > 0 ? &wcuda->recs[0] : NULL;
			wcuda_cnt++;
		}
skip_cuda:

		/* PyTrace (Python call/return) event stream */
		if (inj->pytrace_dump_fd >= 0) {
			struct wpytrace_state *wpy = &wpytraces[wpytrace_cnt];

			if (fstat(inj->pytrace_dump_fd, &st) < 0) {
				err = -errno;
				eprintf("Failed to fstat() PyTrace data dump for %s at '%s': %d\n",
					injectee_str(inj), inj->pytrace_dump_path, err);
				goto skip_pytrace;
			}
			wpy->dump_sz = st.st_size;
			wpy->dump_hdr = mmap(NULL, wpy->dump_sz, PROT_READ | PROT_WRITE, MAP_SHARED, inj->pytrace_dump_fd, 0);
			if (wpy->dump_hdr == MAP_FAILED) {
				err = -errno;
				eprintf("Failed to mmap() PyTrace data dump for %s at '%s': %d\n",
					injectee_str(inj), inj->pytrace_dump_path, err);
				wpy->dump_hdr = NULL;
				goto skip_pytrace;
			}

			wpy->strs = (void *)wpy->dump_hdr + wpy->dump_hdr->hdr_sz + wpy->dump_hdr->strs_off;
			wpy->code_map = (void *)wpy->dump_hdr + wpy->dump_hdr->hdr_sz + wpy->dump_hdr->code_map_off;
			wpy->code_map_cnt = wpy->dump_hdr->code_map_cnt;
			qsort(wpy->code_map, wpy->code_map_cnt, sizeof(*wpy->code_map), wpytrace_code_entry_cmp);
			wpy->tracee_idx = i;
			wpy->rec_idx = 0;
			wpy->rec_cnt = wpy->dump_hdr->event_cnt;
			wpy->recs = calloc(wpy->rec_cnt, sizeof(*wpy->recs));

			struct wpytrace_event_record *py_rec;
			wpytrace_for_each_event(py_rec, wpy->dump_hdr)
				wpy->recs[py_rec->idx] = (struct wrust_ts_ptr){ .ts = py_rec->e->ts, .ptr = py_rec->e };

			wrust_sort_events_by_ts(wpy->recs, wpy->rec_cnt);
			wpy->next_rec = wpy->rec_cnt > 0 ? &wpy->recs[0] : NULL;
			wpytrace_cnt++;
		}
skip_pytrace:

		/* PyTorch (RecordFunction) event stream */
		if (inj->pytorch_dump_fd >= 0) {
			struct wpytorch_state *wtorch = &wpytorches[wpytorch_cnt];

			if (fstat(inj->pytorch_dump_fd, &st) < 0) {
				err = -errno;
				eprintf("Failed to fstat() PyTorch data dump for %s at '%s': %d\n",
					injectee_str(inj), inj->pytorch_dump_path, err);
				goto skip_pytorch;
			}
			wtorch->dump_sz = st.st_size;
			wtorch->dump_hdr = mmap(NULL, wtorch->dump_sz, PROT_READ | PROT_WRITE, MAP_SHARED, inj->pytorch_dump_fd, 0);
			if (wtorch->dump_hdr == MAP_FAILED) {
				err = -errno;
				eprintf("Failed to mmap() PyTorch data dump for %s at '%s': %d\n",
					injectee_str(inj), inj->pytorch_dump_path, err);
				wtorch->dump_hdr = NULL;
				goto skip_pytorch;
			}

			wtorch->strs = (void *)wtorch->dump_hdr + wtorch->dump_hdr->hdr_sz + wtorch->dump_hdr->strs_off;
			wtorch->tracee_idx = i;
			wtorch->rec_idx = 0;
			wtorch->rec_cnt = wtorch->dump_hdr->event_cnt;
			wtorch->recs = calloc(wtorch->rec_cnt, sizeof(*wtorch->recs));

			struct wpytorch_event_record *torch_rec;
			wpytorch_for_each_event(torch_rec, wtorch->dump_hdr)
				wtorch->recs[torch_rec->idx] = (struct wrust_ts_ptr){ .ts = torch_rec->e->ts, .ptr = torch_rec->e };

			wrust_sort_events_by_ts(wtorch->recs, wtorch->rec_cnt);
			wtorch->next_rec = wtorch->rec_cnt > 0 ? &wtorch->recs[0] : NULL;
			wpytorch_cnt++;
		}
skip_pytorch:
		continue;
	}

	/*
	 * Merge and convert events in timestamp order. Pick the next event with
	 * a min priority queue over each stream's head, keyed by (timestamp,
	 * stream index); the stream-index tie-break keeps the lowest-index
	 * stream on equal timestamps, matching the original linear scan.
	 */
	struct wevent wevent_buf;

	int stream_cnt = env.ringbuf_cnt + wcuda_cnt + wpytrace_cnt + wpytorch_cnt;
	struct wpq *pq = wpq_new(stream_cnt);

	for (int i = 0; i < env.ringbuf_cnt; i++) {
		if (wmerges[i].next_rec)
			wpq_push(pq, wmerges[i].next_rec->ts, i);
	}
	for (int i = 0; i < wcuda_cnt; i++) {
		if (wcudas[i].next_rec)
			wpq_push(pq, wcudas[i].next_rec->ts, env.ringbuf_cnt + i);
	}
	for (int i = 0; i < wpytrace_cnt; i++) {
		if (wpytraces[i].next_rec)
			wpq_push(pq, wpytraces[i].next_rec->ts, env.ringbuf_cnt + wcuda_cnt + i);
	}
	for (int i = 0; i < wpytorch_cnt; i++) {
		if (wpytorches[i].next_rec)
			wpq_push(pq, wpytorches[i].next_rec->ts, env.ringbuf_cnt + wcuda_cnt + wpytrace_cnt + i);
	}

	while (!wpq_empty(pq)) {
		uint64_t top_ts;
		uint32_t top_widx;
		wpq_peek(pq, &top_ts, &top_widx);
		int widx = top_widx;

		int wevent_sz;
		if (widx < env.ringbuf_cnt) {
			struct wmerge_state *wmerge = &wmerges[widx];
			const struct wprof_event *r = wmerge->next_rec->ptr;

			/*
			 * Clamp output to the session window [sess_min_ts, sess_max_ts]:
			 * events outside it are skipped -- advance the cursor as usual
			 * but without writing the record. For non-flight-recorder these
			 * bounds equal the capture-time gate, so nothing is dropped.
			 */
			if ((sess_min_ts && ts_before(wmerge->next_rec->ts, sess_min_ts)) ||
			    (sess_max_ts && ts_after(wmerge->next_rec->ts, sess_max_ts))) {
				wmerge->rec_idx++;
				wmerge->next_rec = wmerge->rec_idx < wmerge->rec_cnt ? &wmerge->recs[wmerge->rec_idx] : NULL;

				if (wmerge->next_rec)
					wpq_replace_min(pq, wmerge->next_rec->ts, widx);
				else
					wpq_pop(pq);
				continue;
			}

			wevent_sz = persist_bpf_event(&ps, r, &wevent_buf);
			if (wevent_sz < 0) {
				eprintf("Failed to convert BPF event for RB #%d: %d\n", widx, wevent_sz);
				return wevent_sz;
			}

			wmerge->rec_idx++;
			wmerge->next_rec = wmerge->rec_idx < wmerge->rec_cnt ? &wmerge->recs[wmerge->rec_idx] : NULL;

			if (wmerge->next_rec)
				wpq_replace_min(pq, wmerge->next_rec->ts, widx);
			else
				wpq_pop(pq);

			/*
			 * Some events (e.g., EV_CUDA_CALL) are "ephemeral": they are collected
			 * from BPF side and joined into another (e.g., CUDA-produced EV_CUDA_API)
			 * events, augmenting their data (CUDA call stacks, for instance).
			 * They are dropped and not persisted by themselves after this, but they
			 * should be passed into persist_state. persist_bpf_event() signals this
			 * with wevent_sz == 0 return.
			 */
			if (wevent_sz == 0)
				continue;
		} else if (widx < env.ringbuf_cnt + wcuda_cnt) {
			int cidx = widx - env.ringbuf_cnt;

			struct wcuda_state *wcuda = &wcudas[cidx];
			const struct wcuda_event *r = wcuda->next_rec->ptr;
			struct injectee *inj = &env.injectees[wcuda->tracee_idx];

			wevent_sz = persist_cuda_event(&ps, r, &wevent_buf,
						       inj->pid, inj->proc_name, wcuda->strs);
			if (wevent_sz < 0) {
				eprintf("Failed to convert CUDA event for %s: %d\n", injectee_str(inj), wevent_sz);
				return wevent_sz;
			}

			wcuda->rec_idx++;
			wcuda->next_rec = wcuda->rec_idx < wcuda->rec_cnt ? &wcuda->recs[wcuda->rec_idx] : NULL;

			if (wcuda->next_rec)
				wpq_replace_min(pq, wcuda->next_rec->ts, widx);
			else
				wpq_pop(pq);
		} else if (widx < env.ringbuf_cnt + wcuda_cnt + wpytrace_cnt) {
			int pidx = widx - env.ringbuf_cnt - wcuda_cnt;

			struct wpytrace_state *wpy = &wpytraces[pidx];
			const struct wpytrace_event *r = wpy->next_rec->ptr;
			struct injectee *inj = &env.injectees[wpy->tracee_idx];

			wevent_sz = persist_pytrace_event(&ps, r, &wevent_buf,
							 inj->pid, inj->ns_pid, inj->proc_name,
							 wpy->code_map, wpy->code_map_cnt, wpy->strs);
			if (wevent_sz < 0) {
				eprintf("Failed to convert pytrace event for %s: %d\n", injectee_str(inj), wevent_sz);
				return wevent_sz;
			}

			wpy->rec_idx++;
			wpy->next_rec = wpy->rec_idx < wpy->rec_cnt ? &wpy->recs[wpy->rec_idx] : NULL;

			if (wpy->next_rec)
				wpq_replace_min(pq, wpy->next_rec->ts, widx);
			else
				wpq_pop(pq);

			if (wevent_sz == 0)
				continue;
		} else {
			int tidx = widx - env.ringbuf_cnt - wcuda_cnt - wpytrace_cnt;

			struct wpytorch_state *wtorch = &wpytorches[tidx];
			const struct wpytorch_event *r = wtorch->next_rec->ptr;
			struct injectee *inj = &env.injectees[wtorch->tracee_idx];

			wevent_sz = persist_pytorch_event(&ps, r, &wevent_buf,
							  inj->pid, inj->ns_pid, inj->proc_name, wtorch->strs);
			if (wevent_sz < 0) {
				eprintf("Failed to convert pytorch event for %s: %d\n", injectee_str(inj), wevent_sz);
				return wevent_sz;
			}

			wtorch->rec_idx++;
			wtorch->next_rec = wtorch->rec_idx < wtorch->rec_cnt ? &wtorch->recs[wtorch->rec_idx] : NULL;

			if (wtorch->next_rec)
				wpq_replace_min(pq, wtorch->next_rec->ts, widx);
			else
				wpq_pop(pq);

			if (wevent_sz == 0)
				continue;
		}

		/*
		 * Checkpoint the first event at/after each WPROF_TSIDX_PERIOD_NS
		 * boundary; events_sz/event_cnt are this event's offset and index
		 * (still pre-increment). Anchoring to real events avoids empty
		 * checkpoints across idle gaps; seeding tsidx_next_ts to the session
		 * start makes the first event checkpoint 0 (offset 0, index 0).
		 */
		if (ts_after_or_at(wevent_buf.ts, tsidx_next_ts)) {
			if (tsidx_cnt == tsidx_cap) {
				tsidx_cap = tsidx_cap ? tsidx_cap * 4 / 3 : 64;
				tsidx = realloc(tsidx, tsidx_cap * sizeof(*tsidx));
			}
			tsidx[tsidx_cnt++] = (struct wprof_tsidx_ent){
				.ts = wevent_buf.ts,
				.off = events_sz,
			};
			tsidx_next_ts = wevent_buf.ts + WPROF_TSIDX_PERIOD_NS;
		}

		event_cnt += 1;
		events_sz += wevent_sz;

		if (fwrite(&wevent_buf, wevent_sz, 1, data_dump) != 1) {
			err = -errno;
			if (widx < env.ringbuf_cnt) {
				eprintf("Failed to fwrite() event from ringbuf #%d ('%s'): %d\n",
					widx, workers[widx].dump_path, err);
			} else if (widx < env.ringbuf_cnt + wcuda_cnt) {
				int cidx = widx - env.ringbuf_cnt;
				struct injectee *inj = &env.injectees[wcudas[cidx].tracee_idx];
				eprintf("Failed to fwrite() CUDA event from %s: %d\n",
					injectee_str(inj), err);
			} else if (widx < env.ringbuf_cnt + wcuda_cnt + wpytrace_cnt) {
				int pidx = widx - env.ringbuf_cnt - wcuda_cnt;
				struct injectee *inj = &env.injectees[wpytraces[pidx].tracee_idx];
				eprintf("Failed to fwrite() PyTrace event from %s: %d\n",
					injectee_str(inj), err);
			} else {
				int tidx = widx - env.ringbuf_cnt - wcuda_cnt - wpytrace_cnt;
				struct injectee *inj = &env.injectees[wpytorches[tidx].tracee_idx];
				eprintf("Failed to fwrite() PyTorch event from %s: %d\n",
					injectee_str(inj), err);
			}
			return err;
		}
	}

	wpq_free(pq);

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

		/*
		 * Release the consumed flight-recorder chunks: unmap (kept alive
		 * for the merge loop), unlink honoring keep-workdir, then free. The
		 * PQ is already empty (all popped above), so fr_teardown's later
		 * drain is a no-op.
		 */
		struct fr_chunk *next;
		for (struct fr_chunk *c = fr_lists[i]; c; c = next) {
			next = c->next;
			if (c->mmap)
				munmap(c->mmap, c->byte_sz);
			if (!env.keep_workdir)
				unlink(c->path);
			free(c->path);
			free(c);
		}

		free(wmerge->recs);
	}
	free(wmerges);
	free(fr_lists);

	/* Cleanup CUDA dumps */
	for (int i = 0; i < wcuda_cnt; i++) {
		struct wcuda_state *w = &wcudas[i];

		if (w->dump_hdr)
			munmap(w->dump_hdr, w->dump_sz);

		free(w->recs);
		w->dump_hdr = NULL;
		w->dump_sz = 0;
	}
	free(wcudas);

	/* Cleanup pytrace and torch dumps */
	for (int i = 0; i < wpytrace_cnt; i++) {
		struct wpytrace_state *wpy = &wpytraces[i];

		if (wpy->dump_hdr)
			munmap(wpy->dump_hdr, wpy->dump_sz);

		free(wpy->recs);
		wpy->dump_hdr = NULL;
		wpy->dump_sz = 0;
	}
	for (int i = 0; i < wpytorch_cnt; i++) {
		struct wpytorch_state *wtorch = &wpytorches[i];

		if (wtorch->dump_hdr)
			munmap(wtorch->dump_hdr, wtorch->dump_sz);

		free(wtorch->recs);
		wtorch->dump_hdr = NULL;
		wtorch->dump_sz = 0;
	}
	free(wpytraces);
	free(wpytorches);

	/* Remove and close each injectee's per-feature dump files now they're merged. */
	for (int i = 0; i < env.injectee_cnt; i++) {
		struct injectee *inj = &env.injectees[i];

		if (!env.keep_workdir && inj->cuda_dump_path)
			unlink(inj->cuda_dump_path);
		if (!env.keep_workdir && inj->pytrace_dump_path)
			unlink(inj->pytrace_dump_path);
		if (!env.keep_workdir && inj->pytorch_dump_path)
			unlink(inj->pytorch_dump_path);

		free(inj->cuda_dump_path);
		inj->cuda_dump_path = NULL;
		free(inj->pytrace_dump_path);
		inj->pytrace_dump_path = NULL;
		free(inj->pytorch_dump_path);
		inj->pytorch_dump_path = NULL;

		zclose(inj->cuda_dump_fd);
		zclose(inj->pytrace_dump_fd);
		zclose(inj->pytorch_dump_fd);
	}

	/*
	 * Collect extras (persisted capture-time filters);
	 * must be before string pool so that persist_stroff() interns filter strings.
	 */
	struct wprof_extra_param *extras = NULL;
	u64 extra_cnt = 0;
	collect_extras(&ps, &extras, &extra_cnt);

	/* Prepare stats: allocate, collect everything except rusage, intern prog names */
	struct wprof_stats *stats = prepare_stats(&ps, workers);
	int stats_off = persist_bloboff(&ps, stats, stats->sz, 8);
	add_extra(&extras, &extra_cnt, WEXTRA_STATS, stats_off);

	/* Write extras section (right after events) */
	off_t extras_off = 0;
	size_t extras_sz = 0;
	if (extra_cnt > 0) {
		file_pad(data_dump, 8);
		extras_off = ftell(data_dump) - sizeof(struct wprof_data_hdr);
		extras_sz = extra_cnt * sizeof(struct wprof_extra_param);
		if (fwrite(extras, sizeof(struct wprof_extra_param), extra_cnt, data_dump) != extra_cnt) {
			err = -errno;
			eprintf("Failed to fwrite() extras section: %d\n", err);
			return err;
		}
	}
	free(extras);

	/* Write config section */
	struct wprof_data_cfg cfg = {
		.ktime_start_ns = env.ktime_start_ns,
		.realtime_start_ns = env.realtime_start_ns,
		.duration_ns = env.duration_ns,
		.captured_stack_traces = env.requested_stack_traces,
		.timer_freq_hz = env.timer_freq_hz,
	};
	for (int i = 0; i < capture_feature_cnt; i++) {
		const struct capture_feature *f = &capture_features[i];
		enum tristate *flag = (void *)&env + f->env_flag_off;
		/* inverted features set the bit when DISABLED (see cfg_feature_captured) */
		if (f->inverted ? (*flag != TRUE) : (*flag == TRUE))
			cfg.capture_features |= f->cfg_bit;
	}
	file_pad(data_dump, 8);
	off_t cfg_off = ftell(data_dump) - sizeof(struct wprof_data_hdr);
	size_t cfg_sz = sizeof(cfg);
	if (fwrite(&cfg, sizeof(cfg), 1, data_dump) != 1) {
		err = -errno;
		eprintf("Failed to fwrite() config section: %d\n", err);
		return err;
	}

	/* Write timestamp index section */
	file_pad(data_dump, 8);
	off_t tsidx_off = ftell(data_dump) - sizeof(struct wprof_data_hdr);
	size_t tsidx_sz = tsidx_cnt * sizeof(struct wprof_tsidx_ent);
	if (tsidx_cnt > 0 && fwrite(tsidx, sizeof(struct wprof_tsidx_ent), tsidx_cnt, data_dump) != tsidx_cnt) {
		err = -errno;
		eprintf("Failed to fwrite() timestamp index section: %d\n", err);
		return err;
	}
	free(tsidx);

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
	size_t pmu_def_cnt = ps.pmu_def_total_cnt;
	size_t pmu_defs_sz = pmu_def_cnt * sizeof(struct wevent_pmu_def);
	if (pmu_def_cnt > 0 && fwrite(ps.pmu_defs, sizeof(struct wevent_pmu_def),
				      pmu_def_cnt, data_dump) != pmu_def_cnt) {
		err = -errno;
		eprintf("Failed to fwrite() PMU definitions: %s\n", errstr(err));
		return err;
	}

	/* Write PMU counter values section (spliced from separate file) */
	off_t pmu_vals_off = 0;
	size_t pmu_vals_sz = 0;
	size_t pmu_vals_cnt = ps.pmu_vals.count;
	if (pmu_vals_dump) {
		file_pad(data_dump, 8);
		err = file_splice_into(pmu_vals_dump, data_dump, &pmu_vals_off, &pmu_vals_sz);
		if (err) {
			eprintf("Failed to merge PMU values into final dump: %s\n", errstr(err));
			return err;
		}
		pmu_vals_off -= sizeof(struct wprof_data_hdr);

		fclose(pmu_vals_dump);
		pmu_vals_dump = NULL;

		if (!env.keep_workdir)
			unlink(pmu_vals_path);
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

	/* Write blob pool section */
	long blobs_off = ftell(data_dump) - sizeof(struct wprof_data_hdr);
	const void *blobs_data = blobset__data(ps.blobs);
	size_t blobs_sz = blobset__data_size(ps.blobs);
	if (blobs_sz > 0 && fwrite(blobs_data, 1, blobs_sz, data_dump) != blobs_sz) {
		err = -errno;
		eprintf("Failed to fwrite() blob pool: %d\n", err);
		return err;
	}
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

	long dump_sz = ftell(data_dump);
	if (dump_sz < 0) {
		err = -errno;
		eprintf("Failed to get data dump file position: %d\n", -err);
		return err;
	}

	fflush(data_dump);
	fsync(fileno(data_dump));

	persist_state_free(&ps);

	/* Finalize stats: capture rusage as late as possible */
	finalize_stats(stats);

	err = fseek(data_dump, sizeof(struct wprof_data_hdr) + blobs_off + stats_off, SEEK_SET);
	if (err) {
		err = -errno;
		eprintf("Failed to fseek() to stats blob: %d\n", err);
		return err;
	}
	if (fwrite(stats, stats->sz, 1, data_dump) != 1) {
		err = -errno;
		eprintf("Failed to fwrite() stats blob: %d\n", err);
		return err;
	}
	env.stats = stats;

	/* Finalize data dump header */
	struct wprof_data_hdr hdr;
	init_data_header(&hdr);

	hdr.flags |= WDF_CFG_SECTION;
	hdr.cfg_off = cfg_off;
	hdr.cfg_sz = cfg_sz;

	hdr.events_off = 0;
	hdr.events_sz = events_sz;
	hdr.event_cnt = event_cnt;

	hdr.threads_off = threads_off;
	hdr.threads_sz = threads_sz;
	hdr.thread_cnt = thread_cnt;

	hdr.pmu_defs_off = pmu_defs_off;
	hdr.pmu_defs_sz = pmu_defs_sz;
	hdr.pmu_def_real_cnt = env.pmu_real_cnt;
	hdr.pmu_def_deriv_cnt = env.pmu_deriv_cnt;

	hdr.pmu_vals_off = pmu_vals_off;
	hdr.pmu_vals_sz = pmu_vals_sz;
	hdr.pmu_val_cnt = pmu_vals_cnt;

	hdr.strs_off = strs_off;
	hdr.strs_sz = strs_sz;

	hdr.blobs_off = blobs_off;
	hdr.blobs_sz = blobs_sz;

	hdr.stacks_off = stacks_off;
	hdr.stacks_sz = stacks_sz;

	hdr.extras_off = extras_off;
	hdr.extras_sz = extras_sz;
	hdr.extra_cnt = extra_cnt;

	hdr.tsidx_off = tsidx_off;
	hdr.tsidx_sz = tsidx_sz;
	hdr.tsidx_cnt = tsidx_cnt;

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
	env.data_hdr = w->dump_hdr;

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
