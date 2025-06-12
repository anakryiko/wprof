// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>

#include "protobuf.h"
#include "env.h"
#include "stacktrace.h"

#include "blazesym.h"
#include "../libbpf/src/strset.h"

#define DEBUG_SYMBOLIZATION 0

#define debugf(...) if (DEBUG_SYMBOLIZATION) fprintf(stderr, ##__VA_ARGS__)

struct symb_state {
	struct stack_frame_index *sframe_idx;
	size_t sframe_cap, sframe_cnt;
	struct stack_trace_index *strace_idx;
	size_t strace_cap, strace_cnt;
};

/*
 * SYMBOLIZATION
 */
static void print_frame(const char *name, uintptr_t input_addr, uintptr_t addr, uint64_t offset,
			const blaze_symbolize_code_info* code_info)
{
	/* If we have an input address we have a new symbol. */
	if (input_addr != 0) {
		printf("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
			printf(" %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
		} else if (code_info != NULL && code_info->file != NULL) {
			printf(" %s:%u\n", code_info->file, code_info->line);
		} else {
			printf("\n");
		}
	} else {
		printf("%16s  %s", "", name);
		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL) {
			printf("@ %s/%s:%u [inlined]\n", code_info->dir, code_info->file, code_info->line);
		} else if (code_info != NULL && code_info->file != NULL) {
			printf("@ %s:%u [inlined]\n", code_info->file, code_info->line);
		} else {
			printf("[inlined]\n");
		}
	}
}

__unused
static void show_stack_trace(struct blaze_symbolizer *symbolizer, u64 *stack, int stack_sz, pid_t pid)
{
	const struct blaze_symbolize_inlined_fn* inlined;
	const struct blaze_syms *syms;
	const struct blaze_sym *sym;
	int i, j;

	assert(sizeof(uintptr_t) == sizeof(uint64_t));

	if (pid) {
		struct blaze_symbolize_src_process src = {
			.type_size = sizeof(src),
			.pid = pid,
		};
		syms = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	} else {
		struct blaze_symbolize_src_kernel src = {
			.type_size = sizeof(src),
		};
		syms = blaze_symbolize_kernel_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
	}

	if (!syms) {
		printf("  failed to symbolize addresses: %s\n", blaze_err_str(blaze_err_last()));
		return;
	}

	for (i = 0; i < stack_sz; i++) {
		if (!syms || syms->cnt <= i || syms->syms[i].name == NULL) {
			printf("%016llx: <no-symbol>\n", stack[i]);
			continue;
		}

		sym = &syms->syms[i];
		print_frame(sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);

		for (j = 0; j < sym->inlined_cnt; j++) {
			inlined = &sym->inlined[j];
			print_frame(sym->name, 0, 0, 0, &inlined->code_info);
		}
	}

	blaze_syms_free(syms);
}

static bool stack_trace_eq(const struct stack_trace_index *x,
			   const struct stack_trace_index *y,
			   const struct symb_state *s)
{
	if (x->pid != y->pid)
		return false;

	if (x->frame_cnt != y->frame_cnt)
		return false;

	for (int i = 0; i < x->frame_cnt; i++) {
		u64 xa = s->sframe_idx[x->start_frame_idx + i].addr;
		u64 ya = s->sframe_idx[y->start_frame_idx + i].addr;

		if (xa != ya)
			return false;
	}

	return true;
}

static int stack_trace_cmp_by_content(const void *a, const void *b, void *ctx)
{
	const struct symb_state *s = ctx;
	const struct stack_trace_index *x = a, *y = b;

	if (x->pid != y->pid)
		return x->pid < y->pid ? -1 : 1;

	if (x->frame_cnt != y->frame_cnt)
		return x->frame_cnt < y->frame_cnt ? -1 : 1;

	for (int i = 0; i < x->frame_cnt; i++) {
		u64 xa = s->sframe_idx[x->start_frame_idx + i].addr;
		u64 ya = s->sframe_idx[y->start_frame_idx + i].addr;

		if (xa != ya)
			return xa < ya ? -1 : 1;
	}

	return x->start_frame_idx < y->start_frame_idx ? -1 : 1;
}

static int stack_trace_cmp_by_orig_idx(const void *a, const void *b)
{
	const struct stack_trace_index *x = a, *y = b;

	return x->orig_idx < y->orig_idx ? -1 : 1;
}

static int stack_frame_cmp_by_pid_addr(const void *a, const void *b)
{
	const struct stack_frame_index *x = a, *y = b;

	if (x->pid != y->pid)
		return x->pid < y->pid ? -1 : 1;
	if (x->addr != y->addr)
		return x->addr < y->addr ? -1 : 1;
	return x->orig_idx < y->orig_idx ? -1 : 1;
}

static int stack_frame_cmp_by_orig_idx(const void *a, const void *b)
{
	const struct stack_frame_index *x = a, *y = b;

	return x->orig_idx < y->orig_idx ? -1 : 1;
}

static void stack_trace_append(struct symb_state *s, struct wprof_event *e,
			       int pid, int start_frame_idx, int frame_cnt, bool combine)
{
	if (s->strace_cnt == s->strace_cap) {
		size_t new_cap = s->strace_cnt < 64 ? 64 : s->strace_cnt * 4 / 3;

		s->strace_idx = realloc(s->strace_idx, new_cap * sizeof(*s->strace_idx));
		s->strace_cap = new_cap;
	}
	s->strace_idx[s->strace_cnt] = (struct stack_trace_index){
		.event = e,
		.orig_idx = s->strace_cnt,
		.pid = pid,
		.start_frame_idx = start_frame_idx,
		.frame_cnt = frame_cnt,
		.combine = combine,
	};

	s->strace_cnt++;
}

static void stack_frame_append(struct symb_state *s, int pid, int orig_pid, u64 addr)
{
	if (s->sframe_cnt == s->sframe_cap) {
		size_t new_cap = s->sframe_cnt < 256 ? 256 : s->sframe_cnt * 4 / 3;

		s->sframe_idx = realloc(s->sframe_idx, new_cap * sizeof(*s->sframe_idx));
		s->sframe_cap = new_cap;
	}
	s->sframe_idx[s->sframe_cnt] = (struct stack_frame_index){
		.orig_idx = s->sframe_cnt,
		.pid = pid,
		.orig_pid = orig_pid,
		.addr = addr,
		.sym = NULL,
	};

	s->sframe_cnt++;
}

static int process_event_stack_trace(struct symb_state *state, struct wprof_event *e, size_t size)
{
	struct stack_trace *tr;
	const u64 *kaddrs = NULL, *uaddrs = NULL;
	int ucnt = 0, kcnt = 0;

	if (!(e->flags & EF_STACK_TRACE)) /* no variable-length part of event */
		return 0;

	tr = (void *)e + e->sz;

	if (tr->kstack_sz > 0) {
		kcnt = tr->kstack_sz / 8;
		kaddrs = tr->addrs;
	}

	if (tr->ustack_sz > 0) {
		ucnt = tr->ustack_sz / 8;
		uaddrs = tr->addrs + kcnt;
	}

	/* we need user stack to come in front of kernel stack for further
	 * Perfetto-related stack merging to work correctly
	 */
	if (uaddrs) {
		stack_trace_append(state, e, e->task.pid, state->sframe_cnt, ucnt, false /*!combine*/);
		for (int i = ucnt - 1; i >= 0; i--)
			stack_frame_append(state, e->task.pid, e->task.pid, uaddrs[i]);
	}

	if (kaddrs) {
		stack_trace_append(state, e, 0, state->sframe_cnt, kcnt, !!uaddrs /*combine*/);
		for (int i = kcnt - 1; i >= 0; i--)
			stack_frame_append(state, 0 /* kernel */, e->task.pid, kaddrs[i]);
	}

	return 0;
}

static void update_event_stack_id(struct wprof_event *e, int stack_id)
{
	if (!(e->flags & EF_STACK_TRACE)) {
		fprintf(stderr, "BUG: event without associated stack trace is getting stack ID!\n");
		exit(1);
	}

	struct stack_trace *tr = (void *)e + e->sz;
	tr->stack_id = stack_id;
}

int process_stack_traces(struct worker_state *w)
{
	struct symb_state _state = {}, *state = &_state;
	size_t kaddr_cnt = 0, uaddr_cnt = 0, unkn_cnt = 0, comb_cnt = 0;
	size_t frames_deduped = 0, frames_total = 0, frames_failed = 0, callstacks_deduped = 0;
	u64 start_ns = ktime_now_ns();
	int err;
	u64 base_off = 0;

	fprintf(stderr, "Symbolizing...\n");
	u64 symb_start_ns = ktime_now_ns();

	struct wprof_event_record *rec;
	wprof_for_each_event(rec, w->dump_hdr) {
		err = process_event_stack_trace(state, rec->e, rec->sz);
		if (err) {
			fprintf(stderr, "Failed to pre-process stack trace for event #%d (kind %d, size %zu, offset %zu): %d\n",
				rec->idx, rec->e->kind, rec->sz, (void *)rec - (void *)w->dump_hdr, err);
			return err;
		}
	}

	w->dump_hdr->stacks_off = ftell(w->dump) - sizeof(struct wprof_data_hdr);

	struct wprof_stacks_hdr hdr;
	memset(&hdr, 0, sizeof(hdr));
	if (fwrite(&hdr, sizeof(hdr), 1, w->dump) != 1) {
		err = -errno;
		fprintf(stderr, "Failed to write initial stack header: %d\n", err);
		return err;
	}
	base_off = ftell(w->dump);

	hdr.frames_off = ftell(w->dump) - base_off;
	/* Add dummy all-zero stack frame record to have all the frame IDs
	 * positive, which matches well Perfetto expectations and is generally
	 * nice to have property to be able to use zero ID as "no frame"
	 * indicator (and not have to remember to adjust everything by +/-1
	 * all the time
	 */
	{
		struct wprof_stack_frame dummy_frm;
		memset(&dummy_frm, 0, sizeof(dummy_frm));
		if (fwrite(&dummy_frm, sizeof(dummy_frm), 1, w->dump) != 1) {
			err = -errno;
			fprintf(stderr, "Failed to write dummy stack frame: %d\n", err);
			return err;
		}
		hdr.frame_cnt = 1;
	}

	/* group by pid+addr */
	qsort(state->sframe_idx, state->sframe_cnt, sizeof(*state->sframe_idx), stack_frame_cmp_by_pid_addr);

	u64 last_progress_ns = symb_start_ns;
	double last_progress_pct = 0.0;
	double min_progress_pct = 10.0; /* report no more frequently than every 10.0% */
	u64 min_progress_ns = 3 * 1000000000ULL; /* ... and no more frequently than every 3 secs */

	int total_uniq_cnt = 0, last_uniq_cnt = 0;
	for (int i = 0; i < state->sframe_cnt; i++) {
		if (i > 0 &&
		    state->sframe_idx[i - 1].pid == state->sframe_idx[i].pid &&
		    state->sframe_idx[i - 1].addr == state->sframe_idx[i].addr)
			continue;
		total_uniq_cnt += 1;
	}

	struct blaze_symbolizer_opts blaze_opts = {
		.type_size = sizeof(struct blaze_symbolizer_opts),
		.auto_reload = false,
		.code_info = true,
		.inlined_fns = true,
		.demangle = true,
	};
	struct blaze_symbolizer *symbolizer = NULL;

	if (!env.symbolize_frugally) {
		symbolizer = blaze_symbolizer_new_opts(&blaze_opts);
		if (!symbolizer) {
			blaze_err berr = blaze_err_last();
			const char *berr_str = blaze_err_str(berr);

			fprintf(stderr, "Failed to create a symbolizer: %s (%d)\n", berr_str, berr);
			return berr;
		}
	}

	struct strset *strs = strset__new(UINT_MAX, "", 1);

	int mapped_fr_idx = 1;
	u64 *addrs = NULL;
	size_t addr_cap = 0;
	for (int start = 0, end = 1; end <= state->sframe_cnt; end++) {
		if (end < state->sframe_cnt && state->sframe_idx[start].pid == state->sframe_idx[end].pid)
			continue;

		if (end - start > addr_cap) {
			addr_cap = end - start;
			addrs = realloc(addrs, sizeof(*addrs) * addr_cap);
		}

		size_t addr_cnt = 0;
		for (int i = 0; i < end - start; i++) {
			u64 addr = state->sframe_idx[start + i].addr;

			if (addr_cnt > 0 && addr == addrs[addr_cnt - 1])
				continue;

			addrs[addr_cnt] = addr;
			addr_cnt += 1;
		}

		if (env.symbolize_frugally) {
			symbolizer = blaze_symbolizer_new_opts(&blaze_opts);
			if (!symbolizer) {
				blaze_err berr = blaze_err_last();
				const char *berr_str = blaze_err_str(berr);

				fprintf(stderr, "Failed to create a symbolizer: %s (%d)\n", berr_str, berr);
				return berr;
			}
		}

		/* symbolize [start .. end - 1] range */
		const struct blaze_syms *syms;
		bool is_kernel;
		if (state->sframe_idx[start].pid == 0) { /* kernel addresses */
			struct blaze_symbolize_src_kernel src = {
				.type_size = sizeof(src),
				.debug_syms = true,
			};
			syms = blaze_symbolize_kernel_abs_addrs(symbolizer, &src, (const void *)addrs, addr_cnt);
			kaddr_cnt += addr_cnt;
			is_kernel = true;

			for (int i = 0; i < addr_cnt; i++) {
				const struct blaze_sym *sym = syms ? &syms->syms[i] : NULL;
				debugf("ORIGF#%d [KERNEL] PID %d ADDR %llx: %s+%lx (MOD %s)\n",
					state->sframe_idx[start + i].orig_idx,
					state->sframe_idx[start].pid, addrs[i],
					(sym && sym->name) ? sym->name : "???", sym->offset,
					(sym && sym->module) ? sym->module : "???");
			}
		} else {
			struct blaze_symbolize_src_process src = {
				.type_size = sizeof(src),
				.pid = state->sframe_idx[start].pid,
				.no_map_files = false,
				.debug_syms = true,
			};
			syms = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const void *)addrs, addr_cnt);
			if (!syms && blaze_err_last() != BLAZE_ERR_NOT_FOUND) {
				src.debug_syms = false;
				syms = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const void *)addrs, addr_cnt);
			}
			uaddr_cnt += addr_cnt;
			is_kernel = false;

			for (int i = 0; i < addr_cnt; i++) {
				const struct blaze_sym *sym = syms ? &syms->syms[i] : NULL;
				debugf("ORIGF#%d [USER] PID %d ADDR %llx: %s+%lx (MOD %s)\n",
					state->sframe_idx[start + i].orig_idx,
					state->sframe_idx[start].pid, addrs[i],
					(sym && sym->name) ? sym->name : "???",
					sym ? sym->offset : 0,
					(sym && sym->module) ? sym->module : "???");
			}
		}
		if (!syms) {
			blaze_err berr = blaze_err_last();
			const char *berr_str = blaze_err_str(berr);

			unkn_cnt += addr_cnt;

			if (env.verbose) {
				eprintf("Symbolization failed for PID %d, skipping %zu unique addrs: %s (%d)\n",
					state->sframe_idx[start].pid, addr_cnt, berr_str, berr);
			}
		}

		for (int i = 0, j = 0; i < end - start; i++) {
			if (i > 0 && state->sframe_idx[start + i - 1].addr == state->sframe_idx[start + i].addr) {
				state->sframe_idx[start + i].sym = state->sframe_idx[start + i - 1].sym;
				debugf("ORIGF#%d DEDUPED INTO ORIGF#%d\n",
					state->sframe_idx[start + i].orig_idx,
					state->sframe_idx[start + i - 1].orig_idx);
				continue;
			}

			if (syms) {
				const struct blaze_sym *sym = &syms->syms[j];

				for (int k = 0, n = 1 + sym->inlined_cnt; k < n; k++) {
					const char *func_name = k == 0 ? sym->name : sym->inlined[k - 1].name;
					const char *src_path = k == 0 ? sym->code_info.file : sym->inlined[k -1].code_info.file;
					struct wprof_stack_frame frm = {
						.func_offset = k == 0 ? sym->offset : 0,
						.flags = (k == 0 ? 0 : WSF_INLINED) | (is_kernel ? WSF_KERNEL : 0),
						.func_name_stroff = strset__add_str(strs, func_name ?: ""),
						.src_path_stroff = strset__add_str(strs, src_path ?: ""),
						.line_num = k == 0 ? sym->code_info.line : sym->inlined[k - 1].code_info.line,
						.addr = state->sframe_idx[start + i].addr,
					};

					if (fwrite(&frm, sizeof(frm), 1, w->dump) != 1) {
						err = -errno;
						fprintf(stderr, "Failed to write stack frame: %d\n", err);
						return err;
					}

					debugf("ORIGF#%d MAPPED INTO F#%d\n",
						state->sframe_idx[start + i].orig_idx, mapped_fr_idx);
					mapped_fr_idx++;

					hdr.frame_cnt += 1;
				}

				state->sframe_idx[start + i].sym = &syms->syms[j];
				j++;
			} else {
				struct wprof_stack_frame frm = {
					.func_offset = state->sframe_idx[start + i].addr,
					.flags = WSF_UNSYMBOLIZED | (is_kernel ? WSF_KERNEL : 0),
				};

				if (fwrite(&frm, sizeof(frm), 1, w->dump) != 1) {
					err = -errno;
					fprintf(stderr, "Failed to write stack frame: %d\n", err);
					return err;
				}

				debugf("ORIGF#%d MAPPED INTO F#%d\n",
					state->sframe_idx[start + i].orig_idx, mapped_fr_idx);
				mapped_fr_idx++;

				hdr.frame_cnt += 1;
			}
		}
#if 0
		int pid_of_interest = 869620;
		for (int k = start; k < end; k++) {
			struct stack_frame_index *f = &state->sframe_idx[k];

			if (f->sym && f->sym->name && f->orig_pid != pid_of_interest)
				continue;

			if (k > start && state->sframe_idx[k - 1].pid == f->pid &&
			    state->sframe_idx[k - 1].addr == f->addr)
				continue;

			if (!f->sym) {
				printf("FAILED SYMBOLIZATION PID %d (ORIG PID %d): %s\n",
					f->pid, f->orig_pid, blaze_err_str(blaze_err_last()));
			} else {
				if (f->sym->name == NULL) {
					printf("[PID %d] %016llx: <no-symbol>\n", f->orig_pid, f->addr);
					continue;
				}

				print_frame(f->sym->name, f->addr, f->sym->addr, f->sym->offset, &f->sym->code_info);

				for (int j = 0; j < f->sym->inlined_cnt; j++) {
					printf("[PID %d] ", f->orig_pid);
					print_frame(f->sym->name, 0, 0, 0, &f->sym->inlined[j].code_info);
				}
			}
		}
#endif
		if (ktime_now_ns() - last_progress_ns >= min_progress_ns ||
		    (last_uniq_cnt + addr_cnt) * 100.0 / total_uniq_cnt - last_progress_pct >= min_progress_pct) {
			last_progress_ns = ktime_now_ns();
			last_progress_pct = (last_uniq_cnt + addr_cnt) * 100.0 / total_uniq_cnt;
			fprintf(stderr, "Symbolized %zu (%.3lf%%) unique addresses in %.3lfs...\n",
				last_uniq_cnt + addr_cnt, (last_uniq_cnt + addr_cnt) * 100.0 / total_uniq_cnt,
				(last_progress_ns - symb_start_ns) / 1000000000.0);
		}
		last_uniq_cnt += addr_cnt;

		start = end;

		if (env.symbolize_frugally) {
			blaze_symbolizer_free(symbolizer);
			symbolizer = NULL;
		}
	}
	blaze_symbolizer_free(symbolizer);
	free(addrs);

	u64 symb_end_ns = ktime_now_ns();
	fprintf(stderr, "Symbolized %zu user and %zu kernel UNIQUE addresses (%zu total, failed %zu) in %.3lfs.\n",
		uaddr_cnt, kaddr_cnt, uaddr_cnt + kaddr_cnt, unkn_cnt,
		(symb_end_ns - symb_start_ns) / 1000000000.0);

	u32 frame_iid = 1;
	for (int i = 0; i < state->sframe_cnt; i++) {
		struct stack_frame_index *f = &state->sframe_idx[i];

		if (i > 0 && state->sframe_idx[i - 1].pid == f->pid && state->sframe_idx[i - 1].addr == f->addr) {
			f->frame_cnt = state->sframe_idx[i - 1].frame_cnt;
			f->frame_iid = state->sframe_idx[i - 1].frame_iid;
			f->frame_iids = state->sframe_idx[i - 1].frame_iids;
			frames_deduped += f->frame_cnt;
			frames_total += f->frame_cnt;
			if (!f->sym || !f->sym->name)
				frames_failed += f->frame_cnt;
			continue;
		}

		f->frame_cnt = f->sym ? 1 + f->sym->inlined_cnt : 1;
		frames_total += f->frame_cnt;
		if (!f->sym || !f->sym->name)
			frames_failed += 1;

		if (f->frame_cnt > 1)
			f->frame_iids = calloc(f->frame_cnt, sizeof(*f->frame_iids));

		for (int j = 0; j < f->frame_cnt; j++) {
			if (f->frame_iids)
				f->frame_iids[j] = frame_iid;
			else
				f->frame_iid = frame_iid;

			debugf("ORIG FRAME #%d MAPS TO UNIQ FRAME #%d\n", f->orig_idx, frame_iid);
			frame_iid += 1;
		}
	}

	qsort(state->sframe_idx, state->sframe_cnt, sizeof(*state->sframe_idx), stack_frame_cmp_by_orig_idx);

	/* combine kernel and user stack traces into one callstack */
	comb_cnt = 0;
	for (int i = 0; i < state->strace_cnt; i++) {
		struct stack_trace_index *s = &state->strace_idx[i];

		if (s->combine) {
			struct stack_trace_index *c = &state->strace_idx[comb_cnt - 1];

			c->kframe_cnt = s->frame_cnt;
			c->frame_cnt += s->frame_cnt;
		} else {
			state->strace_idx[comb_cnt] = *s;
			comb_cnt += 1;
		}

		debugf("ORIGSTACK (%d -> %zu) (%s) %s:\n", i, comb_cnt - 1,
			s->combine ? "COMBINED WITH PREV" : "NON-COMBINED", s->pid ? "USER" : "KERNEL");
		for (int j = 0; j < s->frame_cnt; j++) {
			struct stack_frame_index *f = &state->sframe_idx[s->start_frame_idx + j];
			debugf("    ORIGFR#%d (FR#%d->%d) ADDR %llx '%s'+%lx\n",
				f->orig_idx,
				f->frame_cnt > 1 ? f->frame_iids[0] : f->frame_iid,
				(f->frame_cnt > 1 ? f->frame_iids[0] : f->frame_iid) + f->frame_cnt - 1,
				f->addr,
				f->sym && f->sym->name ? f->sym->name : "???",
				f->sym ? f->sym->offset : 0);
		}
	}
	state->strace_cnt = comb_cnt;

	/* dedup and assign callstack IIDs */
	qsort_r(state->strace_idx, state->strace_cnt, sizeof(*state->strace_idx), stack_trace_cmp_by_content, state);

	hdr.frame_mappings_off = ftell(w->dump) - base_off;

	int frame_mapping_idx = 0;
	u32 trace_iid = 1;
	for (int i = 0; i < state->strace_cnt; i++) {
		struct stack_trace_index *t = &state->strace_idx[i];
		
		if (i > 0 && stack_trace_eq(&state->strace_idx[i - 1], t, state)) {
			t->mapped_frame_idx = state->strace_idx[i - 1].mapped_frame_idx;
			t->mapped_frame_cnt = state->strace_idx[i - 1].mapped_frame_cnt;
			t->callstack_iid = state->strace_idx[i - 1].callstack_iid;
			update_event_stack_id(t->event, t->callstack_iid);
			callstacks_deduped += 1;
			debugf("ORIGSTACK%d DEDUPED INTO ORIGSTACK%d (STACK#%d) (FR#%d->%d)\n",
				t->orig_idx, state->strace_idx[i - 1].orig_idx, t->callstack_iid,
				t->mapped_frame_idx, t->mapped_frame_idx + t->mapped_frame_cnt - 1);
			continue;
		}

		t->mapped_frame_idx = frame_mapping_idx;
		t->mapped_frame_cnt = 0;

		debugf("ORIGSTACK#%d IS MAPPED TO STACK#%d\n", t->orig_idx, trace_iid);
		int fr_pos = 0;
		for (int j = 0; j < t->frame_cnt; j++) {
			const struct stack_frame_index *f = &state->sframe_idx[t->start_frame_idx + j];

			for (int k = 0; k < f->frame_cnt; k++) {
				u32 frame_iid = f->frame_cnt > 1 ? f->frame_iids[k] : f->frame_iid;
				if (fwrite(&frame_iid, sizeof(frame_iid), 1, w->dump) != 1) {
					err = -errno;
					fprintf(stderr, "Failed to write stack trace frame id: %d\n", err);
					return err;
				}
				hdr.frame_mapping_cnt += 1;
				t->mapped_frame_cnt += 1;
				frame_mapping_idx += 1;
				debugf("POS#%d ORIGF#%d -> F#%d\n", fr_pos++, f->orig_idx,  frame_iid);
			}
		}

		t->callstack_iid = trace_iid;
		update_event_stack_id(t->event, trace_iid);
		trace_iid += 1;
	}

	hdr.stacks_off = ftell(w->dump) - base_off;
	/* Add dummy all-zero stack trace record to have all the stack IDs
	 * positive, which matches well Perfetto expectations and is generally
	 * nice to have property to be able to use zero ID as "no stack"
	 * indicator (and not have to remember to adjust everything by +/-1
	 * all the time)
	 */
	{
		struct wprof_stack_trace dummy_stack;
		memset(&dummy_stack, 0, sizeof(dummy_stack));
		if (fwrite(&dummy_stack, sizeof(dummy_stack), 1, w->dump) != 1) {
			err = -errno;
			fprintf(stderr, "Failed to write dummy stack frame: %d\n", err);
			return err;
		}
		hdr.stack_cnt = 1;
	}
	for (int i = 0; i < state->strace_cnt; i++) {
		struct stack_trace_index *t = &state->strace_idx[i];
		
		if (i > 0 && stack_trace_eq(&state->strace_idx[i - 1], t, state))
			continue;

		struct wprof_stack_trace stack = {
			.frame_mapping_idx = t->mapped_frame_idx,
			.frame_mapping_cnt = t->mapped_frame_cnt,
		};
		if (fwrite(&stack, sizeof(stack), 1, w->dump) != 1) {
			err = -errno;
			fprintf(stderr, "Failed to write stack trace header: %d\n", err);
			return err;
		}
		hdr.stack_cnt += 1;
	}

	qsort(state->sframe_idx, state->sframe_cnt, sizeof(*state->sframe_idx), stack_frame_cmp_by_orig_idx);
	qsort(state->strace_idx, state->strace_cnt, sizeof(*state->strace_idx), stack_trace_cmp_by_orig_idx);

	hdr.strs_off = ftell(w->dump) - base_off;
	hdr.strs_sz = strset__data_size(strs);

	const char *strs_data = strset__data(strs);
	int strs_rem = hdr.strs_sz, strs_written = 0;
	while (strs_rem > 0 && (strs_written = fwrite(strs_data, 1, strs_rem, w->dump)) > 0) {
		strs_data += strs_written;
		strs_rem -= strs_written;
	}
	if (strs_written <= 0) {
		err = -errno;
		fprintf(stderr, "Failed to write strings: %d\n", err);
		return err;
	}

	strset__free(strs);
	strs = NULL;

	/* Finalize stack dump and re-mmap() data */
	long orig_pos = ftell(w->dump);

	w->dump_hdr->stacks_sz = ftell(w->dump) - w->dump_hdr->stacks_off;

	err = fseek(w->dump, base_off - sizeof(hdr), SEEK_SET);
	if (err) {
		err = -errno;
		fprintf(stderr, "Failed to fseek() to stacks header: %d\n", err);
		return err;
	}

	if (fwrite(&hdr, sizeof(hdr), 1, w->dump) != 1) {
		err = -errno;
		fprintf(stderr, "Failed to update stacks header: %d\n", err);
		return err;
	}

	err = fseek(w->dump, orig_pos, SEEK_SET);
	if (err) {
		err = -errno;
		fprintf(stderr, "Failed to fseek() to after stacks: %d\n", err);
		return err;
	}

	fflush(w->dump);
	fsync(fileno(w->dump));

	w->dump_mem = mremap(w->dump_mem, w->dump_sz, orig_pos, MREMAP_MAYMOVE);
	if (w->dump_mem == MAP_FAILED) {
		err = -errno;
		fprintf(stderr, "Failed to expand data dump mmap: %d\n", err);
		w->dump_mem = NULL;
		return err;
	}
	w->dump_hdr = w->dump_mem;
	w->dump_sz = orig_pos;

	u64 end_ns = ktime_now_ns();
	fprintf(stderr, "Symbolized %zu stack traces with %zu frames (%zu traces and %zu frames deduped, %zu unknown frames, %.3lfMB) in %.3lfs.\n",
		state->strace_cnt, frames_total,
		callstacks_deduped, frames_deduped,
		frames_failed,
		(orig_pos - base_off) / 1024.0 / 1024.0,
		(end_ns - start_ns) / 1000000000.0);


#if DEBUG_SYMBOLIZATION
	struct wprof_stack_frame_record *frec;
	wprof_for_each_stack_frame(frec, w->dump_hdr) {
		const char *indent = "";
		const struct wprof_stack_frame *f = frec->f;
		u32 fr_idx = frec->idx;

		const char *fname = f->func_name_stroff ? wprof_stacks_str(w->dump_hdr, f->func_name_stroff) : "???";
		const char *src = f->src_path_stroff ? wprof_stacks_str(w->dump_hdr, f->src_path_stroff) : "???";
		fprintf(stderr, "%sFRAME #%d: [%c] '%s'+%llx (%s%s), %s:%d (ADDR %llx)\n",
			indent, fr_idx,
			f->flags & WSF_KERNEL ? 'K' : 'U',
			fname, f->func_offset,
			f->flags & WSF_INLINED ? " INLINED" : "",
			f->flags & WSF_UNSYMBOLIZED ? "UNKNOWN" : "",
			src, f->line_num, f->addr);
	}
	struct wprof_stack_trace_record *trec;
	wprof_for_each_stack_trace(trec, w->dump_hdr) {
		const char *indent = "    ";

		fprintf(stderr, "STACK #%d (%u -> %u) HAS %u FRAMES:\n",
			trec->idx, trec->t->frame_mapping_idx,
			trec->t->frame_mapping_idx + trec->t->frame_mapping_cnt - 1,
			trec->t->frame_mapping_cnt);

		for (int i = 0; i < trec->t->frame_mapping_cnt; i++) {
			u32 fr_idx = trec->frame_ids[i];
			const struct wprof_stack_frame *f = wprof_stacks_frame(w->dump_hdr, fr_idx);

			const char *fname = f->func_name_stroff ? wprof_stacks_str(w->dump_hdr, f->func_name_stroff) : "???";
			const char *src = f->src_path_stroff ? wprof_stacks_str(w->dump_hdr, f->src_path_stroff) : "???";
			fprintf(stderr, "%sFRAME #%d: [%c] '%s'+%llx (%s%s), %s:%d (ADDR %llx)\n",
				indent, fr_idx,
				f->flags & WSF_KERNEL ? 'K' : 'U',
				fname, f->func_offset,
				f->flags & WSF_INLINED ? " INLINED" : "",
				f->flags & WSF_UNSYMBOLIZED ? "UNKNOWN" : "",
				src, f->line_num, f->addr);
		}
	}
#endif
	return 0;
}

int generate_stack_traces(struct worker_state *w)
{
	struct stack_trace_iids strace_iids = {};
	struct str_iid_domain fname_iids = (struct str_iid_domain) {
		.str_iids = hashmap__new(str_hash_fn, str_equal_fn, NULL),
		.next_str_iid = 1,
		.domain_desc = "func_name",
	};

	/* XXX: mapping singleton */
	pb_iid mapping_iid = 1;
	append_mapping_iid(&strace_iids.mappings, mapping_iid, 0, 0x7fffffffffffffff, 0);

	pb_iid kern_unkn_iid = str_iid_for(&fname_iids, "[K] <unknown>", NULL, NULL);
	append_str_iid(&strace_iids.func_names, kern_unkn_iid, "[K] <unknown>");
	pb_iid user_unkn_iid = str_iid_for(&fname_iids, "[U] <unknown>", NULL, NULL);
	append_str_iid(&strace_iids.func_names, user_unkn_iid, "[U] <unknown>");

	char sym_buf[1024];
	struct wprof_stack_frame_record *frec;
	wprof_for_each_stack_frame(frec, w->dump_hdr) {
		struct wprof_stack_frame *f = frec->f;
		pb_iid fname_iid = f->flags & WSF_KERNEL ? kern_unkn_iid : user_unkn_iid;
		bool new_iid = false;
		const char *sym_name = f->func_name_stroff ? wprof_stacks_str(w->dump_hdr, f->func_name_stroff) : NULL;

		if (sym_name) {
			snprintf(sym_buf, sizeof(sym_buf), "[%c] %s%s",
				 (f->flags & WSF_KERNEL) ? 'K' : 'U',
				 sym_name,
				 (f->flags & WSF_INLINED) ? " (inlined)" : "");
			sym_name = sym_buf;
		}

		if (sym_name && (fname_iid = str_iid_for(&fname_iids, sym_name, &new_iid, &sym_name)) && new_iid)
			append_str_iid(&strace_iids.func_names, fname_iid, sym_name);

		append_frame_iid(&strace_iids.frames, frec->idx, mapping_iid, fname_iid, f->func_offset);
	}

	struct wprof_stack_trace_record *trec;
	wprof_for_each_stack_trace(trec, w->dump_hdr) {
		for (int i = 0; i < trec->frame_cnt; i++) {
			append_callstack_frame_iid(&strace_iids.callstacks, trec->idx, trec->frame_ids[i]);
		}
	}

	ssize_t pb_sz_before = file_size(w->trace);
	TracePacket ev_pb = {
		PB_INIT(timestamp) = 0,
		PB_TRUST_SEQ_ID(),
		PB_INIT(interned_data) = {
			.function_names = PB_STR_IIDS(&strace_iids.func_names),
			.frames = PB_FRAMES(&strace_iids.frames),
			.callstacks = PB_CALLSTACKS(&strace_iids.callstacks),
			.mappings = PB_MAPPINGS(&strace_iids.mappings),
		},
	};
	enc_trace_packet(&w->stream, &ev_pb);
	ssize_t pb_sz_after = file_size(w->trace);
	fprintf(stderr, "Emitted %.3lfMB of stack traces data.\n", (pb_sz_after - pb_sz_before) / 1024.0 / 1024.0);
	return 0;
}

int event_stack_trace_id(struct worker_state *w, const struct wprof_event *e, size_t size)
{
	struct stack_trace *tr;

	/* if no stack traces were requested, pretend we never had them in the first place */
	if (!env.capture_stack_traces)
		return -1;

	if (!(e->flags & EF_STACK_TRACE)) /* no variable-length part of event */
		return -1;

	tr = (void *)e + e->sz;
	if (tr->stack_id > 0)
		return tr->stack_id;

	return -1;
}
