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

#include "protobuf.h"
#include "env.h"
#include "stacktrace.h"

#include "blazesym.h"

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
			   const struct worker_state *w)
{
	if (x->pid != y->pid)
		return false;

	if (x->frame_cnt != y->frame_cnt)
		return false;

	for (int i = 0; i < x->frame_cnt; i++) {
		u64 xa = w->sframe_idx[x->start_frame_idx + i].addr;
		u64 ya = w->sframe_idx[y->start_frame_idx + i].addr;

		if (xa != ya)
			return false;
	}

	return true;
}

static int stack_trace_cmp_by_content(const void *a, const void *b, void *ctx)
{
	const struct worker_state *w = ctx;
	const struct stack_trace_index *x = a, *y = b;

	if (x->pid != y->pid)
		return x->pid < y->pid ? -1 : 1;

	if (x->frame_cnt != y->frame_cnt)
		return x->frame_cnt < y->frame_cnt ? -1 : 1;

	for (int i = 0; i < x->frame_cnt; i++) {
		u64 xa = w->sframe_idx[x->start_frame_idx + i].addr;
		u64 ya = w->sframe_idx[y->start_frame_idx + i].addr;

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

static void stack_trace_append(struct worker_state *w, int pid, int start_frame_idx, int frame_cnt, bool combine)
{
	if (w->strace_cnt == w->strace_cap) {
		size_t new_cap = w->strace_cnt < 64 ? 64 : w->strace_cnt * 4 / 3;

		w->strace_idx = realloc(w->strace_idx, new_cap * sizeof(*w->strace_idx));
		w->strace_cap = new_cap;
	}
	w->strace_idx[w->strace_cnt] = (struct stack_trace_index){
		.orig_idx = w->strace_cnt,
		.pid = pid,
		.start_frame_idx = start_frame_idx,
		.frame_cnt = frame_cnt,
		.combine = combine,
	};

	w->strace_cnt++;
}

static void stack_frame_append(struct worker_state *w, int pid, int orig_pid, u64 addr)
{
	if (w->sframe_cnt == w->sframe_cap) {
		size_t new_cap = w->sframe_cnt < 256 ? 256 : w->sframe_cnt * 4 / 3;

		w->sframe_idx = realloc(w->sframe_idx, new_cap * sizeof(*w->sframe_idx));
		w->sframe_cap = new_cap;
	}
	w->sframe_idx[w->sframe_cnt] = (struct stack_frame_index){
		.orig_idx = w->sframe_cnt,
		.pid = pid,
		.orig_pid = orig_pid,
		.addr = addr,
		.sym = NULL,
	};

	w->sframe_cnt++;
}

static int process_event_stack_trace(struct worker_state *w, struct wprof_event *e, size_t size)
{
	struct stack_trace *tr;
	const u64 *kaddrs = NULL, *uaddrs = NULL;
	int ucnt = 0, kcnt = 0;


	if (e->sz == size) /* no variable-length part of event */
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
		stack_trace_append(w, e->task.pid, w->sframe_cnt, ucnt, false /*!combine*/);
		for (int i = ucnt - 1; i >= 0; i--)
			stack_frame_append(w, e->task.pid, e->task.pid, uaddrs[i]);
	}

	if (kaddrs) {
		stack_trace_append(w, 0, w->sframe_cnt, kcnt, !!uaddrs /*combine*/);
		for (int i = kcnt - 1; i >= 0; i--)
			stack_frame_append(w, 0 /* kernel */, e->task.pid, kaddrs[i]);
	}

	return 0;
}

int process_stack_traces(struct worker_state *w, const void *dump_mem, size_t dump_sz)
{
	struct wprof_event *rec;
	size_t rec_sz, off, idx, kaddr_cnt = 0, uaddr_cnt = 0, unkn_cnt = 0, comb_cnt = 0;
	size_t frames_deduped = 0, frames_total = 0, frames_failed = 0, callstacks_deduped = 0;
	u64 start_ns = ktime_now_ns();
	int err;

	if (!env.stack_traces)
		return 0;
	if (!w->trace)
		goto skip_trace;

	fprintf(stderr, "Symbolizing...\n");

	off = 0;
	idx = 0;
	while (off < dump_sz) {
		rec_sz = *(size_t *)(dump_mem + off);
		rec = (struct wprof_event *)(dump_mem + off + sizeof(rec_sz));
		err = process_event_stack_trace(w, rec, rec_sz);
		if (err) {
			fprintf(stderr, "Failed to pre-process stack trace for event #%zu (kind %d, size %zu, offset %zu): %d\n",
				idx, rec->kind, rec_sz, off, err);
			return err;
		}
		off += sizeof(rec_sz) + rec_sz;
		idx += 1;
	}

	/* group by pid+addr */
	qsort(w->sframe_idx, w->sframe_cnt, sizeof(*w->sframe_idx), stack_frame_cmp_by_pid_addr);

	u64 symb_start_ns = ktime_now_ns();
	u64 *addrs = NULL;
	size_t addr_cap = 0;
	for (int start = 0, end = 1; end <= w->sframe_cnt; end++) {
		if (end < w->sframe_cnt && w->sframe_idx[start].pid == w->sframe_idx[end].pid)
			continue;

		if (end - start > addr_cap) {
			addr_cap = end - start;
			addrs = realloc(addrs, sizeof(*addrs) * addr_cap);
		}

		size_t addr_cnt = 0;
		for (int i = 0; i < end - start; i++) {
			u64 addr = w->sframe_idx[start + i].addr;

			if (addr_cnt > 0 && addr == addrs[addr_cnt - 1])
				continue;

			addrs[addr_cnt] = addr;
			addr_cnt += 1;
		}

		struct blaze_symbolizer_opts blaze_opts = {
			.type_size = sizeof(struct blaze_symbolizer_opts),
			.auto_reload = false,
			.code_info = false,
			.inlined_fns = true,
			.demangle = true,
		};
		struct blaze_symbolizer *symbolizer = blaze_symbolizer_new_opts(&blaze_opts);
		if (!symbolizer) {
			enum blaze_err berr = blaze_err_last();
			const char *berr_str = blaze_err_str(berr);

			fprintf(stderr, "Failed to create a symbolizer: %s (%d)\n", berr_str, berr);
			return berr;
		}

		/* symbolize [start .. end - 1] range */
		const struct blaze_syms *syms;
		if (w->sframe_idx[start].pid == 0) { /* kernel addresses */
			struct blaze_symbolize_src_kernel src = {
				.type_size = sizeof(src),
				.debug_syms = true,
			};
			syms = blaze_symbolize_kernel_abs_addrs(symbolizer, &src, (const void *)addrs, addr_cnt);
			kaddr_cnt += addr_cnt;
		} else {
			struct blaze_symbolize_src_process src = {
				.type_size = sizeof(src),
				.pid = w->sframe_idx[start].pid,
				.map_files = true,
				.debug_syms = true,
			};
			syms = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const void *)addrs, addr_cnt);
			if (!syms && blaze_err_last() != BLAZE_ERR_NOT_FOUND) {
				src.debug_syms = false;
				syms = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const void *)addrs, addr_cnt);
			}
			uaddr_cnt += addr_cnt;
		}
		if (!syms) {
			enum blaze_err berr = blaze_err_last();
			const char *berr_str = blaze_err_str(berr);

			unkn_cnt += end - start;

			fprintf(stderr, "Symbolization failed for PID %d: %s (%d)\n",
				w->sframe_idx[start].pid, berr_str, berr);
		} else {
			for (int i = 0, j = 0; i < end - start; i++) {
				if (i > 0 && w->sframe_idx[start + i - 1].addr == w->sframe_idx[start + i].addr) {
					w->sframe_idx[start + i].sym = w->sframe_idx[start + i - 1].sym;
				} else {
					w->sframe_idx[start + i].sym = &syms->syms[j];
					j++;
				}
			}
		}

#if 0
		int pid_of_interest = 869620;
		for (int k = start; k < end; k++) {
			struct stack_frame_index *f = &w->sframe_idx[k];

			if (f->sym && f->sym->name && f->orig_pid != pid_of_interest)
				continue;

			if (k > start && w->sframe_idx[k - 1].pid == f->pid &&
			    w->sframe_idx[k - 1].addr == f->addr)
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
		start = end;
		blaze_symbolizer_free(symbolizer);
	}
	free(addrs);

	u64 symb_end_ns = ktime_now_ns();
	fprintf(stderr, "Symbolized %zu user and %zu kernel unique addresses (%zu total, failed %zu) in %.3lfms.\n",
		uaddr_cnt, kaddr_cnt, uaddr_cnt + kaddr_cnt, unkn_cnt,
		(symb_end_ns - symb_start_ns) / 1000000.0);

	/* XXX: mapping singleton */
	pb_iid mapping_iid = 1;
	append_mapping_iid(&w->strace_iids.mappings, mapping_iid, 0, 0x7fffffffffffffff, 0);

	w->fname_iids = (struct str_iid_domain) {
		.str_iids = hashmap__new(str_hash_fn, str_equal_fn, NULL),
		.next_str_iid = 1,
		.domain_desc = "func_name",
	};

	pb_iid unkn_iid = str_iid_for(&w->fname_iids, "<unknown>", NULL, NULL);
	append_str_iid(&w->strace_iids.func_names, unkn_iid, "<unknown>");

	char sym_buf[1024];
	pb_iid frame_iid = 1;
	for (int i = 0; i < w->sframe_cnt; i++) {
		struct stack_frame_index *f = &w->sframe_idx[i];

		if (i > 0 && w->sframe_idx[i - 1].pid == f->pid && w->sframe_idx[i - 1].addr == f->addr) {
			f->frame_cnt = w->sframe_idx[i - 1].frame_cnt;
			f->frame_iid = w->sframe_idx[i - 1].frame_iid;
			f->frame_iids = w->sframe_idx[i - 1].frame_iids;
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
			const char *sym_name;
			size_t offset;
			pb_iid fname_iid = unkn_iid;
			bool new_iid = false;

			offset = j == 0 ? (f->sym && f->sym->name ? f->sym->offset : f->addr) : 0;
			sym_name = j == 0 ? (f->sym ? f->sym->name : NULL) : f->sym->inlined[j - 1].name;

			if (sym_name) {
				snprintf(sym_buf, sizeof(sym_buf),
					 "[%c] %s%s", f->pid ? 'U' : 'K', sym_name, j > 0 ? "inlined" : "");
				sym_name = sym_buf;
			}

			if (sym_name && (fname_iid = str_iid_for(&w->fname_iids, sym_name, &new_iid, &sym_name)) && new_iid)
				append_str_iid(&w->strace_iids.func_names, fname_iid, sym_name);

			append_frame_iid(&w->strace_iids.frames, frame_iid, mapping_iid, fname_iid, offset);

			if (f->frame_iids)
				f->frame_iids[j] = frame_iid;
			else
				f->frame_iid = frame_iid;

			frame_iid += 1;
		}
	}

	qsort(w->sframe_idx, w->sframe_cnt, sizeof(*w->sframe_idx), stack_frame_cmp_by_orig_idx);

	/* combine kernel and user stack traces into one callstack */
	comb_cnt = 0;
	for (int i = 0; i < w->strace_cnt; i++) {
		struct stack_trace_index *s = &w->strace_idx[i];

		if (s->combine) {
			struct stack_trace_index *c = &w->strace_idx[comb_cnt - 1];

			c->kframe_cnt = s->frame_cnt;
			c->frame_cnt += s->frame_cnt;
		} else {
			w->strace_idx[comb_cnt] = *s;
			comb_cnt += 1;
		}
	}
	w->strace_cnt = comb_cnt;

	/* dedup and assign callstack IIDs */
	qsort_r(w->strace_idx, w->strace_cnt, sizeof(*w->strace_idx), stack_trace_cmp_by_content, w);

	pb_iid trace_iid = 1;
	for (int i = 0; i < w->strace_cnt; i++) {
		struct stack_trace_index *t = &w->strace_idx[i];
		
		if (i > 0 && stack_trace_eq(&w->strace_idx[i - 1], t, w)) {
			t->callstack_iid = w->strace_idx[i - 1].callstack_iid;
			callstacks_deduped += 1;
			continue;
		}

		for (int j = 0; j < t->frame_cnt; j++) {
			const struct stack_frame_index *f = &w->sframe_idx[t->start_frame_idx + j];

			for (int k = 0; k < f->frame_cnt; k++) {
				pb_iid frame_iid = f->frame_cnt > 1 ? f->frame_iids[k] : f->frame_iid;

				append_callstack_frame_iid(&w->strace_iids.callstacks, trace_iid, frame_iid);
			}
		}

		t->callstack_iid = trace_iid;
		trace_iid += 1;
	}

	qsort(w->sframe_idx, w->sframe_cnt, sizeof(*w->sframe_idx), stack_frame_cmp_by_orig_idx);
	qsort(w->strace_idx, w->strace_cnt, sizeof(*w->strace_idx), stack_trace_cmp_by_orig_idx);

	ssize_t pb_sz_before = file_size(w->trace);
	TracePacket ev_pb = {
		PB_INIT(timestamp) = 0,
		PB_TRUST_SEQ_ID(),
		PB_INIT(interned_data) = {
			.function_names = PB_STR_IIDS(&w->strace_iids.func_names),
			.frames = PB_FRAMES(&w->strace_iids.frames),
			.callstacks = PB_CALLSTACKS(&w->strace_iids.callstacks),
			.mappings = PB_MAPPINGS(&w->strace_iids.mappings),
		},
	};
	enc_trace_packet(&w->stream, &ev_pb);
	ssize_t pb_sz_after = file_size(w->trace);
	fprintf(stderr, "Emitted %.3lfMB of stack traces data.\n", (pb_sz_after - pb_sz_before) / 1024.0 / 1024.0);

skip_trace:
	u64 end_ns = ktime_now_ns();
	fprintf(stderr, "Symbolized %zu stack traces with %zu frames (%zu traces and %zu frames deduped, %zu unknown frames) in %.3lfms.\n",
		w->strace_cnt, frames_total,
		callstacks_deduped, frames_deduped,
		frames_failed,
		(end_ns - start_ns) / 1000000.0);

	return 0;
}

int event_stack_trace_id(struct worker_state *w, const struct wprof_event *e, size_t size)
{
	struct stack_trace *tr;

	if (e->sz == size) /* no variable-length part of event */
		return -1;

	tr = (void *)e + e->sz;
	if (tr->kstack_sz > 0 || tr->ustack_sz > 0) {
		w->next_stack_trace_id += 1;
		return w->next_stack_trace_id - 1;
	}

	return -1;
}
