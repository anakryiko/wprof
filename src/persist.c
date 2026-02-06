// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "persist.h"
#include "utils.h"
#include "pmu.h"
#include "cuda_data.h"
#include "proc.h"
#include "../libbpf/src/strset.h"
#include "../libbpf/src/hashmap.h"

#define THREAD_TABLE_INIT_CAP 1024
#define PMU_VALS_INIT_CAP 4096

/*
 * Thread table lookup key.
 * We store a pointer to this in the hashmap, so it must be heap-allocated.
 */
struct thread_key {
	u32 tid;
	u32 pid;
	char comm[TASK_COMM_FULL_LEN];
	char pcomm[TASK_COMM_LEN];
};

static size_t thread_key_hash_fn(long key, void *ctx)
{
	const struct thread_key *k = (void *)key;
	size_t h;

	h = k->tid;
	h = h * 31 + k->pid;
	h = h * 31 + str_hash(k->comm);
	h = h * 31 + str_hash(k->pcomm);
	return h;
}

static bool thread_key_equal_fn(long a, long b, void *ctx)
{
	const struct thread_key *ka = (void *)a;
	const struct thread_key *kb = (void *)b;

	return ka->tid == kb->tid &&
	       ka->pid == kb->pid &&
	       strcmp(ka->comm, kb->comm) == 0 &&
	       strcmp(ka->pcomm, kb->pcomm) == 0;
}

int persist_state_init(struct persist_state *ps, int pmu_cnt)
{
	memset(ps, 0, sizeof(*ps));

	ps->strs = strset__new(UINT_MAX, "", 1);
	if (!ps->strs)
		return -ENOMEM;

	ps->threads.lookup = hashmap__new(thread_key_hash_fn, thread_key_equal_fn, NULL);
	if (!ps->threads.lookup)
		goto err_out;

	ps->threads.entries = calloc(THREAD_TABLE_INIT_CAP, sizeof(*ps->threads.entries));
	if (!ps->threads.entries)
		goto err_out;

	ps->threads.capacity = THREAD_TABLE_INIT_CAP;
	ps->threads.count = 1; /* reserve index 0 as invalid/null */

	ps->pmu_vals.pmu_cnt = pmu_cnt;
	if (pmu_cnt > 0) {
		ps->pmu_vals.data = calloc(PMU_VALS_INIT_CAP * pmu_cnt, sizeof(u64));
		if (!ps->pmu_vals.data)
			goto err_out;
		ps->pmu_vals.capacity = PMU_VALS_INIT_CAP;
		ps->pmu_vals.count = 1; /* reserve index 0 as null entry */
	}

	return 0;
err_out:
	persist_state_free(ps);
	return -ENOMEM;
}

void persist_state_free(struct persist_state *ps)
{
	struct hashmap_entry *entry;
	size_t bkt;

	if (ps->threads.lookup) {
		/* free all allocated keys */
		hashmap__for_each_entry(ps->threads.lookup, entry, bkt) {
			free((void *)entry->key);
		}
		hashmap__free(ps->threads.lookup);
	}
	free(ps->threads.entries);
	free(ps->pmu_vals.data);
	free(ps->pmu_defs);
	strset__free(ps->strs);
}

int persist_stroff(struct persist_state *ps, const char *str)
{
	if (!str || !str[0])
		return 0;
	return strset__add_str(ps->strs, str);
}

int persist_task_id(struct persist_state *ps, const struct wprof_task *task)
{
	struct thread_key key;
	long task_id;

	key.tid = task->tid;
	key.pid = task->pid;
	snprintf(key.comm, sizeof(key.comm), "%s", task->comm);
	snprintf(key.pcomm, sizeof(key.pcomm), "%s", task->pcomm);

	if (hashmap__find(ps->threads.lookup, &key, &task_id))
		return task_id;

	if (ps->threads.count >= ps->threads.capacity) {
		size_t new_cap = ps->threads.capacity * 3 / 2;

		ps->threads.entries = realloc(ps->threads.entries, new_cap * sizeof(*ps->threads.entries));
		ps->threads.capacity = new_cap;
	}

	task_id = ps->threads.count;
	struct wevent_task *entry = &ps->threads.entries[task_id];

	entry->tid = task->tid;
	entry->pid = task->pid;
	entry->flags = task->flags;
	entry->comm_stroff = persist_stroff(ps, task->comm);
	entry->pcomm_stroff = persist_stroff(ps, task->pcomm);

	/* allocate key for hashmap (needs to persist) */
	struct thread_key *pkey = malloc(sizeof(key));
	*pkey = key;

	hashmap__add(ps->threads.lookup, pkey, task_id);

	ps->threads.count += 1;

	return (int)task_id;
}

int persist_pmu_vals_id(struct persist_state *ps, const struct perf_counters *ctrs)
{
	if (!ctrs || ps->pmu_vals.pmu_cnt == 0)
		return 0;

	size_t sz = ps->pmu_vals.pmu_cnt * sizeof(u64);

	if (ps->pmu_vals.count >= ps->pmu_vals.capacity) {
		u32 new_cap = ps->pmu_vals.capacity * 3 / 2;

		ps->pmu_vals.data = realloc(ps->pmu_vals.data, new_cap * sz);
		ps->pmu_vals.capacity = new_cap;
	}

	u64 *dest = &ps->pmu_vals.data[ps->pmu_vals.count * ps->pmu_vals.pmu_cnt];
	memcpy(dest, ctrs->val, sz);
	ps->pmu_vals.count += 1;

	return ps->pmu_vals.count - 1;
}

int persist_add_pmu_def(struct persist_state *ps, const struct pmu_event *ev)
{
	ps->pmu_defs = realloc(ps->pmu_defs, (ps->pmu_def_cnt + 1) * sizeof(*ps->pmu_defs));

	struct wevent_pmu_def *def = &ps->pmu_defs[ps->pmu_def_cnt];
	def->perf_type = ev->perf_type;
	def->config = ev->config;
	def->config1 = ev->config1;
	def->config2 = ev->config2;
	def->name_stroff = persist_stroff(ps, ev->name);

	ps->pmu_def_cnt += 1;
	return ps->pmu_def_cnt - 1;
}

static void fill_wevent_hdr(struct wevent_hdr *hdr, const struct wprof_event *e, u32 task_id, u16 sz)
{
	hdr->sz = sz;
	hdr->flags = e->flags;
	hdr->kind = e->kind;
	hdr->task_id = task_id;
	hdr->cpu = e->cpu;
	hdr->numa_node = e->numa_node;
	hdr->ts = e->ts;
}

int persist_bpf_event(struct persist_state *ps,
		      const struct wprof_event *e, size_t src_sz,
		      struct wevent *dst)
{
	int task_id = persist_task_id(ps, &e->task);
	size_t trailing_sz = src_sz - e->sz;

	switch (e->kind) {
	case EV_SWITCH: {
		fill_wevent_hdr(&dst->hdr, e, task_id, WEVENT_SZ(swtch) + trailing_sz);

		dst->swtch.next_task_id = persist_task_id(ps, &e->swtch.next);
		dst->swtch.waker_task_id = persist_task_id(ps, &e->swtch.waker);
		dst->swtch.pmu_vals_id = persist_pmu_vals_id(ps, &e->swtch.ctrs);
		dst->swtch.waking_flags = e->swtch.waking_flags;
		dst->swtch.waking_ts = e->swtch.waking_ts;
		dst->swtch.prev_task_state = e->swtch.prev_task_state;
		dst->swtch.last_next_task_state = e->swtch.last_next_task_state;
		dst->swtch.prev_prio = e->swtch.prev_prio;
		dst->swtch.next_prio = e->swtch.next_prio;
		dst->swtch.waker_cpu = e->swtch.waker_cpu;
		dst->swtch.waker_numa_node = e->swtch.waker_numa_node;
		dst->swtch.next_task_scx_layer_id = e->swtch.next_task_scx_layer_id;
		dst->swtch.next_task_scx_dsq_id = e->swtch.next_task_scx_dsq_id;
		break;
	}
	case EV_TIMER:
		fill_wevent_hdr(&dst->hdr, e, task_id, WEVENT_SZ(timer) + trailing_sz);
		break;

	case EV_WAKING: {
		fill_wevent_hdr(&dst->hdr, e, task_id, WEVENT_SZ(waking) + trailing_sz);

		dst->waking.wakee_task_id = persist_task_id(ps, &e->waking.wakee);
		break;
	}
	case EV_WAKEUP_NEW: {
		fill_wevent_hdr(&dst->hdr, e, task_id, WEVENT_SZ(wakeup_new) + trailing_sz);

		dst->wakeup_new.wakee_task_id = persist_task_id(ps, &e->wakeup_new.wakee);
		break;
	}
	case EV_HARDIRQ_EXIT: {
		fill_wevent_hdr(&dst->hdr, e, task_id, WEVENT_SZ(hardirq) + trailing_sz);

		dst->hardirq.hardirq_ts = e->hardirq.hardirq_ts;
		dst->hardirq.irq = e->hardirq.irq;
		dst->hardirq.name_stroff = persist_stroff(ps, e->hardirq.name);
		dst->hardirq.pmu_vals_id = persist_pmu_vals_id(ps, &e->hardirq.ctrs);
		break;
	}
	case EV_SOFTIRQ_EXIT: {
		fill_wevent_hdr(&dst->hdr, e, task_id, WEVENT_SZ(softirq) + trailing_sz);

		dst->softirq.softirq_ts = e->softirq.softirq_ts;
		dst->softirq.vec_nr = e->softirq.vec_nr;
		dst->softirq.pmu_vals_id = persist_pmu_vals_id(ps, &e->softirq.ctrs);
		break;
	}
	case EV_WQ_END: {
		fill_wevent_hdr(&dst->hdr, e, task_id, WEVENT_SZ(wq) + trailing_sz);

		dst->wq.wq_ts = e->wq.wq_ts;
		dst->wq.desc_stroff = persist_stroff(ps, e->wq.desc);
		dst->wq.pmu_vals_id = persist_pmu_vals_id(ps, &e->wq.ctrs);
		break;
	}
	case EV_FORK: {
		fill_wevent_hdr(&dst->hdr, e, task_id, WEVENT_SZ(fork) + trailing_sz);

		dst->fork.child_task_id = persist_task_id(ps, &e->fork.child);
		break;
	}
	case EV_EXEC:
		fill_wevent_hdr(&dst->hdr, e, task_id, WEVENT_SZ(exec) + trailing_sz);

		dst->exec.old_tid = e->exec.old_tid;
		dst->exec.filename_stroff = persist_stroff(ps, e->exec.filename);
		break;

	case EV_TASK_RENAME:
		fill_wevent_hdr(&dst->hdr, e, task_id, WEVENT_SZ(rename) + trailing_sz);

		dst->rename.new_comm_stroff = persist_stroff(ps, e->rename.new_comm);
		break;

	case EV_TASK_EXIT:
		fill_wevent_hdr(&dst->hdr, e, task_id, WEVENT_SZ(task_exit) + trailing_sz);
		break;

	case EV_TASK_FREE:
		fill_wevent_hdr(&dst->hdr, e, task_id, WEVENT_SZ(task_free) + trailing_sz);
		break;

	case EV_IPI_SEND:
		fill_wevent_hdr(&dst->hdr, e, task_id, WEVENT_SZ(ipi_send) + trailing_sz);

		dst->ipi_send.ipi_id = e->ipi_send.ipi_id;
		dst->ipi_send.kind = e->ipi_send.kind;
		dst->ipi_send.target_cpu = e->ipi_send.target_cpu;
		break;

	case EV_IPI_EXIT: {
		fill_wevent_hdr(&dst->hdr, e, task_id, WEVENT_SZ(ipi) + trailing_sz);

		dst->ipi.ipi_ts = e->ipi.ipi_ts;
		dst->ipi.send_ts = e->ipi.send_ts;
		dst->ipi.ipi_id = e->ipi.ipi_id;
		dst->ipi.kind = e->ipi.kind;
		dst->ipi.send_cpu = e->ipi.send_cpu;
		dst->ipi.pmu_vals_id = persist_pmu_vals_id(ps, &e->ipi.ctrs);
		break;
	}
	case EV_REQ_EVENT:
		fill_wevent_hdr(&dst->hdr, e, task_id, WEVENT_SZ(req) + trailing_sz);

		dst->req.req_ts = e->req.req_ts;
		dst->req.req_id = e->req.req_id;
		dst->req.req_event = e->req.req_event;
		dst->req.req_name_stroff = persist_stroff(ps, e->req.req_name);
		break;

	case EV_REQ_TASK_EVENT:
		fill_wevent_hdr(&dst->hdr, e, task_id, WEVENT_SZ(req_task) + trailing_sz);

		dst->req_task.req_task_event = e->req_task.req_task_event;
		dst->req_task.req_id = e->req_task.req_id;
		dst->req_task.req_task_id = e->req_task.task_id;
		dst->req_task.enqueue_ts = e->req_task.enqueue_ts;
		dst->req_task.wait_time_ns = e->req_task.wait_time_ns;
		dst->req_task.run_time_ns = e->req_task.run_time_ns;
		break;

	case EV_SCX_DSQ_END:
		fill_wevent_hdr(&dst->hdr, e, task_id, WEVENT_SZ(scx_dsq) + trailing_sz);

		dst->scx_dsq.scx_dsq_insert_ts = e->scx_dsq.scx_dsq_insert_ts;
		dst->scx_dsq.scx_dsq_id = e->scx_dsq.scx_dsq_id;
		dst->scx_dsq.scx_layer_id = e->scx_dsq.scx_layer_id;
		dst->scx_dsq.scx_dsq_insert_type = e->scx_dsq.scx_dsq_insert_type;
		break;

	case EV_CUDA_CALL:
		fill_wevent_hdr(&dst->hdr, e, task_id, WEVENT_SZ(cuda_call) + trailing_sz);

		dst->cuda_call.domain = e->cuda_call.domain;
		dst->cuda_call.cbid = e->cuda_call.cbid;
		dst->cuda_call.corr_id = e->cuda_call.corr_id;
		break;

	default:
		eprintf("Unrecognized event type %d while persisting!\n", e->kind);
		return -EINVAL;
	}

	/* XXX: we shouldn't have trailing size, to be cleaned up */
	if (trailing_sz > 0) {
		void *src = (void *)e + e->sz;
		void *dst_tail = (void *)dst + dst->hdr.sz - trailing_sz;
		memcpy(dst_tail, src, trailing_sz);
	}

	return dst->hdr.sz;
}

struct tid_cache_value {
	int host_tid;
	char thread_name[16];
};

static int resolve_cuda_api_task_id(struct persist_state *ps,
				    int host_pid, const char *proc_name,
				    struct hashmap *tid_cache,
				    const struct wcuda_event *e)
{
	long key = ((u64)host_pid << 32) | (u32)e->cuda_api.tid;
	struct tid_cache_value *ti = NULL;

	if (hashmap__find(tid_cache, key, &ti)) {
		if (ti->host_tid <= 0)
			return 0;
	} else {
		ti = calloc(1, sizeof(*ti));

		if (host_pid == e->cuda_api.pid) {
			/* no namespacing, no need to resolve TID */
			ti->host_tid = e->cuda_api.tid;
		} else {
			ti->host_tid = host_tid_by_ns_tid(host_pid, e->cuda_api.tid);
			if (ti->host_tid < 0) {
				eprintf("FAILED to resolve host-level TID by namespaced TID %d (PID %d, %s): %d\n",
					e->cuda_api.tid, host_pid, proc_name, ti->host_tid);
				/* negative cache this TID so we don't do expensive look ups again */
				ti->host_tid = 0;
				ti->thread_name[0] = '\0';
				goto cache;
			}
		}

		(void)thread_name_by_tid(host_pid, ti->host_tid, ti->thread_name, sizeof(ti->thread_name));
cache:
		hashmap__add(tid_cache, key, ti);
	}

	if (ti->host_tid <= 0)
		return 0;

	struct wprof_task task = {
		.tid = ti->host_tid,
		.pid = host_pid,
		.flags = 0,
	};
	snprintf(task.comm, sizeof(task.comm), "%s", ti->thread_name);
	snprintf(task.pcomm, sizeof(task.pcomm), "%s", proc_name);

	return persist_task_id(ps, &task);
}

static void fill_cuda_wevent_hdr(struct wevent_hdr *hdr, const struct wcuda_event *e,
				 enum event_kind kind, u32 task_id, u16 sz)
{
	hdr->sz = sz;
	hdr->flags = e->flags;
	hdr->kind = kind;
	hdr->task_id = task_id;
	hdr->cpu = 0;
	hdr->numa_node = 0;
	hdr->ts = e->ts;
}

int persist_cuda_event(struct persist_state *ps, const struct wcuda_event *e, struct wevent *dst,
		       int host_pid, const char *proc_name, const char *cuda_strs,
		       struct hashmap *tid_cache)
{
	switch (e->kind) {
	case WCK_CUDA_API: {
		int task_id = resolve_cuda_api_task_id(ps, host_pid, proc_name, tid_cache, e);
		fill_cuda_wevent_hdr(&dst->hdr, e, EV_CUDA_API, task_id, WEVENT_SZ(cuda_api));

		dst->cuda_api.end_ts = e->cuda_api.end_ts;
		dst->cuda_api.corr_id = e->cuda_api.corr_id;
		dst->cuda_api.cbid = e->cuda_api.cbid;
		dst->cuda_api.task_id = task_id;
		dst->cuda_api.ret_val = e->cuda_api.ret_val;
		dst->cuda_api.kind = e->cuda_api.kind;
		break;
	}

	case WCK_CUDA_KERNEL:
		fill_cuda_wevent_hdr(&dst->hdr, e, EV_CUDA_KERNEL, 0, WEVENT_SZ(cuda_kernel));

		dst->cuda_kernel.end_ts = e->cuda_kernel.end_ts;
		dst->cuda_kernel.name_stroff = persist_stroff(ps, cuda_strs + e->cuda_kernel.name_off);
		dst->cuda_kernel.corr_id = e->cuda_kernel.corr_id;
		dst->cuda_kernel.device_id = e->cuda_kernel.device_id;
		dst->cuda_kernel.ctx_id = e->cuda_kernel.ctx_id;
		dst->cuda_kernel.stream_id = e->cuda_kernel.stream_id;
		dst->cuda_kernel.grid_x = e->cuda_kernel.grid_x;
		dst->cuda_kernel.grid_y = e->cuda_kernel.grid_y;
		dst->cuda_kernel.grid_z = e->cuda_kernel.grid_z;
		dst->cuda_kernel.block_x = e->cuda_kernel.block_x;
		dst->cuda_kernel.block_y = e->cuda_kernel.block_y;
		dst->cuda_kernel.block_z = e->cuda_kernel.block_z;
		break;

	case WCK_CUDA_MEMCPY:
		fill_cuda_wevent_hdr(&dst->hdr, e, EV_CUDA_MEMCPY, 0, WEVENT_SZ(cuda_memcpy));

		dst->cuda_memcpy.end_ts = e->cuda_memcpy.end_ts;
		dst->cuda_memcpy.byte_cnt = e->cuda_memcpy.byte_cnt;
		dst->cuda_memcpy.corr_id = e->cuda_memcpy.corr_id;
		dst->cuda_memcpy.device_id = e->cuda_memcpy.device_id;
		dst->cuda_memcpy.ctx_id = e->cuda_memcpy.ctx_id;
		dst->cuda_memcpy.stream_id = e->cuda_memcpy.stream_id;
		dst->cuda_memcpy.copy_kind = e->cuda_memcpy.copy_kind;
		dst->cuda_memcpy.src_kind = e->cuda_memcpy.src_kind;
		dst->cuda_memcpy.dst_kind = e->cuda_memcpy.dst_kind;
		break;

	case WCK_CUDA_MEMSET:
		fill_cuda_wevent_hdr(&dst->hdr, e, EV_CUDA_MEMSET, 0, WEVENT_SZ(cuda_memset));

		dst->cuda_memset.end_ts = e->cuda_memset.end_ts;
		dst->cuda_memset.byte_cnt = e->cuda_memset.byte_cnt;
		dst->cuda_memset.corr_id = e->cuda_memset.corr_id;
		dst->cuda_memset.device_id = e->cuda_memset.device_id;
		dst->cuda_memset.ctx_id = e->cuda_memset.ctx_id;
		dst->cuda_memset.stream_id = e->cuda_memset.stream_id;
		dst->cuda_memset.value = e->cuda_memset.value;
		dst->cuda_memset.mem_kind = e->cuda_memset.mem_kind;
		break;

	case WCK_CUDA_SYNC:
		fill_cuda_wevent_hdr(&dst->hdr, e, EV_CUDA_SYNC, 0, WEVENT_SZ(cuda_sync));

		dst->cuda_sync.end_ts = e->cuda_sync.end_ts;
		dst->cuda_sync.corr_id = e->cuda_sync.corr_id;
		dst->cuda_sync.stream_id = e->cuda_sync.stream_id;
		dst->cuda_sync.ctx_id = e->cuda_sync.ctx_id;
		dst->cuda_sync.event_id = e->cuda_sync.event_id;
		dst->cuda_sync.sync_type = e->cuda_sync.sync_type;
		break;

	default:
		eprintf("Unrecognized CUDA event type %d while persisting!\n", e->kind);
		return -EINVAL;
	}

	return dst->hdr.sz;
}
