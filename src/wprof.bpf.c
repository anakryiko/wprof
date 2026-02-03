// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2025 Meta Platforms, Inc. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>

#include "wprof.h"
#include "wprof.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct cpu_state {
	u64 ipi_counter;
	u64 ipi_ts;
	u64 ipi_send_ts;
	int ipi_send_cpu;
	struct perf_counters ipi_ctrs;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int); /* task_id, see task_id() */
	__type(value, struct task_state);
} task_states SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct wprof_stats);
	__uint(max_entries, 1);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct stack_trace);
	__uint(max_entries, 1); /* maximum number of stack traces per event */
} stack_trace_scratch SEC(".maps");

#define inc_stat(stat) ({							\
	u64 __s = 0;								\
	struct wprof_stats *s = bpf_map_lookup_elem(&stats, (void *)&zero);	\
	if (s) { s->stat++; __s = s->stat; }					\
	__s;									\
})

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, int);
	__type(value, int);
} perf_cntrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, u32);
	__array(values, struct {
		__uint(type, BPF_MAP_TYPE_RINGBUF);
		 /* max_entries doesn't matter, just to successfully create inner map proto */
		__uint(max_entries, 64 * 1024);
	});
} rbs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_state);
	__uint(max_entries, 1);
} cpu_states SEC(".maps");

/* FILTERING */
const volatile enum wprof_filt_mode filt_mode;

int allow_pids[1] SEC(".data.allow_pids");
const volatile int allow_pid_cnt;
int deny_pids[1] SEC(".data.deny_pids");
const volatile int deny_pid_cnt;

int allow_tids[1] SEC(".data.allow_tids");
const volatile int allow_tid_cnt;
int deny_tids[1] SEC(".data.deny_tids");
const volatile int deny_tid_cnt;

struct glob_str allow_pnames[1] SEC(".data.allow_pnames");
const volatile int allow_pname_cnt;
struct glob_str deny_pnames[1] SEC(".data.deny_pnames");
const volatile int deny_pname_cnt;

struct glob_str allow_tnames[1] SEC(".data.allow_tnames");
const volatile int allow_tname_cnt;
struct glob_str deny_tnames[1] SEC(".data.deny_tnames");
const volatile int deny_tname_cnt;
/* END FILTERING */

const volatile u32 perf_ctr_cnt = 1; /* for veristat, reset in user space */

u32 rb_cpu_map[1] SEC(".data.rb_cpu_map");
const volatile u64 rb_cpu_map_mask;
const volatile u64 rb_cnt;

const volatile u64 rb_submit_threshold_bytes;

const volatile enum stack_trace_kind requested_stack_traces = ST_ALL;
const volatile bool capture_scx_layer_id = true;

static int zero = 0;
static struct task_state empty_task_state;

u64 session_start_ts;
u64 session_end_ts;

/* XXX: pass CPU explicitly to avoid unnecessary surprises */
static __always_inline int task_id(int pid)
{
	/* use CPU ID for identifying idle tasks */
	return pid ?: -(bpf_get_smp_processor_id() + 1);
}

__hidden struct task_state *task_state(int pid)
{
	struct task_state *s;
	int id = task_id(pid);

	s = bpf_map_lookup_elem(&task_states, &id);
	if (!s) {
		bpf_map_update_elem(&task_states, &id, &empty_task_state, BPF_NOEXIST);
		s = bpf_map_lookup_elem(&task_states, &id);
	}
	if (!s)
		(void)inc_stat(task_state_drops);
	return s;
}

/* don't create an entry if it's not there already */
static struct task_state *task_state_peek(int pid)
{
	int id = task_id(pid);

	return bpf_map_lookup_elem(&task_states, &id);
}

static void task_state_delete(int pid)
{
	int id = task_id(pid);

	bpf_map_delete_elem(&task_states, &id);
}

struct comm_str { char str[TASK_COMM_LEN]; };

bool glob_match_comm(struct glob_str *glob, struct comm_str *comm)
{
	return glob_match(glob->pat, sizeof(glob->pat), comm->str, sizeof(comm->str));
}

static bool should_trace_task(struct task_struct *tsk, u64 now_ts)
{
	if (unlikely(session_start_ts == 0)) /* we are still starting */
		return false;

	/* check if we are outside of session [start, end] time range */
	if (unlikely((long)(now_ts - session_start_ts) < 0 ||
		     (long)(now_ts - session_end_ts) > 0 ))
		return false;

	enum wprof_filt_mode mode = filt_mode;
	if (likely(mode == 0))
		return true;

	/* DENY filtering */
	if (mode & FILT_DENY_IDLE) {
		if (tsk->pid == 0)
			return false;
	}
	if (mode & FILT_DENY_KTHREAD) {
		if (tsk->flags & PF_KTHREAD)
			return false;
	}
	if (mode & FILT_DENY_PID) {
		u32 pid = tsk->tgid;
		for (int i = 0; i < deny_pid_cnt; i++) {
			if (deny_pids[i] == pid)
				return false;
		}
	}
	if (mode & FILT_DENY_TID) {
		u32 tid = tsk->pid;
		for (int i = 0; i < deny_tid_cnt; i++) {
			if (deny_tids[i] == tid)
				return false;
		}
	}
	if (mode & FILT_DENY_PNAME) {
		struct comm_str pcomm;
		bpf_probe_read_kernel(pcomm.str, sizeof(pcomm.str), tsk->group_leader->comm);
		for (int i = 0; i < deny_pname_cnt; i++) {
			if (glob_match(deny_pnames[i].pat, sizeof(deny_pnames[i].pat),
				       pcomm.str, sizeof(pcomm.str)))
				return false;
		}
	}
	if (mode & FILT_DENY_TNAME) {
		struct comm_str comm;
		bpf_probe_read_kernel(comm.str, sizeof(comm.str), tsk->comm);
		for (int i = 0; i < deny_tname_cnt; i++) {
			if (glob_match(deny_tnames[i].pat, sizeof(deny_tnames[i].pat),
				       comm.str, sizeof(comm.str)))
				return false;
		}
	}

	/* ALLOW filtering */
	bool needs_match = false;
	if (mode & FILT_ALLOW_PID) {
		u32 pid = tsk->tgid;
		for (int i = 0; i < allow_pid_cnt; i++) {
			if (allow_pids[i] == pid)
				return true;
		}
		needs_match = true;
	}
	if (mode & FILT_ALLOW_TID) {
		u32 tid = tsk->pid;
		for (int i = 0; i < allow_tid_cnt; i++) {
			if (allow_tids[i] == tid)
				return true;
		}
		needs_match = true;
	}
	if (mode & FILT_ALLOW_PNAME) {
		struct comm_str pcomm;
		bpf_probe_read_kernel(pcomm.str, sizeof(pcomm.str), tsk->group_leader->comm);
		for (int i = 0; i < allow_pname_cnt; i++) {
			if (glob_match(allow_pnames[i].pat, sizeof(allow_pnames[i].pat),
				       pcomm.str, sizeof(pcomm.str)))
				return true;
		}
		needs_match = true;
	}
	if (mode & FILT_ALLOW_TNAME) {
		struct comm_str comm;
		bpf_probe_read_kernel(comm.str, sizeof(comm.str), tsk->comm);
		for (int i = 0; i < allow_tname_cnt; i++) {
			if (glob_match(allow_tnames[i].pat, sizeof(allow_tnames[i].pat),
				       comm.str, sizeof(comm.str)))
				return true;
		}
		needs_match = true;
	}
	if (mode & FILT_ALLOW_IDLE) {
		if (tsk->pid == 0)
			return true;
		needs_match = true;
	}
	if (mode & FILT_ALLOW_KTHREAD) {
		if (tsk->flags & PF_KTHREAD)
			return true;
		needs_match = true;
	}
	if (needs_match)
		return false;
	return true;
}

static void fill_task_name(struct task_struct *t, char *comm, int max_len)
{
	if (t->flags & PF_KTHREAD) {
		struct kthread *k = bpf_core_cast(t->worker_private, struct kthread);
		int err = -1;

		if (bpf_core_field_exists(struct kthread, full_name) && k->full_name)
			err = bpf_probe_read_kernel_str(comm, max_len, k->full_name);
		if (err)
			__builtin_memcpy(comm, t->comm, TASK_COMM_LEN);
	} else {
		__builtin_memcpy(comm, t->comm, TASK_COMM_LEN);
	}
}

static void fill_task_info(struct task_struct *t, struct wprof_task *info)
{
	info->tid = t->pid;
	if (info->tid == 0) /* idle thread */
		info->tid = -(bpf_get_smp_processor_id() + 1);
	info->pid = t->tgid;
	info->flags = t->flags;
	fill_task_name(t, info->comm, sizeof(info->comm));
	__builtin_memcpy(info->pcomm, t->group_leader->comm, sizeof(info->pcomm));
}

struct rb_ctx {
	void *rb;
	void *ev;
	struct bpf_dynptr dptr;
	u64 has_dptr;
};


static __always_inline void *pick_rescue_rb()
{
	u32 rb_slot;
	void *rb1, *rb2;

	rb_slot = bpf_get_prandom_u32() % rb_cnt;
	rb1 = bpf_map_lookup_elem(&rbs, &rb_slot);

	rb_slot = bpf_get_prandom_u32() % rb_cnt;
	rb2 = bpf_map_lookup_elem(&rbs, &rb_slot);

	if (!rb1 || !rb2) /* should never happen */
		return NULL;

	u64 rb1_used = bpf_ringbuf_query(rb1, BPF_RB_AVAIL_DATA);
	u64 rb2_used = bpf_ringbuf_query(rb2, BPF_RB_AVAIL_DATA);
	return rb1_used < rb2_used ? rb1 : rb2;
}

static __always_inline struct rb_ctx __rb_event_reserve(struct task_struct *p, u64 fix_sz, u64 dyn_sz,
							void **ev_out, struct bpf_dynptr **dptr)
{
	struct rb_ctx rb_ctx = {};
	void *rb;
	u32 cpu = bpf_get_smp_processor_id();
	u32 rb_slot = rb_cpu_map[cpu & rb_cpu_map_mask];

	rb = bpf_map_lookup_elem(&rbs, &rb_slot);
	if (!rb) {
		(void)inc_stat(rb_misses);
		return rb_ctx;
	}
	rb_ctx.rb = rb;
	rb_ctx.has_dptr = true;

	if (bpf_ringbuf_reserve_dynptr(rb, fix_sz + dyn_sz, 0, &rb_ctx.dptr)) {
		bpf_ringbuf_submit_dynptr(&rb_ctx.dptr, 0); /* no-op */

		/*
		 * If designated ringbuf is full, fallback to picking best (least full) out of two
		 * randomly picked ringbufs in a last ditch effort. This is meant to even out
		 * utilization of ringbufs if system event load is highly skewed to smaller subset
		 * of CPUs.
		 */
		rb_ctx.rb = rb = pick_rescue_rb();
		if (!rb) {
			(void)inc_stat(rb_misses);
			rb_ctx.has_dptr = false;
			return rb_ctx;
		}

		if (bpf_ringbuf_reserve_dynptr(rb, fix_sz + dyn_sz, 0, &rb_ctx.dptr)) {
			(void)inc_stat(rb_drops);
		} else {
			(void)inc_stat(rb_rescues);
			(void)inc_stat(rb_handled);
		}
	} else {
		(void)inc_stat(rb_handled);
	}

	*ev_out = rb_ctx.ev = bpf_dynptr_data(&rb_ctx.dptr, 0, fix_sz);
	if (dptr)
		*dptr = &rb_ctx.dptr;

	return rb_ctx;
}

static void __rb_event_submit(void *arg)
{
	struct rb_ctx *ctx = arg;

	if (!ctx->has_dptr)
		return;

	long queued_sz = bpf_ringbuf_query(ctx->rb, BPF_RB_AVAIL_DATA);
	long flags = queued_sz >= rb_submit_threshold_bytes ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;

	/* no-op, if ctx->rb is NULL */
	bpf_ringbuf_submit_dynptr(&ctx->dptr, flags);
}

static void capture_perf_counters(struct perf_counters *c, int cpu)
{
	struct bpf_perf_event_value perf_val;

	for (u64 i = 0; i < perf_ctr_cnt; i++) {
		int idx = cpu * perf_ctr_cnt + i, err;

		err = bpf_perf_event_read_value(&perf_cntrs, idx, &perf_val, sizeof(perf_val));
		if (err) {
			bpf_printk("Failed to read perf counter #%d for #%d: %d", err, i, cpu);
			c->val[i] = 0;
		} else {
			c->val[i] = perf_val.counter;
		}
	}
}

static void __capture_stack_trace(void *ctx, struct task_struct *task, struct stack_trace *st,
				  enum stack_trace_kind kind, bool user_only)
{
	u64 off = zero;

	if (!task)
		task = bpf_get_current_task_btf();

	st->stack_id = 0;
	st->kind = kind;
	st->pid = task->tgid;

	if (user_only) {
		st->kstack_sz = -ENOENT;
	} else {
		st->kstack_sz = bpf_get_task_stack(task, st->addrs, sizeof(st->addrs) / 2, 0);
		if (st->kstack_sz > 0)
			off += st->kstack_sz;
	}

	if (off > sizeof(st->addrs) / 2) /* impossible */
		off = sizeof(st->addrs) / 2;

	st->ustack_sz = bpf_get_task_stack(task, (void *)st->addrs + off, sizeof(st->addrs) / 2, BPF_F_USER_STACK);
}

static struct stack_trace *__grab_stack_trace(void *ctx, struct task_struct *task,
					      enum stack_trace_kind kind, bool user_only,
					      size_t *sz)
{
	struct stack_trace *st;

	st = bpf_map_lookup_elem(&stack_trace_scratch, &zero);
	if (!st)
		return *sz = 0, NULL; /* shouldn't happen */

	__capture_stack_trace(ctx, task, st, kind, user_only);
	*sz = (st->kstack_sz < 0 ? 0 : st->kstack_sz) +
	       (st->ustack_sz < 0 ? 0 : st->ustack_sz) +
	       offsetof(struct stack_trace, addrs);
	return st;
}

static __always_inline struct stack_trace *grab_stack_trace(void *ctx, struct task_struct *task,
							    enum stack_trace_kind kind, size_t *sz)
{
	return __grab_stack_trace(ctx, task, kind, false /*!user_only*/, sz);
}

static int emit_stack_trace(struct stack_trace *t, size_t sz, struct bpf_dynptr *dptr, size_t offset)
{
	if (sz == 0)
		return -ENODATA;
	barrier_var(sz);
	if (sz > sizeof(*t))
		return -E2BIG; /* shouldn't ever happen */
	return bpf_dynptr_write(dptr, offset, t, sz, 0);
}

static __always_inline bool init_wprof_event(struct wprof_event *e, u32 sz, enum event_kind kind, u64 ts, struct task_struct *p)
{
	e->sz = sz;
	e->flags = 0;
	e->kind = kind;
	e->ts = ts;
	e->cpu = bpf_get_smp_processor_id();
	e->numa_node = bpf_get_numa_node_id();
	fill_task_info(p, &e->task);
	return true; /* makes emit_task_event() macro a bit easier to write */
}

#define emit_task_event(e, fix_sz, dyn_sz, kind, ts, task)					\
	for (struct rb_ctx __cleanup(__rb_event_submit) __ctx =					\
			__rb_event_reserve(task, fix_sz, dyn_sz, (void **)&(e), NULL);		\
	     e && __ctx.ev && init_wprof_event(e, fix_sz /*+ dyn_sz*/, kind, ts, task);		\
	     __ctx.ev = NULL)

#define emit_task_event_dyn(e, dptr, fix_sz, dyn_sz, kind, ts, task)				\
	for (struct rb_ctx __cleanup(__rb_event_submit) __ctx =					\
			__rb_event_reserve(task, fix_sz, dyn_sz, (void **)&(e), &(dptr));	\
	     e && __ctx.ev && init_wprof_event(e, fix_sz /*+ dyn_sz*/, kind, ts, task);		\
	     __ctx.ev = NULL)

void emit_scx_dsq_event(u64 end_ts, struct task_struct *task, struct task_state *s)
{
	struct wprof_event *e;

	emit_task_event(e, EV_SZ(scx_dsq), 0, EV_SCX_DSQ_END, end_ts, task) {
		e->scx_dsq = s->scx_dsq;
	}
}

SEC("?perf_event")
int wprof_timer_tick(void *ctx)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct task_state *scur;
	struct task_struct *cur = bpf_get_current_task_btf();

	if (!should_trace_task(cur, now_ts))
		return false;

	scur = task_state(cur->pid);
	if (!scur)
		return 0; /* shouldn't happen, unless we ran out of space */


	struct wprof_event *e;
	struct bpf_dynptr *dptr;
	struct stack_trace *tr = NULL;
	size_t dyn_sz = 0;
	size_t fix_sz = EV_SZ(timer);

	if (requested_stack_traces & ST_TIMER)
		tr = grab_stack_trace(ctx, NULL, ST_TIMER, &dyn_sz);

	emit_task_event_dyn(e, dptr, fix_sz, dyn_sz, EV_TIMER, now_ts, cur) {
		if (tr) {
			emit_stack_trace(tr, dyn_sz, dptr, fix_sz);
			e->flags |= ST_TIMER;
		}
	}

	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(wprof_task_switch,
	     bool preempt,
	     struct task_struct *prev,
	     struct task_struct *next,
	     unsigned prev_state)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct task_state *sprev, *snext;
	struct wprof_event *e;
	u64 waking_ts;
	int cpu = bpf_get_smp_processor_id();
	struct perf_counters counters;

	if (!should_trace_task(prev, now_ts) && !should_trace_task(next, now_ts))
		return 0;

	sprev = task_state(prev->pid);
	snext = task_state(next->pid);
	if (!sprev || !snext)
		return 0;

	waking_ts = snext->waking_ts;

	if (perf_ctr_cnt)
		capture_perf_counters(&counters, cpu);

	/* prev task was on-cpu since last checkpoint */
	sprev->waking_ts = 0;

	/* if process was involuntarily preempted, mark this as a start of
	 * scheduling delay
	 */
	if (prev->__state == TASK_RUNNING && prev->pid) {
		sprev->waking_ts = now_ts;
		sprev->waking_flags = WF_PREEMPTED;
		sprev->waker_cpu = cpu;
		sprev->waker_numa_node = bpf_get_numa_node_id();
		fill_task_info(next, &sprev->waker_task);
	}
	sprev->last_task_state = prev->__state;

	/* next task was off-cpu since last checkpoint */
	snext->waking_ts = 0;

	struct bpf_dynptr *dptr;
	struct stack_trace *tr_out = NULL;
	size_t tr_out_sz = 0;
	size_t fix_sz = EV_SZ(swtch);

	if (requested_stack_traces & ST_OFFCPU)
		tr_out = grab_stack_trace(ctx, NULL, ST_OFFCPU, &tr_out_sz);

	int scx_layer_id = -1;
	u64 scx_dsq_id = 0;
	if (capture_scx_layer_id) {
		scx_layer_id = snext->scx_dsq.scx_layer_id;
		scx_dsq_id = snext->scx_dsq.scx_dsq_id;
		handle_dsq(now_ts, next, snext);
	}

	emit_task_event_dyn(e, dptr, fix_sz, tr_out_sz, EV_SWITCH, now_ts, prev) {
		e->swtch.ctrs = counters;
		e->swtch.prev_task_state = prev->__state;
		e->swtch.last_next_task_state = snext->last_task_state;
		e->swtch.prev_prio = prev->prio;
		e->swtch.next_prio = next->prio;
		fill_task_info(next, &e->swtch.next);

		e->swtch.waking_ts = waking_ts;
		if (waking_ts) {
			e->swtch.waking_flags = snext->waking_flags;
			e->swtch.waker_cpu = snext->waker_cpu;
			e->swtch.waker_numa_node = snext->waker_numa_node;
			bpf_probe_read_kernel(&e->swtch.waker, sizeof(snext->waker_task), &snext->waker_task);
		}

		e->flags = 0;
		if (tr_out) {
			emit_stack_trace(tr_out, tr_out_sz, dptr, fix_sz);
			e->flags |= ST_OFFCPU;
		}

		e->swtch.next_task_scx_layer_id = scx_layer_id;
		e->swtch.next_task_scx_dsq_id = scx_dsq_id;
	}

	return 0;
}

SEC("tp_btf/sched_waking")
int BPF_PROG(wprof_task_waking, struct task_struct *p)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct task_state *s;
	struct task_struct *task;

	if (!should_trace_task(p, now_ts))
		return 0;

	s = task_state(p->pid);
	if (!s)
		return 0;

	if (s->waking_ts != 0)
		return 0; /* there was an earlier wakeup */

	s->waking_ts = now_ts;
	s->waking_flags = WF_WOKEN;
	s->waker_cpu = bpf_get_smp_processor_id();
	s->waker_numa_node = bpf_get_numa_node_id();
	s->last_task_state = p->__state;
	task = bpf_get_current_task_btf();
	fill_task_info(task, &s->waker_task);

	if (!(requested_stack_traces & ST_WAKER))
		goto skip_emit;

	struct wprof_event *e;
	struct bpf_dynptr *dptr;
	struct stack_trace *tr = NULL;
	size_t dyn_sz = 0;
	size_t fix_sz = EV_SZ(waking);

	tr = grab_stack_trace(ctx, NULL, ST_WAKER, &dyn_sz);
	if (!tr)
		goto skip_emit;

	emit_task_event_dyn(e, dptr, fix_sz, dyn_sz, EV_WAKING, now_ts, task) {
		fill_task_info(p, &e->waking.wakee);
		emit_stack_trace(tr, dyn_sz, dptr, fix_sz);
		e->flags |= ST_WAKER;
	}

skip_emit:
	return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(wprof_task_wakeup_new, struct task_struct *p)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct task_struct *task;
	struct task_state *s;

	if (!should_trace_task(p, now_ts))
		return 0;

	s = task_state(p->pid);
	if (!s)
		return 0;

	if (s->waking_ts != 0)
		goto skip_emit;

	s->waking_ts = now_ts;
	s->waking_flags = WF_WOKEN_NEW;
	s->waker_cpu = bpf_get_smp_processor_id();
	s->waker_numa_node = bpf_get_numa_node_id();
	s->last_task_state = p->__state;
	task = bpf_get_current_task_btf();
	fill_task_info(task, &s->waker_task);

	if (!(requested_stack_traces & ST_WAKER))
		goto skip_emit;

	struct wprof_event *e;
	struct bpf_dynptr *dptr;
	struct stack_trace *tr = NULL;
	size_t dyn_sz = 0;
	size_t fix_sz = EV_SZ(wakeup_new);

	tr = grab_stack_trace(ctx, NULL, ST_WAKER, &dyn_sz);
	if (!tr)
		goto skip_emit;

	emit_task_event_dyn(e, dptr, fix_sz, dyn_sz, EV_WAKEUP_NEW, now_ts, task) {
		fill_task_info(p, &e->wakeup_new.wakee);
		emit_stack_trace(tr, dyn_sz, dptr, fix_sz);
		e->flags |= ST_WAKER;
	}

skip_emit:
	return 0;
}

/*
SEC("?tp_btf/sched_wakeup")
int BPF_PROG(wprof_task_wakeup, struct task_struct *p)
{
	struct wprof_event *e;
	u64 now_ts = bpf_ktime_get_ns();

	if (!should_trace_task(p, now_ts))
		return 0;

	emit_task_event(e, EV_SZ(task), 0, EV_WAKEUP, now_ts, p);

	return 0;
}
*/

SEC("tp_btf/task_rename")
int BPF_PROG(wprof_task_rename, struct task_struct *task, const char *comm)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct wprof_event *e;

	if (!should_trace_task(task, now_ts))
		return 0;

	if (task->flags & (PF_KTHREAD | PF_WQ_WORKER))
		return 0;

	emit_task_event(e, EV_SZ(rename), 0, EV_TASK_RENAME, now_ts, task) {
		bpf_probe_read_kernel_str(e->rename.new_comm, sizeof(e->rename.new_comm), comm);
	}

	return 0;
}


SEC("tp_btf/sched_process_fork")
int BPF_PROG(wprof_task_fork, struct task_struct *parent, struct task_struct *child)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct wprof_event *e;

	if (!should_trace_task(parent, now_ts) && !should_trace_task(child, now_ts))
		return 0;

	emit_task_event(e, EV_SZ(fork), 0, EV_FORK, now_ts, parent) {
		fill_task_info(child, &e->fork.child);
	}

	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(wprof_task_exec, struct task_struct *p, int old_pid, struct linux_binprm *bprm)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct wprof_event *e;

	if (!should_trace_task(p, now_ts))
		return 0;

	emit_task_event(e, EV_SZ(exec), 0, EV_EXEC, now_ts, p) {
		e->exec.old_tid = old_pid;
		bpf_probe_read_kernel_str(e->exec.filename, sizeof(e->exec.filename), bprm->filename);
	}

	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(wprof_task_exit, struct task_struct *p)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct task_state *s;

	if (!should_trace_task(p, now_ts))
		return 0;

	s = task_state_peek(p->pid);
	if (!s)
		return 0;

	struct wprof_event *e;
	emit_task_event(e, EV_SZ(task), 0, EV_TASK_EXIT, now_ts, p);

	task_state_delete(p->pid);

	return 0;
}

SEC("tp_btf/sched_process_free")
int BPF_PROG(wprof_task_free, struct task_struct *p)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct wprof_event *e;

	if (!should_trace_task(p, now_ts))
		return 0;

	emit_task_event(e, EV_SZ(task), 0, EV_TASK_FREE, now_ts, p);

	return 0;
}

static int handle_hardirq(u64 now_ts, struct task_struct *task,
			  struct irqaction *action, int irq, bool start)
{
	struct task_state *s;
	struct wprof_event *e;
	int cpu;

	s = task_state(task->pid);
	if (!s)
		return 0;

	cpu = bpf_get_smp_processor_id();
	if (start) {
		s->hardirq_ts = now_ts;
		if (perf_ctr_cnt)
			capture_perf_counters(&s->hardirq_ctrs, cpu);
		return 0;
	}

	if (s->hardirq_ts == 0) /* we never recorded matching start, ignore */
		return 0;

	emit_task_event(e, EV_SZ(hardirq), 0, EV_HARDIRQ_EXIT, now_ts, task) {
		e->hardirq.hardirq_ts = s->hardirq_ts;
		e->hardirq.irq = irq;
		bpf_probe_read_kernel_str(&e->hardirq.name, sizeof(e->hardirq.name), action->name);

		if (perf_ctr_cnt) {
			struct perf_counters ctrs;

			capture_perf_counters(&ctrs, cpu);
			for (u64 i = 0; i < perf_ctr_cnt; i++)
				e->hardirq.ctrs.val[i] = ctrs.val[i] - s->hardirq_ctrs.val[i];
		}
	}

	s->hardirq_ts = 0;

	return 0;
}

SEC("tp_btf/irq_handler_entry")
int BPF_PROG(wprof_hardirq_entry, int irq, struct irqaction *action)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct task_struct *task = bpf_get_current_task_btf();

	if (!should_trace_task(task, now_ts))
		return 0;

	return handle_hardirq(now_ts, task, action, irq, true /*start*/);
}

SEC("tp_btf/irq_handler_exit")
int BPF_PROG(wprof_hardirq_exit, int irq, struct irqaction *action, int ret)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct task_struct *task = bpf_get_current_task_btf();

	if (!should_trace_task(task, now_ts))
		return 0;

	return handle_hardirq(now_ts, task, action, irq, false /*!start*/);
}

static int handle_softirq(u64 now_ts, struct task_struct *task, int vec_nr, bool start)
{
	struct task_state *s;
	struct wprof_event *e;
	int cpu;

	s = task_state(task->pid);
	if (!s)
		return 0;

	cpu = bpf_get_smp_processor_id();
	if (start) {
		s->softirq_ts = now_ts;
		if (perf_ctr_cnt)
			capture_perf_counters(&s->softirq_ctrs, cpu);
		return 0;
	}

	if (s->softirq_ts == 0) /* we never recorded matching start, ignore */
		return 0;

	emit_task_event(e, EV_SZ(softirq), 0, EV_SOFTIRQ_EXIT, now_ts, task) {
		e->softirq.softirq_ts = s->softirq_ts;
		e->softirq.vec_nr = vec_nr;

		if (perf_ctr_cnt) {
			struct perf_counters ctrs;

			capture_perf_counters(&ctrs, cpu);
			for (u64 i = 0; i < perf_ctr_cnt; i++)
				e->softirq.ctrs.val[i] = ctrs.val[i] - s->softirq_ctrs.val[i];
		}
	}

	s->softirq_ts = 0;

	return 0;
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(wprof_softirq_entry, int vec_nr)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct task_struct *task = bpf_get_current_task_btf();

	if (!should_trace_task(task, now_ts))
		return 0;

	return handle_softirq(now_ts, task, vec_nr, true /*start*/);
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(wprof_softirq_exit, int vec_nr)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct task_struct *task = bpf_get_current_task_btf();

	if (!should_trace_task(task, now_ts))
		return 0;

	return handle_softirq(now_ts, task, vec_nr, false /*!start*/);
}

static __always_inline bool is_valid_wq_char(char c)
{
	switch (c) {
	case '_': case '-': case '[': case ']': case '\\': case '/': case '=':
	case '.': case ',': case ';': case ':':
	case '0' ... '9':
	case 'a' ... 'z':
	case 'A' ... 'Z':
		return true;
	default:
		return false;
	}
}

static int handle_workqueue(u64 now_ts, struct task_struct *task, struct work_struct *work, bool start)
{
	struct task_state *s;
	struct wprof_event *e;
	int cpu, err;

	s = task_state(task->pid);
	if (!s)
		return 0;

	cpu = bpf_get_smp_processor_id();
	if (start) {
		struct kthread *k = bpf_core_cast(task->worker_private, struct kthread);
		struct worker *worker = bpf_core_cast(k->data, struct worker);

		s->wq_ts = now_ts;

		err = bpf_probe_read_kernel_str(s->wq_name, sizeof(s->wq_name), worker->desc);
		if (err < 0 || !is_valid_wq_char(s->wq_name[0])) {
			s->wq_name[0] = '?';
			s->wq_name[1] = '?';
			s->wq_name[2] = '?';
			s->wq_name[3] = '\0';
		}

		if (perf_ctr_cnt)
			capture_perf_counters(&s->wq_ctrs, cpu);
		return 0;
	}

	if (s->wq_ts == 0) /* we never recorded matching start, ignore */
		return 0;

	emit_task_event(e, EV_SZ(wq), 0, EV_WQ_END, now_ts, task) {
		e->wq.wq_ts = s->wq_ts;
		__builtin_memcpy(e->wq.desc, s->wq_name, sizeof(e->wq.desc));

		if (perf_ctr_cnt) {
			struct perf_counters ctrs;

			capture_perf_counters(&ctrs, cpu);
			for (u64 i = 0; i < perf_ctr_cnt; i++)
				e->wq.ctrs.val[i] = ctrs.val[i] - s->wq_ctrs.val[i];
		}
	}

	s->wq_ts = 0;

	return 0;
}

SEC("tp_btf/workqueue_execute_start")
int BPF_PROG(wprof_wq_exec_start, struct work_struct *work)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct task_struct *task = bpf_get_current_task_btf();

	if (!should_trace_task(task, now_ts))
		return 0;

	return handle_workqueue(now_ts, task, work, true /*start*/);
}

SEC("tp_btf/workqueue_execute_end")
int BPF_PROG(wprof_wq_exec_end, struct work_struct *work /* , work_func_t function */)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct task_struct *task = bpf_get_current_task_btf();

	if (!should_trace_task(task, now_ts))
		return 0;

	return handle_workqueue(now_ts, task, work, false /*!start*/);
}

#ifdef __TARGET_ARCH_x86

static struct cpu_state all_cpus_state;

static int handle_ipi_send(u64 now_ts, struct task_struct *task,
			   enum wprof_ipi_kind ipi_kind, int target_cpu)
{
	struct cpu_state *s;
	struct wprof_event *e;
	int cpu;

	if (target_cpu >= 0) {
		s = bpf_map_lookup_percpu_elem(&cpu_states, &zero, target_cpu);
		if (!s) /* shouldn't happen */
			return 0;
	} else {
		s = &all_cpus_state;
	}

	cpu = bpf_get_smp_processor_id();

	s->ipi_send_ts = now_ts;
	s->ipi_send_cpu = cpu;
	s->ipi_counter += 1;

	emit_task_event(e, EV_SZ(ipi_send), 0, EV_IPI_SEND, now_ts, task) {
		e->ipi_send.kind = ipi_kind;
		e->ipi_send.target_cpu = target_cpu;
		e->ipi_send.ipi_id = s->ipi_counter | ((u64)target_cpu << 48);
	}

	return 0;
}

SEC("?tp_btf/ipi_send_cpu")
int BPF_PROG(wprof_ipi_send_cpu, int cpu)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct task_struct *task = bpf_get_current_task_btf();

	if (!should_trace_task(task, now_ts))
		return 0;

	return handle_ipi_send(now_ts, task, IPI_SINGLE, cpu);
}

SEC("?tp_btf/ipi_send_cpumask")
int BPF_PROG(wprof_ipi_send_mask, struct cpumask *mask)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct task_struct *task = bpf_get_current_task_btf();

	if (!should_trace_task(task, now_ts))
		return 0;

	return handle_ipi_send(now_ts, task, IPI_MULTI, -1);
}

#define RESCHEDULE_VECTOR		0xfd
#define CALL_FUNCTION_VECTOR		0xfc
#define CALL_FUNCTION_SINGLE_VECTOR	0xfb

static int handle_ipi(u64 now_ts, struct task_struct *task, enum wprof_ipi_kind ipi_kind, bool start)
{
	struct cpu_state *s;
	struct wprof_event *e;
	int cpu;

	s = bpf_map_lookup_elem(&cpu_states, &zero);
	if (!s) /* can't happen */
		return 0;

	cpu = bpf_get_smp_processor_id();
	if (start) {
		s->ipi_ts = now_ts;
		if (perf_ctr_cnt)
			capture_perf_counters(&s->ipi_ctrs, cpu);
		return 0;
	}

	if (s->ipi_ts == 0) /* we never recorded matching start, ignore */
		return 0;

	emit_task_event(e, EV_SZ(ipi), 0, EV_IPI_EXIT, now_ts, task) {
		e->ipi.kind = ipi_kind;
		e->ipi.ipi_ts = s->ipi_ts;

		if (ipi_kind == IPI_SINGLE && s->ipi_send_ts > 0) {
			e->ipi.send_ts = s->ipi_send_ts;
			e->ipi.send_cpu = s->ipi_send_cpu;
			e->ipi.ipi_id = s->ipi_counter | ((u64)cpu << 48);
		} else if (ipi_kind == IPI_MULTI && all_cpus_state.ipi_send_ts > 0) {
			e->ipi.send_ts = all_cpus_state.ipi_send_ts;
			e->ipi.send_cpu = all_cpus_state.ipi_send_cpu;
			e->ipi.ipi_id = 0;
		} else {
			e->ipi.send_ts = 0;
			e->ipi.send_cpu = -1;
			e->ipi.ipi_id = 0;
		}

		if (perf_ctr_cnt) {
			struct perf_counters ctrs;

			capture_perf_counters(&ctrs, cpu);
			for (u64 i = 0; i < perf_ctr_cnt; i++)
				e->ipi.ctrs.val[i] = ctrs.val[i] - s->ipi_ctrs.val[i];
		}
	}

	s->ipi_ts = 0;

	return 0;
}

SEC("?tp_btf/call_function_entry")
int BPF_PROG(wprof_ipi_multi_entry, int vector)
{
	u64 now_ts;
	struct task_struct *task;

	if (vector != CALL_FUNCTION_VECTOR)
		return 0;

	now_ts = bpf_ktime_get_ns();
	task = bpf_get_current_task_btf();
	if (!should_trace_task(task, now_ts))
		return 0;

	return handle_ipi(now_ts, task, IPI_MULTI, true /*start*/);
}

SEC("?tp_btf/call_function_exit")
int BPF_PROG(wprof_ipi_multi_exit, int vector)
{
	u64 now_ts;
	struct task_struct *task;

	if (vector != CALL_FUNCTION_VECTOR)
		return 0;

	now_ts = bpf_ktime_get_ns();
	task = bpf_get_current_task_btf();
	if (!should_trace_task(task, now_ts))
		return 0;

	return handle_ipi(now_ts, task, IPI_MULTI, false /*!start*/);
}

SEC("?tp_btf/call_function_single_entry")
int BPF_PROG(wprof_ipi_single_entry, int vector)
{
	u64 now_ts;
	struct task_struct *task;

	if (vector != CALL_FUNCTION_SINGLE_VECTOR)
		return 0;

	now_ts = bpf_ktime_get_ns();
	task = bpf_get_current_task_btf();
	if (!should_trace_task(task, now_ts))
		return 0;

	return handle_ipi(now_ts, task, IPI_SINGLE, true /*start*/);
}

SEC("?tp_btf/call_function_single_exit")
int BPF_PROG(wprof_ipi_single_exit, int vector)
{
	u64 now_ts;
	struct task_struct *task;

	if (vector != CALL_FUNCTION_SINGLE_VECTOR)
		return 0;

	now_ts = bpf_ktime_get_ns();
	task = bpf_get_current_task_btf();
	if (!should_trace_task(task, now_ts))
		return 0;

	return handle_ipi(now_ts, task, IPI_SINGLE, false /*!start*/);
}

SEC("?tp_btf/reschedule_entry")
int BPF_PROG(wprof_ipi_resched_entry, int vector)
{
	u64 now_ts;
	struct task_struct *task;

	if (vector != RESCHEDULE_VECTOR)
		return 0;

	now_ts = bpf_ktime_get_ns();
	task = bpf_get_current_task_btf();
	if (!should_trace_task(task, now_ts))
		return 0;

	return handle_ipi(now_ts, task, IPI_RESCHED, true /*start*/);
}

SEC("?tp_btf/reschedule_exit")
int BPF_PROG(wprof_ipi_resched_exit, int vector)
{
	u64 now_ts;
	struct task_struct *task;

	if (vector != RESCHEDULE_VECTOR)
		return 0;

	now_ts = bpf_ktime_get_ns();
	task = bpf_get_current_task_btf();
	if (!should_trace_task(task, now_ts))
		return 0;

	return handle_ipi(now_ts, task, IPI_RESCHED, false /*!start*/);
}

#endif /* __TARGET_ARCH_x86 */

struct req_state {
	u64 start_ts;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); /* req_id */
	__type(value, struct req_state);
} req_states SEC(".maps");

static struct req_state empty_req_state;

/* attached to thrift:crochet_request_data_context USDT */
SEC("?usdt")
int BPF_USDT(wprof_req_ctx, u64 req_id, const char *endpoint, enum wprof_req_event_kind event_kind)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct task_struct *task = bpf_get_current_task_btf();
	struct req_state *s;

	if (!should_trace_task(task, now_ts))
		return 0;

	switch (event_kind) {
	case REQ_BEGIN:
		s = bpf_map_lookup_elem(&req_states, &req_id);
		if (!s) {
			bpf_map_update_elem(&req_states, &req_id, &empty_req_state, BPF_NOEXIST);
			s = bpf_map_lookup_elem(&req_states, &req_id);
		}
		if (!s) {
			(void)inc_stat(req_state_drops);
			return 0;
		}
		s->start_ts = now_ts;
		break;
	case REQ_END:
	case REQ_SET:
	case REQ_UNSET:
		s = bpf_map_lookup_elem(&req_states, &req_id);
		if (!s) /* caught request in mid-flight or out of req_states space */
			return 0;
		break;
	case REQ_CLEAR: /* don't care */
	default:
		return 0;
	}

	struct wprof_event *e;
	emit_task_event(e, EV_SZ(req), 0, EV_REQ_EVENT, now_ts, task) {
		e->req.req_id = req_id;
		e->req.req_ts = s->start_ts;
		e->req.req_event = event_kind;
		if (bpf_probe_read_user(&e->req.req_name, sizeof(e->req.req_name), endpoint))
			e->req.req_name[0] = '\0';
	}

	if (event_kind == REQ_END)
		bpf_map_delete_elem(&req_states, &req_id);

	return 0;
}

/* folly:thread_pool_executor_task_enqueued USDT handler */
SEC("?usdt")
int BPF_USDT(wprof_req_task_enqueue,
	     const char *thread_factory_pfx, u64 req_id, u64 enqueue_ts,
	     u64 task_id)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct task_struct *task = bpf_get_current_task_btf();

	if (!should_trace_task(task, now_ts))
		return 0;

	struct wprof_event *e;
	emit_task_event(e, EV_SZ(req_task), 0, EV_REQ_TASK_EVENT, now_ts, task) {
		e->req_task.req_task_event = REQ_TASK_ENQUEUE;
		e->req_task.req_id = req_id;
		e->req_task.task_id = task_id;
		e->req_task.enqueue_ts = enqueue_ts;
		e->req_task.wait_time_ns = 0;
		e->req_task.run_time_ns = 0;
	}

	return 0;
}

/* folly:thread_pool_executor_task_dequeued USDT handler */
SEC("?usdt")
int BPF_USDT(wprof_req_task_dequeue,
	     const char *thread_factory_pfx, u64 req_id, u64 enqueue_ts,
	     u64 wait_time_ns, u64 task_id)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct task_struct *task = bpf_get_current_task_btf();

	if (!should_trace_task(task, now_ts))
		return 0;

	struct wprof_event *e;
	emit_task_event(e, EV_SZ(req_task), 0, EV_REQ_TASK_EVENT, now_ts, task) {
		e->req_task.req_task_event = REQ_TASK_DEQUEUE;
		e->req_task.req_id = req_id;
		e->req_task.task_id = task_id;
		e->req_task.enqueue_ts = enqueue_ts;
		e->req_task.wait_time_ns = wait_time_ns;
		e->req_task.run_time_ns = 0;
	}

	return 0;
}

/* folly:thread_pool_executor_task_stats USDT handler */
SEC("?usdt")
int BPF_USDT(wprof_req_task_stats,
	     const char *thread_factory_pfx, u64 req_id, u64 enqueue_ts,
	     u64 wait_time_ns, u64 run_time_ns, u64 task_id)
{
	u64 now_ts = bpf_ktime_get_ns();
	struct task_struct *task = bpf_get_current_task_btf();

	if (!should_trace_task(task, now_ts))
		return 0;

	struct wprof_event *e;
	emit_task_event(e, EV_SZ(req_task), 0, EV_REQ_TASK_EVENT, now_ts, task) {
		e->req_task.req_task_event = REQ_TASK_STATS;
		e->req_task.req_id = req_id;
		e->req_task.task_id = task_id;
		e->req_task.enqueue_ts = enqueue_ts;
		e->req_task.wait_time_ns = wait_time_ns;
		e->req_task.run_time_ns = run_time_ns;
	}

	return 0;
}
