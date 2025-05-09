// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include "utils.h"
#include "protobuf.h"
#include "wprof.h"
#include "env.h"
#include "stacktrace.h"

struct task_state {
	int tid, pid;
	pb_iid name_iid;
	pb_iid rename_iid;
	char comm[TASK_COMM_FULL_LEN];
	/* task renames */
	u64 rename_ts;
	char old_comm[TASK_COMM_FULL_LEN];
	/* perf counters */
	u64 oncpu_ts;
	struct perf_counters oncpu_ctrs;
};

static struct hashmap *tasks;
static __thread struct emit_state em;
static __thread pb_ostream_t *cur_stream;

int init_emit(struct worker_state *w)
{
	tasks = hashmap__new(hash_identity_fn, hash_equal_fn, NULL);
	if (!tasks)
		return -ENOMEM;

	cur_stream = &w->stream;

	return 0;
}

/*
 * HIGH-LEVEL TRACE RECORD EMITTING INTERFACES
 */
struct emit_state {
	TracePacket pb;
	struct pb_anns anns;
};

__unused
static void emit_kv_str(pb_iid key_iid, const char *key, pb_iid value_iid, const char *value)
{
	anns_add_str(&em.anns, key_iid, key, value_iid, value);
}

__unused
__attribute__((format(printf, 3, 4)))
static void emit_kv_fmt(pb_iid key_iid, const char *key, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	anns_add_str(&em.anns, key_iid, key, IID_NONE, vsfmt(fmt, ap));

	va_end(ap);
}

__unused
static void emit_kv_int(pb_iid key_iid, const char *key, int64_t value)
{
	anns_add_int(&em.anns, key_iid, key, value);
}

__unused
static void emit_kv_float(pb_iid key_iid, const char *key, const char *fmt, double value)
{
	anns_add_double(&em.anns, key_iid, key, value);
}

__unused
static void emit_flow_id(u64 flow_id)
{
	em.pb.data.track_event.flow_ids = PB_FLOW_ID(flow_id);
}

__unused
static void emit_flow_id_end(u64 flow_id)
{
	em.pb.data.track_event.terminating_flow_ids = PB_FLOW_ID(flow_id);
}

struct emit_rec { bool done; };

static void emit_cleanup(struct emit_rec *r)
{
	enc_trace_packet(cur_stream, &em.pb);
}

enum task_kind {
	TASK_NORMAL,
	TASK_IDLE,
	TASK_KWORKER,
	TASK_KTHREAD,
};

#define TRACK_UUID_IDLE		2000000000ULL
#define TRACK_UUID_KWORKER	2000000001ULL
#define TRACK_UUID_KTHREAD	2000000002ULL

#define TRACK_RANK_IDLE		-3
#define TRACK_RANK_KWORKER	-2
#define TRACK_RANK_KTHREAD	-1

static enum task_kind task_kind(const struct wprof_task *t)
{
	if (t->pid == 0)
		return TASK_IDLE;
	else if (t->flags & PF_WQ_WORKER)
		return TASK_KWORKER;
	else if (t->flags & PF_KTHREAD)
		return TASK_KTHREAD;
	else
		return TASK_NORMAL;
}

static int task_tid(const struct wprof_task *t)
{
	return t->pid ? t->tid : 0;
}

static int track_tid(const struct wprof_task *t)
{
	return t->pid ? t->tid : (-t->tid - 1);
}

static int track_pid(const struct wprof_task *t)
{
	enum task_kind kind = task_kind(t);

	switch (kind) {
	case TASK_NORMAL:
		return t->pid;
	case TASK_IDLE:
		return TRACK_UUID_IDLE;
	case TASK_KWORKER:
		return TRACK_UUID_KWORKER;
	case TASK_KTHREAD:
		return TRACK_UUID_KTHREAD;
	default:
		fprintf(stderr, "BUG: unexpected task kind in track_pid(): %d\n", kind);
		exit(1);
	}
}

static int track_thread_rank(const struct wprof_task *t)
{
	return task_tid(t);
}

static int track_process_rank(const struct wprof_task *t)
{
	enum task_kind kind = task_kind(t);

	switch (kind) {
	case TASK_NORMAL:
		return t->pid + 1000000000ULL;
	case TASK_IDLE:
		return TRACK_RANK_IDLE;
	case TASK_KWORKER:
		return TRACK_RANK_KWORKER;
	case TASK_KTHREAD:
		return TRACK_RANK_KTHREAD;
	default:
		fprintf(stderr, "BUG: unexpected task kind in track_process_rank(): %d\n", kind);
		exit(1);
	}
}

__unused
static int trace_sort_idx(const struct wprof_task *t)
{
	if (t->pid == 0)
		return -1; /* IDLE */
	else if (t->flags & PF_WQ_WORKER)
		return -2;
	else if (t->flags & PF_KTHREAD)
		return -3;
	else
		return 0;
}

#define TRACK_NAME_IDLE "IDLE"
#define TRACK_NAME_KWORKER "KWORKER"
#define TRACK_NAME_KTHREAD "KTHREAD"

static const char *track_pcomm(const struct wprof_task *t)
{
	enum task_kind kind = task_kind(t);

	switch (kind) {
	case TASK_NORMAL:
		return t->pcomm;
	case TASK_IDLE:
		return TRACK_NAME_IDLE;
	case TASK_KWORKER:
		return TRACK_NAME_KWORKER;
	case TASK_KTHREAD:
		return TRACK_NAME_KTHREAD;
	default:
		fprintf(stderr, "BUG: unexpected task kind in track_pcomm(): %d\n", kind);
		exit(1);
	}
}

__unused
static const u64 kind_track_uuid(enum task_kind kind)
{
	switch (kind) {
	case TASK_IDLE:
		return TRACK_UUID_IDLE;
	case TASK_KWORKER:
		return TRACK_UUID_KWORKER;
	case TASK_KTHREAD:
		return TRACK_UUID_KTHREAD;
	default:
		fprintf(stderr, "BUG: unexpected task kind in kind_track_uuid(): %d\n", kind);
		exit(1);
	}
}

__unused
static const char *kind_track_name(enum task_kind kind)
{
	switch (kind) {
	case TASK_IDLE:
		return TRACK_NAME_IDLE;
	case TASK_KWORKER:
		return TRACK_NAME_KWORKER;
	case TASK_KTHREAD:
		return TRACK_NAME_KTHREAD;
	default:
		fprintf(stderr, "BUG: unexpected task kind in kind_track_name(): %d\n", kind);
		exit(1);
	}
}

__unused
static const int kind_track_rank(enum task_kind kind)
{
	switch (kind) {
	case TASK_IDLE:
		return TRACK_RANK_IDLE;
	case TASK_KWORKER:
		return TRACK_RANK_KWORKER;
	case TASK_KTHREAD:
		return TRACK_RANK_KTHREAD;
	default:
		fprintf(stderr, "BUG: unexpected task kind in kind_track_rank(): %d\n", kind);
		exit(1);
	}
}

static uint64_t task_track_uuid(const struct wprof_task *t)
{
	return track_pid(t) * 1000000000ULL + track_tid(t);
}

static uint64_t process_track_uuid(const struct wprof_task *t)
{
	enum task_kind k = task_kind(t);

	if (k == TASK_NORMAL)
		return track_pid(t) * 1000000000ULL;
	return kind_track_uuid(k);
}

static const char *event_kind_str_map[] = {
	[EV_TIMER] = "TIMER",
	[EV_SWITCH_FROM] = "SWITCH_FROM",
	[EV_SWITCH_TO] = "SWITCH_TO",
	[EV_WAKEUP_NEW] = "WAKEUP_NEW",
	[EV_WAKEUP] = "WAKEUP",
	[EV_WAKING] = "WAKING",
	[EV_HARDIRQ_EXIT] = "HARDIRQ_EXIT",
	[EV_SOFTIRQ_EXIT] = "SOFTIRQ_EXIT",
	[EV_WQ_END] = "WQ_END",
	[EV_FORK] = "FORK",
	[EV_EXEC] = "EXEC",
	[EV_TASK_RENAME] = "TASK_RENAME",
	[EV_TASK_EXIT] = "TASK_EXIT",
	[EV_TASK_FREE] = "TASK_FREE",
};

static const char *event_kind_str(enum event_kind kind)
{
	if (kind >= 0 && kind < ARRAY_SIZE(event_kind_str_map))
		return event_kind_str_map[kind] ?: "UNKNOWN";
	return "UNKNOWN";
}

static const char *waking_reason_str(enum waking_flags flags)
{
	switch (flags) {
		case WF_UNKNOWN: return "unknown";
		case WF_WOKEN: return "woken";
		case WF_WOKEN_NEW: return "woken_new";
		case WF_PREEMPTED: return "preempted";
		default: return "???";
	}
}

enum instant_scope {
	SCOPE_THREAD,
	SCOPE_PROCESS,
	SCOPE_GLOBAL,
};

__unused
static const char *scope_str_map[] = {
	[SCOPE_THREAD] = "t",
	[SCOPE_PROCESS] = "p",
	[SCOPE_GLOBAL] = "g",
};

__unused
static const char *scope_str(enum instant_scope scope)
{
	return scope_str_map[scope];
}

__unused
static struct emit_rec emit_instant_pre(u64 ts, const struct wprof_task *t,
					pb_iid name_iid, const char *name)
{
	em.pb = (TracePacket) {
		PB_INIT(timestamp) = ts - env.sess_start_ts,
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_track_event) = { .track_event = {
			PB_INIT(track_uuid) = task_track_uuid(t),
			PB_INIT(type) = perfetto_protos_TrackEvent_Type_TYPE_INSTANT,
			PB_NAME(TrackEvent, name_field, name_iid, name),
			.debug_annotations = PB_ANNOTATIONS(&em.anns),
		}},
	};
	anns_reset(&em.anns);

	/* ... could have args emitted afterwards */
	return (struct emit_rec){};
}

#define emit_instant(ts, t, name_iid, name)							\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_instant_pre(ts, t, name_iid, name);						\
	     !___r.done; ___r.done = true)

__unused
static struct emit_rec emit_slice_point_pre(u64 ts, const struct wprof_task *t,
					    pb_iid name_iid, const char *name,
					    pb_iid cat_iid, const char *category,
					    bool start)
{
	em.pb = (TracePacket) {
		PB_INIT(timestamp) = ts - env.sess_start_ts,
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_track_event) = { .track_event = {
			PB_INIT(track_uuid) = task_track_uuid(t),
			PB_INIT(type) = start ? perfetto_protos_TrackEvent_Type_TYPE_SLICE_BEGIN
					      : perfetto_protos_TrackEvent_Type_TYPE_SLICE_END,
			.category_iids = cat_iid ? PB_STRING_IID(cat_iid) : PB_NONE,
			.categories = cat_iid ? PB_NONE : PB_STRING(category),
			PB_NAME(TrackEvent, name_field, name_iid, name),
			.debug_annotations = PB_ANNOTATIONS(&em.anns),
		}},
	};
	/* allow explicitly not providing the name */
	if (!name_iid && !name)
		em.pb.data.track_event.which_name_field = 0;
	/* end slice points don't need to repeat the name */
	if (!start)
		em.pb.data.track_event.which_name_field = 0;
	anns_reset(&em.anns);

	/* ... could have args emitted afterwards */
	return (struct emit_rec){};
}

#define emit_slice_point(ts, t, name_iid, name, cat_iid, category, start)			\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_slice_point_pre(ts, t, name_iid, name, cat_iid, category, start);		\
	     !___r.done; ___r.done = true)

__unused
static struct emit_rec emit_counter_pre(u64 ts, const struct wprof_task *t,
					pb_iid name_iid, const char *name)
{
	/* TODO: support counters */
	return (struct emit_rec){ .done = true };
}

#define emit_counter(ts, t, name_iid, name)							\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_counter_pre(ts, t, name_iid, name);						\
	     !___r.done; ___r.done = true)

static bool kind_track_emitted[] = {
	[TASK_IDLE] = false,
	[TASK_KWORKER] = false,
	[TASK_KTHREAD] = false,
};

static void emit_kind_track_descr(pb_ostream_t *stream, enum task_kind k)
{
	u64 track_uuid = kind_track_uuid(k);
	const char *track_name = kind_track_name(k);
	int track_rank = kind_track_rank(k);

	TracePacket desc_pb = {
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_track_descriptor) = { .track_descriptor = {
			PB_INIT(uuid) = track_uuid,
			PB_INIT(process) = {
				PB_INIT(pid) = track_uuid,
				.process_name = PB_STRING(track_name),
			},
			PB_INIT(child_ordering) = k == TASK_KWORKER
				? perfetto_protos_TrackDescriptor_ChildTracksOrdering_LEXICOGRAPHIC
				: perfetto_protos_TrackDescriptor_ChildTracksOrdering_EXPLICIT,
			PB_INIT(sibling_order_rank) = track_rank,
		}},
	};
	enc_trace_packet(stream, &desc_pb);
}

static void emit_process_track_descr(pb_ostream_t *stream, const struct wprof_task *t, pb_iid pname_iid)
{
	const char *pcomm;

	pcomm = track_pcomm(t);
	TracePacket proc_desc = {
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_track_descriptor) = { .track_descriptor = {
			PB_INIT(uuid) = process_track_uuid(t),
			PB_INIT(process) = {
				PB_INIT(pid) = track_pid(t),
				.process_name = PB_STRING(pcomm),
			},
			PB_INIT(child_ordering) = perfetto_protos_TrackDescriptor_ChildTracksOrdering_EXPLICIT,
			PB_INIT(sibling_order_rank) = track_process_rank(t),
		}},
		PB_INIT(interned_data) = {
			.event_names = PB_STR_IID(pname_iid, pcomm),
			.debug_annotation_string_values = PB_STR_IID(pname_iid, pcomm),
		}
	};
	enc_trace_packet(stream, &proc_desc);
}

static void emit_thread_track_descr(pb_ostream_t *stream, const struct wprof_task *t, pb_iid tname_iid, const char *comm)
{
	TracePacket thread_desc = {
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_track_descriptor) = { .track_descriptor = {
			PB_INIT(uuid) = task_track_uuid(t),
			PB_INIT(thread) = {
				PB_INIT(tid) = track_tid(t),
				PB_INIT(pid) = track_pid(t),
				.thread_name = PB_STRING(comm),
			},
			PB_INIT(child_ordering) = perfetto_protos_TrackDescriptor_ChildTracksOrdering_EXPLICIT,
			PB_INIT(sibling_order_rank) = track_thread_rank(t),
		}},
		PB_INIT(interned_data) = {
			.event_names = PB_STR_IID(tname_iid, comm),
			.debug_annotation_string_values = PB_STR_IID(tname_iid, comm),
		}
	};
	enc_trace_packet(stream, &thread_desc);
}

static struct task_state *task_state(struct worker_state *w, struct wprof_task *t)
{
	unsigned long key = t->tid;
	struct task_state *st;

	if (hashmap__find(tasks, key, &st))
		return st;

	st = calloc(1, sizeof(*st));
	st->tid = t->tid;
	st->pid = t->pid;
	strlcpy(st->comm, t->comm, sizeof(st->comm));
	st->name_iid = str_iid_for(&w->name_iids, t->comm, NULL, NULL);

	hashmap__set(tasks, key, st, NULL, NULL);

	/* Proactively setup process group leader tasks info */
	enum task_kind tkind = task_kind(t);
	if (tkind == TASK_NORMAL) {
		unsigned long pkey = t->pid;
		struct task_state *pst = NULL;

		if (t->tid == t->pid) {
			/* we are the new task group leader */
			emit_process_track_descr(&w->stream, t, str_iid_for(&w->name_iids, t->pcomm, NULL, NULL));
		} else if (!hashmap__find(tasks, pkey, &pst)) {
			/* no task group leader task yet */
			pst = calloc(1, sizeof(*st));
			pst->tid = pst->pid = t->pid;
			strlcpy(pst->comm, t->pcomm, sizeof(pst->comm));
			pst->name_iid = str_iid_for(&w->name_iids, pst->comm, NULL, NULL);

			hashmap__set(tasks, pkey, pst, NULL, NULL);

			struct wprof_task pt = {
				.tid = t->pid,
				.pid = t->pid,
				.flags = 0,
			};
			strlcpy(pt.comm, t->pcomm, sizeof(pt.comm));
			strlcpy(pt.pcomm, t->pcomm, sizeof(pt.comm));

			emit_process_track_descr(&w->stream, &pt, pst->name_iid);
			emit_thread_track_descr(&w->stream, &pt, pst->name_iid, pst->comm);
		} else {
			/* otherwise someone already emitted descriptors */
		}
	} else if (!kind_track_emitted[tkind]) {
		emit_kind_track_descr(&w->stream, tkind);
		kind_track_emitted[tkind] = true;
	}

	emit_thread_track_descr(&w->stream, t, st->name_iid, t->comm);

	return st;
}

static void task_state_delete(struct wprof_task *t)
{
	unsigned long key = t->tid;
	struct task_state *st;

	hashmap__delete(tasks, key, NULL, &st);

	free(st);
}

int process_event(struct worker_state *w, struct wprof_event *e, size_t size)
{
	const char *status;
	struct task_state *st, *pst = NULL, *fst = NULL, *nst = NULL;
	int strace_id;

	st = task_state(w, &e->task);

	switch (e->kind) {
	case EV_TIMER:
		break;
	case EV_SWITCH_FROM:
		nst = task_state(w, &e->swtch_from.next);
		break;
	case EV_SWITCH_TO:
		/* init switched-from task state, if necessary */
		pst = task_state(w, &e->swtch_to.prev);
		st->oncpu_ctrs = e->swtch_to.ctrs;
		st->oncpu_ts = e->ts;
		break;
	case EV_FORK:
		/* init forked child task state */
		fst = task_state(w, &e->fork.child);
		break;
	case EV_TASK_RENAME:
		if (st->rename_ts == 0) {
			memcpy(st->old_comm, e->task.comm, sizeof(st->old_comm));
			st->rename_ts = e->ts;
		}
		memcpy(st->comm, e->rename.new_comm, sizeof(st->comm));
		break;
	case EV_TASK_EXIT:
		/* we still might be getting task events, too early to delete the state */
		break;
	case EV_TASK_FREE:
		/* now we should be done with the task */
		task_state_delete(&e->task);
		break;
	default:
	}

	status = event_kind_str(e->kind);

	strace_id = event_stack_trace_id(w, e, size);

	if (w->trace) {
		switch (e->kind) {
		case EV_TIMER:
			/* task keeps running on CPU */
			emit_instant(e->ts, &e->task, IID_NAME_TIMER, "TIMER") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
			}

			TracePacket pb = (TracePacket) {
				PB_INIT(timestamp) = e->ts - env.sess_start_ts,
				PB_TRUST_SEQ_ID(),
				PB_ONEOF(data, TracePacket_perf_sample) = { .perf_sample = {
					PB_INIT(pid) = track_pid(&e->task),
					PB_INIT(tid) = track_tid(&e->task),
				}},
			};
			if (strace_id > 0) {
				pb.data.perf_sample.has_callstack_iid = true;
				pb.data.perf_sample.callstack_iid = strace_id;
			}
			enc_trace_packet(&w->stream, &pb);
			break;
		case EV_SWITCH_FROM: {
			const char *prev_name;
			pb_iid prev_name_iid;

			/* take into account task rename for switched-out task
			 * to maintain consistently named trace slice
			 */
			prev_name = st->rename_ts ? st->old_comm : st->comm;
			prev_name_iid = st->rename_ts ? st->rename_iid : st->name_iid;

			/* We are about to emit SLICE_END without
			 * corresponding SLICE_BEGIN ever being emitted;
			 * normally, Perfetto will just skip such SLICE_END
			 * and won't render anything, which is annoying and
			 * confusing. We want to avoid this, so we'll emit
			 * a fake SLICE_BEGIN with fake timestamp ZERO.
			 */
			if (st->oncpu_ts == 0) {
				emit_slice_point(env.sess_start_ts, &e->task,
						 prev_name_iid, prev_name,
						 IID_CAT_ONCPU, "ONCPU", true /*start*/) {
					emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
					emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
				}
			}

			emit_slice_point(e->ts, &e->task,
					 prev_name_iid, prev_name,
					 IID_CAT_ONCPU, "ONCPU", false /*!start*/) {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);

				emit_kv_str(IID_ANNK_SWITCH_TO, "switch_to", nst->name_iid, e->swtch_from.next.comm);
				emit_kv_int(IID_ANNK_SWITCH_TO_TID, "switch_to_tid", task_tid(&e->swtch_from.next));
				emit_kv_int(IID_ANNK_SWITCH_TO_PID, "switch_to_pid", e->swtch_from.next.pid);

				for (int i = 0; i < env.counter_cnt; i++) {
					const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[i]];
					const struct perf_counters *st_ctrs = &st->oncpu_ctrs;
					const struct perf_counters *ev_ctrs = &e->swtch_from.ctrs;

					if (st_ctrs->val[i] && ev_ctrs->val[i]) {
						emit_kv_float(def->trace_name_iid, def->trace_name,
							      "%.6lf", (ev_ctrs->val[i] - st_ctrs->val[i]) * def->mul);
					}
				}

				if (st->rename_ts)
					emit_kv_str(IID_ANNK_RENAMED_TO, "renamed_to", IID_NONE, e->task.comm);
			}

			/*
			if (env.cpu_counters && env.breakout_counters &&
			    st->oncpu_ts && st->cpu_cycles && e->swtch_from.cpu_cycles) {
				emit_counter(st->oncpu_ts, &e->task, IID_NONE, "cpu_cycles") {
					emit_kv_float(IID_NONE, "mega_cycles", "%.6lf",
						      (e->swtch_from.cpu_cycles - st->cpu_cycles) / 1000000.0);
				}
				emit_counter(e->ts, &e->task, IID_NONE, "cpu_cycles") {
					emit_kv_float(IID_NONE, "mega_cycles", "%.6lf", 0.0);
				}
			}
			*/

			TracePacket pb = (TracePacket) {
				PB_INIT(timestamp) = e->ts - env.sess_start_ts,
				PB_TRUST_SEQ_ID(),
				PB_ONEOF(data, TracePacket_perf_sample) = { .perf_sample = {
					PB_INIT(pid) = track_pid(&e->task),
					PB_INIT(tid) = track_tid(&e->task),
				}},
			};
			if (strace_id > 0) {
				pb.data.perf_sample.has_callstack_iid = true;
				pb.data.perf_sample.callstack_iid = strace_id;
			}
			enc_trace_packet(&w->stream, &pb);

			if (st->rename_ts) {
				st->rename_ts = 0;
				st->name_iid = st->rename_iid;
			}
			break;
		}
		case EV_SWITCH_TO: {
			struct task_state *wst = NULL;

			if (e->swtch_to.waking_ts) {
				wst = task_state(w, &e->swtch_to.waking);

				/* event on awaker's timeline */
				emit_instant(e->swtch_to.waking_ts, &e->swtch_to.waking,
					     e->swtch_to.waking_flags == WF_WOKEN_NEW ? IID_NAME_WAKEUP_NEW : IID_NAME_WAKING,
					     e->swtch_to.waking_flags == WF_WOKEN_NEW ? "WAKEUP_NEW" : "WAKING") {
					emit_kv_int(IID_ANNK_CPU, "cpu", e->swtch_to.waking_cpu);
					emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->swtch_to.waking_numa_node);

					emit_kv_str(IID_ANNK_WAKING_TARGET, "waking_target", st->name_iid, e->task.comm);
					emit_kv_int(IID_ANNK_WAKING_TARGET_TID, "waking_target_tid", task_tid(&e->task));
					emit_kv_int(IID_ANNK_WAKING_TARGET_PID, "waking_target_pid", e->task.pid);

					emit_flow_id(e->swtch_to.waking_ts);
				}

				/* event on awoken's timeline */
				if (e->swtch_to.waking_cpu != e->cpu) {
					emit_instant(e->swtch_to.waking_ts, &e->task,
						     e->swtch_to.waking_flags == WF_WOKEN_NEW ? IID_NAME_WOKEN_NEW : IID_NAME_WOKEN,
						     e->swtch_to.waking_flags == WF_WOKEN_NEW ? "WOKEN_NEW" : "WOKEN") {
						emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
						emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);

						emit_flow_id(e->swtch_to.waking_ts);
					}
				}
			}

			emit_slice_point(e->ts, &e->task, st->name_iid, e->task.comm,
					 IID_CAT_ONCPU, "ONCPU", true /*start*/) {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);

				if (e->swtch_to.waking_ts) {
					emit_kv_str(IID_ANNK_WAKING_BY, "waking_by", wst->name_iid, e->swtch_to.waking.comm);
					emit_kv_int(IID_ANNK_WAKING_BY_TID, "waking_by_tid", task_tid(&e->swtch_to.waking));
					emit_kv_int(IID_ANNK_WAKING_BY_PID, "waking_by_pid", e->swtch_to.waking.pid);
					emit_kv_str(IID_ANNK_WAKING_REASON, "waking_reason",
						    IID_NONE, waking_reason_str(e->swtch_to.waking_flags));
					emit_kv_int(IID_ANNK_WAKING_CPU, "waking_cpu", e->swtch_to.waking_cpu);
					emit_kv_int(IID_ANNK_WAKING_NUMA_NODE, "waking_numa_node", e->swtch_to.waking_numa_node);
					emit_kv_float(IID_ANNK_WAKING_DELAY_US, "waking_delay_us",
						      "%.3lf", (e->ts - e->swtch_to.waking_ts) / 1000.0);
				}

				emit_kv_str(IID_ANNK_SWITCH_FROM, "switch_from", pst->name_iid, e->task.comm);
				emit_kv_int(IID_ANNK_SWITCH_FROM_TID, "switch_from_tid", task_tid(&e->swtch_to.prev));
				emit_kv_int(IID_ANNK_SWITCH_FROM_PID, "switch_from_pid", e->swtch_to.prev.pid);
			}

			if (env.breakout_counters && e->swtch_to.waking_ts) {
				emit_counter(e->ts, &e->task, IID_NONE, "waking_delay") {
					emit_kv_float(IID_NONE, "us", "%.3lf", (e->ts - e->swtch_to.waking_ts) / 1000.0);
				}
			}

			if (pst->rename_ts) {
				pst->rename_ts = 0;
				pst->name_iid = pst->rename_iid;
			}
			break;
		}
		case EV_FORK: {
			emit_instant(e->ts, &e->task, IID_NAME_FORKING, "FORKING") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);

				emit_kv_str(IID_ANNK_FORKED_INTO, "forked_into", fst->name_iid, e->fork.child.comm);
				emit_kv_int(IID_ANNK_FORKED_INTO_TID, "forked_into_tid", task_tid(&e->fork.child));
				emit_kv_int(IID_ANNK_FORKED_INTO_PID, "forked_into_pid", e->fork.child.pid);
			}
			emit_instant(e->ts, &e->fork.child, IID_NAME_FORKED, "FORKED") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);

				emit_kv_str(IID_ANNK_FORKED_FROM, "forked_from", st->name_iid, e->task.comm);
				emit_kv_int(IID_ANNK_FORKED_FROM_TID, "forked_from_tid", task_tid(&e->task));
				emit_kv_int(IID_ANNK_FORKED_FROM_PID, "forked_from_pid", e->task.pid);
			}
			break;
		}
		case EV_EXEC: {
			emit_instant(e->ts, &e->task, IID_NAME_EXEC, "EXEC") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);

				emit_kv_str(IID_ANNK_FILENAME, "filename", IID_NONE, e->exec.filename);
				if (e->task.tid != e->exec.old_tid)
					emit_kv_int(IID_ANNK_TID_CHANGED_FROM, "tid_changed_from", e->exec.old_tid);
			}
			break;
		}
		case EV_TASK_RENAME: {
			emit_instant(e->ts, &e->task, IID_NAME_RENAME, "RENAME") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);

				emit_kv_str(IID_ANNK_OLD_NAME, "old_name", IID_NONE, e->task.comm);
				emit_kv_str(IID_ANNK_NEW_NAME, "new_name", IID_NONE, e->rename.new_comm);
			}

			st->rename_iid = str_iid_for(&w->name_iids, e->rename.new_comm, NULL, NULL);
			emit_thread_track_descr(&w->stream, &e->task, st->rename_iid, e->rename.new_comm);
			break;
		}
		case EV_TASK_EXIT:
			emit_instant(e->ts, &e->task, IID_NAME_EXIT, "EXIT") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
			}
			break;
		case EV_TASK_FREE:
			emit_instant(e->ts, &e->task, IID_NAME_FREE, "FREE") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
			}
			break;
		case EV_WAKEUP:
			emit_instant(e->ts, &e->task, IID_NAME_WAKEUP, "WAKEUP") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
			}
			break;
		case EV_WAKEUP_NEW:
			emit_instant(e->ts, &e->task, IID_NAME_WAKEUP_NEW, "WAKEUP_NEW") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
			}
			break;
		case EV_WAKING:
			emit_instant(e->ts, &e->task, IID_NAME_WAKING, "WAKING") {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
			}
			break;
		case EV_HARDIRQ_EXIT:
			emit_slice_point(e->hardirq.hardirq_ts, &e->task,
					 IID_NAME_HARDIRQ, "HARDIRQ",
					 IID_CAT_HARDIRQ, "HARDIRQ", true /* start */) {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
				emit_kv_int(IID_ANNK_IRQ, "irq", e->hardirq.irq);
				emit_kv_str(IID_ANNK_ACTION, "action", IID_NONE, e->hardirq.name);
			}
			emit_slice_point(e->ts, &e->task,
					 IID_NAME_HARDIRQ, "HARDIRQ",
					 IID_CAT_HARDIRQ, "HARDIRQ", false /* !start */) {
				for (int i = 0; i < env.counter_cnt; i++) {
					const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[i]];

					emit_kv_float(def->trace_name_iid, def->trace_name,
						      "%.6lf", e->hardirq.ctrs.val[i] * def->mul);
				}
			}
			break;
		case EV_SOFTIRQ_EXIT: {
			pb_iid name_iid, act_iid;

			if (e->softirq.vec_nr >= 0 && e->softirq.vec_nr < NR_SOFTIRQS) {
				name_iid = IID_NAME_SOFTIRQ + e->softirq.vec_nr;
				act_iid = IID_ANNV_SOFTIRQ_ACTION + e->softirq.vec_nr;
			} else {
				name_iid = IID_NONE;
				act_iid = IID_NONE;
			}

			emit_slice_point(e->softirq.softirq_ts, &e->task,
					 name_iid, sfmt("%s:%s", "SOFTIRQ", softirq_str(e->softirq.vec_nr)),
					 IID_CAT_SOFTIRQ, "SOFTIRQ", true /* start */) {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
				emit_kv_str(IID_ANNK_ACTION, "action", act_iid, softirq_str(e->softirq.vec_nr));
			}

			emit_slice_point(e->ts, &e->task,
					 name_iid, sfmt("%s:%s", "SOFTIRQ", softirq_str(e->softirq.vec_nr)),
					 IID_CAT_SOFTIRQ, "SOFTIRQ", false /* !start */) {
				for (int i = 0; i < env.counter_cnt; i++) {
					const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[i]];

					emit_kv_float(def->trace_name_iid, def->trace_name,
						      "%.6lf", e->softirq.ctrs.val[i] * def->mul);
				}
			}
			break;
		}
		case EV_WQ_END:
			emit_slice_point(e->wq.wq_ts, &e->task,
					 IID_NONE, sfmt("%s:%s", "WQ", e->wq.desc),
					 IID_CAT_WQ, "WQ", true /* start */) {
				emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
				emit_kv_str(IID_ANNK_ACTION, "action", IID_NONE, e->wq.desc);
			}
			emit_slice_point(e->ts, &e->task,
					 IID_NONE, sfmt("%s:%s", "WQ", e->wq.desc),
					 IID_CAT_WQ, "WQ", false /* !start */) {
				for (int i = 0; i < env.counter_cnt; i++) {
					const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[i]];

					emit_kv_float(def->trace_name_iid, def->trace_name,
						      "%.6lf", e->wq.ctrs.val[i] * def->mul);
				}
			}
			break;
		default:
			fprintf(stderr, "UNHANDLED EVENT %d\n", e->kind);
			exit(1);
			break;
		}
	}

	/* event post-processing logic */
	switch (e->kind) {
	case EV_SWITCH_FROM:
		/* init switched-from task state, if necessary */
		memset(&st->oncpu_ctrs, 0, sizeof(struct perf_counters));
		st->oncpu_ts = 0;
		break;
	default:
	}

	if (!env.verbose)
		return 0;

	printf("%s (%d/%d) @ CPU %d %s %lldus\n",
	       e->task.comm, e->task.tid, e->task.pid, e->cpu,
	       status, 0LL /* e->dur_ns / 1000 */);

	return 0;
}

