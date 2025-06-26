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

enum task_run_state {
	TASK_STATE_RUNNING,
	TASK_STATE_WAITING,
	TASK_STATE_PREEMPTED,
};

struct task_state {
	int tid, pid;
	pb_iid name_iid;
	char comm[TASK_COMM_FULL_LEN];
	/* task renames */
	u64 rename_ts;
	char old_comm[TASK_COMM_FULL_LEN];
	/* on-cpu state */
	enum task_run_state run_state;
	u64 oncpu_ts;
	u64 req_id; /* active ongoing request ID */
	/* perf counters */
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
	struct pb_str_iids str_iids;
};

__unused
static void emit_kv_str(pb_iid key_iid, const char *key, pb_iid value_iid, const char *value)
{
	anns_add_str(&em.anns, key_iid, key, value_iid, value);
}

__unused
static void __emit_kv_str(struct pb_str key, struct pb_str value)
{
	emit_kv_str(key.iid, key.s, value.iid, value.s);
}

#define emit_kv_str2(key, value) __emit_kv_str(__pb_str((key)), __pb_str((value)))

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
static void __emit_kv_int(struct pb_str key, int64_t value)
{
	emit_kv_int(key.iid, key.s, value);
}

#define emit_kv_int2(key, value) __emit_kv_int(__pb_str((key)), (value))

__unused
static void emit_kv_float(pb_iid key_iid, const char *key, const char *fmt, double value)
{
	anns_add_double(&em.anns, key_iid, key, value);
}

__unused
static void __emit_kv_float(struct pb_str key, const char *fmt, double value)
{
	emit_kv_float(key.iid, key.s, fmt, value);
}

#define emit_kv_float2(key, fmt, value) __emit_kv_float(__pb_str((key)), (fmt), (value))

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

__unused
static void emit_str_iid(pb_iid iid, const char *key)
{
	append_str_iid(&em.str_iids, iid, key);
}

struct emit_rec { bool done; };

static void emit_trace_packet(pb_ostream_t *stream, TracePacket *pb)
{
	if (em.str_iids.cnt > 0) {
		if (pb->has_interned_data && pb->interned_data.event_names.funcs.encode) {
			fprintf(stderr, "BUG: interned_data.event_names is already set!\n");
			exit(1);
		}
		if (pb->has_interned_data && pb->interned_data.debug_annotation_string_values.funcs.encode) {
			fprintf(stderr, "BUG: interned_data.debug_annotation_string_values is already set!\n");
			exit(1);
		}
		pb->has_interned_data = true;
		pb->interned_data.event_names = PB_STR_IIDS(&em.str_iids);
		pb->interned_data.debug_annotation_string_values = PB_STR_IIDS(&em.str_iids);
	}

	enc_trace_packet(stream, pb);

	reset_str_iids(&em.str_iids);
}

static void emit_cleanup(struct emit_rec *r)
{
	emit_trace_packet(cur_stream, &em.pb);
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
#define TRACK_UUID_REQUESTS	2000000003ULL

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

static uint64_t track_thread(const struct wprof_task *t)
{
	return track_pid(t) * 1000000000ULL + track_tid(t);
}

static uint64_t track_process(const struct wprof_task *t)
{
	enum task_kind k = task_kind(t);

	if (k == TASK_NORMAL)
		return track_pid(t) * 1000000000ULL;
	return kind_track_uuid(k);
}

static inline u64 track_req_thread(u64 req_id, const struct wprof_task *t)
{
	return req_id ^ t->tid;
}

static inline u64 track_req_process(u64 req_id, const struct wprof_task *t)
{
	return req_id ^ t->pid;
}

static inline u64 track_process_reqs(const struct wprof_task *t)
{
	return t->pid | TRACK_UUID_REQUESTS;
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
	[EV_IPI_SEND] = "IPI_SEND",
	[EV_IPI_EXIT] = "IPI_EXIT",
	[EV_REQ_EVENT] = "REQ_EVENT",
};

__unused
static const char *event_kind_str(enum event_kind kind)
{
	if (kind >= 0 && kind < ARRAY_SIZE(event_kind_str_map))
		return event_kind_str_map[kind] ?: "UNKNOWN";
	return "UNKNOWN";
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
					__u64 track_uuid,
					pb_iid name_iid, const char *name,
					pb_iid cat_iid, const char *cat)
{
	em.pb = (TracePacket) {
		PB_INIT(timestamp) = ts - env.sess_start_ts,
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_track_event) = { .track_event = {
			PB_INIT(track_uuid) = track_uuid,
			PB_INIT(type) = perfetto_protos_TrackEvent_Type_TYPE_INSTANT,
			.category_iids = cat_iid ? PB_STRING_IID(cat_iid) : PB_NONE,
			.categories = cat_iid ? PB_NONE : PB_STRING(cat),
			PB_NAME(TrackEvent, name_field, name_iid, name),
			.debug_annotations = PB_ANNOTATIONS(&em.anns),
		}},
	};
	anns_reset(&em.anns);

	/* ... could have args emitted afterwards */
	return (struct emit_rec){};
}

static struct emit_rec emit_instant_pre2(u64 ts, __u64 track_uuid,
					struct pb_str name, struct pb_str cat)
{
	return emit_instant_pre(ts, NULL, track_uuid, name.iid, name.s, cat.iid, cat.s);
}

#define emit_instant(ts, t, name_iid, name, cat_iid, cat)					\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_instant_pre(ts, t, track_thread(t), name_iid, name, cat_iid, cat);		\
	     !___r.done; ___r.done = true)

#define emit_track_instant(ts, t, track_uuid, name_iid, name, cat)				\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_instant_pre(ts, t, track_uuid, name_iid, name, cat);				\
	     !___r.done; ___r.done = true)

__unused
static struct emit_rec emit_slice_point_pre(u64 ts, const struct wprof_task *t,
					    __u64 track_uuid,
					    pb_iid name_iid, const char *name,
					    pb_iid cat_iid, const char *cat,
					    bool start)
{
	em.pb = (TracePacket) {
		PB_INIT(timestamp) = ts - env.sess_start_ts,
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_track_event) = { .track_event = {
			PB_INIT(track_uuid) = track_uuid,
			PB_INIT(type) = start ? perfetto_protos_TrackEvent_Type_TYPE_SLICE_BEGIN
					      : perfetto_protos_TrackEvent_Type_TYPE_SLICE_END,
			.category_iids = cat_iid ? PB_STRING_IID(cat_iid) : PB_NONE,
			.categories = cat_iid ? PB_NONE : PB_STRING(cat),
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

static struct emit_rec emit_slice_point_pre2(u64 ts, u64 track_uuid,
					    struct pb_str name, struct pb_str cat, bool start)
{
	return emit_slice_point_pre(ts, NULL, track_uuid, name.iid, name.s, cat.iid, cat.s, start);
}

#define emit_slice_point(ts, t, name_iid, name, cat_iid, cat, start)				\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_slice_point_pre(ts, t, track_thread(t),					\
				  name_iid, name, cat_iid, cat, start);				\
	     !___r.done; ___r.done = true)

#define emit_track_slice_point(ts, t, track_uuid, name_iid, name, cat, start)			\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_slice_point_pre(ts, t, track_uuid, name_iid, name, cat, start);		\
	     !___r.done; ___r.done = true)

static inline struct pb_str __pb_str_literal(const char *str) { return iid_str(0, str); }
static inline struct pb_str __pb_str_iid(enum pb_static_iid iid) { return iid_str(iid, pb_static_str(iid)); }
static inline struct pb_str __pb_str_iidstr(struct pb_str str) { return str; }

#define __pb_str(arg) _Generic((arg),								\
	const char *: __pb_str_literal,								\
	int: __pb_str_iid,									\
	struct pb_str: __pb_str_iidstr								\
)((arg))

#define emit_track_slice_start(ts, track, name, cat)						\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_slice_point_pre2(ts, track, __pb_str(name), __pb_str(cat), true /*start*/);	\
	     !___r.done; ___r.done = true)

#define emit_track_slice_end(ts, track, name, cat)						\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_slice_point_pre2(ts, track, __pb_str(name), __pb_str(cat), false /*!start*/);	\
	     !___r.done; ___r.done = true)

#define emit_track_instan2(ts, track, name, cat)						\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_instant_pre2(ts, track, __pb_str(name), __pb_str(cat));			\
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

static void emit_stack_trace(u64 ts, const struct wprof_task *t, int stack_id)
{
	TracePacket pb = (TracePacket) {
		PB_INIT(timestamp) = ts - env.sess_start_ts,
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_perf_sample) = { .perf_sample = {
			PB_INIT(pid) = track_pid(t),
			PB_INIT(tid) = track_tid(t),
			PB_INIT(callstack_iid) = stack_id,
		}},
	};
	emit_trace_packet(cur_stream, &pb);
}

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
	emit_trace_packet(stream, &desc_pb);
}

static void emit_track_descr(pb_ostream_t *stream, __u64 track_uuid, __u64 parent_track_uuid, const char *name)
{
	TracePacket desc = {
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_track_descriptor) = { .track_descriptor = {
			PB_INIT(uuid) = track_uuid,
			PB_INIT(disallow_merging_with_system_tracks) = true,
			.parent_uuid = parent_track_uuid,
			.has_parent_uuid = parent_track_uuid != 0,
			PB_ONEOF(static_or_dynamic_name, TrackDescriptor_name) = { .name = PB_STRING(name) },
		}},
	};
	emit_trace_packet(stream, &desc);
}

static void emit_process_track_descr(pb_ostream_t *stream, const struct wprof_task *t)
{
	const char *pcomm;

	pcomm = track_pcomm(t);
	TracePacket proc_desc = {
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_track_descriptor) = { .track_descriptor = {
			PB_INIT(uuid) = track_process(t),
			PB_INIT(process) = {
				PB_INIT(pid) = track_pid(t),
				.process_name = PB_STRING(pcomm),
			},
			PB_INIT(child_ordering) = perfetto_protos_TrackDescriptor_ChildTracksOrdering_EXPLICIT,
			PB_INIT(sibling_order_rank) = track_process_rank(t),
		}},
	};
	emit_trace_packet(stream, &proc_desc);
}

static void emit_thread_track_descr(pb_ostream_t *stream, const struct wprof_task *t, const char *comm)
{
	TracePacket thread_desc = {
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_track_descriptor) = { .track_descriptor = {
			PB_INIT(uuid) = track_thread(t),
			PB_INIT(thread) = {
				PB_INIT(tid) = track_tid(t),
				PB_INIT(pid) = track_pid(t),
				.thread_name = PB_STRING(comm),
			},
			PB_INIT(child_ordering) = perfetto_protos_TrackDescriptor_ChildTracksOrdering_EXPLICIT,
			PB_INIT(sibling_order_rank) = track_thread_rank(t),
		}},
	};
	emit_trace_packet(stream, &thread_desc);
}

static pb_iid emit_intern_str(struct worker_state *w, const char *s)
{
	pb_iid iid = 0;
	bool new_iid;
	const char *iid_str;

	iid = str_iid_for(&w->name_iids, s, &new_iid, &iid_str);
	if (new_iid)
		emit_str_iid(iid, iid_str);
	return iid;
}

static struct task_state *task_state(struct worker_state *w, const struct wprof_task *t)
{
	unsigned long key = t->tid;
	struct task_state *st;

	if (hashmap__find(tasks, key, &st))
		return st;

	st = calloc(1, sizeof(*st));
	st->tid = t->tid;
	st->pid = t->pid;
	wprof_strlcpy(st->comm, t->comm, sizeof(st->comm));
	st->name_iid = emit_intern_str(w, t->comm);

	hashmap__set(tasks, key, st, NULL, NULL);

	/* Proactively setup process group leader tasks info */
	enum task_kind tkind = task_kind(t);
	if (tkind == TASK_NORMAL) {
		unsigned long pkey = t->pid;
		struct task_state *pst = NULL;

		if (t->tid == t->pid) {
			/* we are the new task group leader */
			(void)emit_intern_str(w, t->pcomm);
			emit_process_track_descr(&w->stream, t);
		} else if (!hashmap__find(tasks, pkey, &pst)) {
			/* no task group leader task yet */
			pst = calloc(1, sizeof(*st));
			pst->tid = pst->pid = t->pid;
			wprof_strlcpy(pst->comm, t->pcomm, sizeof(pst->comm));
			pst->name_iid = emit_intern_str(w, pst->comm);

			hashmap__set(tasks, pkey, pst, NULL, NULL);

			struct wprof_task pt = {
				.tid = t->pid,
				.pid = t->pid,
				.flags = 0,
			};
			wprof_strlcpy(pt.comm, t->pcomm, sizeof(pt.comm));
			wprof_strlcpy(pt.pcomm, t->pcomm, sizeof(pt.pcomm));

			emit_process_track_descr(&w->stream, &pt);
			emit_thread_track_descr(&w->stream, &pt, pst->comm);
		} else {
			/* otherwise someone already emitted descriptors */
		}
	} else if (!kind_track_emitted[tkind]) {
		emit_kind_track_descr(&w->stream, tkind);
		kind_track_emitted[tkind] = true;
	}

	emit_thread_track_descr(&w->stream, t, t->comm);

	return st;
}

static void task_state_delete(struct wprof_task *t)
{
	unsigned long key = t->tid;
	struct task_state *st;

	if (hashmap__delete(tasks, key, NULL, &st))
		free(st);
}

static bool should_trace_task(const struct wprof_task *task)
{
	/* Denying takes precedence. Any matching deny filter rejects sample. */
	for (int i = 0; i < env.deny_pid_cnt; i++)
		if (task->pid == env.deny_pids[i])
			return false;
	for (int i = 0; i < env.deny_tid_cnt; i++)
		if (task->tid == env.deny_tids[i])
			return false;
	for (int i = 0; i < env.deny_pname_cnt; i++)
		if (wprof_glob_match(env.deny_pnames[i], task->pcomm))
			return false;
	for (int i = 0; i < env.deny_tname_cnt; i++)
		if (wprof_glob_match(env.deny_tnames[i], task->comm))
			return false;
	if (env.deny_idle && task->pid == 0)
		return false;
	if (env.deny_kthread && (task->flags & PF_KTHREAD))
		return false;

	/* Any matching allow filter accepts sample. If there are no
	 * filtering, sample is implicitly allowed. If filters are set, but
	 * none match - reject.
	 */
	bool needs_match = false;
	for (int i = 0; i < env.allow_pid_cnt; i++) {
		if (task->pid == env.allow_pids[i])
			return true;
		needs_match = true;
	}
	for (int i = 0; i < env.allow_tid_cnt; i++) {
		if (task->tid == env.allow_tids[i])
			return true;
		needs_match = true;
	}
	for (int i = 0; i < env.allow_pname_cnt; i++) {
		if (wprof_glob_match(env.allow_pnames[i], task->pcomm))
			return true;
		needs_match = true;
	}
	for (int i = 0; i < env.allow_tname_cnt; i++) {
		if (wprof_glob_match(env.allow_tnames[i], task->comm))
			return true;
		needs_match = true;
	}
	if (env.allow_idle) {
		if (task->pid == 0)
			return true;
		needs_match = true;
	}
	if (env.allow_kthread) {
		if (task->flags & PF_KTHREAD)
			return true;
		needs_match = true;
	}
	if (needs_match)
		return false;
	return true;
}

static bool is_ts_in_range(u64 ts)
{
	if ((long long)(ts - env.sess_start_ts) < 0)
		return false;
	if ((long long)(ts - env.sess_end_ts) >= 0)
		return false;
	return true;
}

/* EV_TIMER */
static int process_timer(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!should_trace_task(&e->task))
		return 0;

	(void)task_state(w, &e->task);

	/* task keeps running on CPU */
	emit_instant(e->ts, &e->task, IID_NAME_TIMER, "TIMER", IID_CAT_TIMER, "TIMER") {
		emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
	}

	int strace_id = event_stack_trace_id(w, e, size);
	if (strace_id > 0)
		emit_stack_trace(e->ts, &e->task, strace_id);

	return 0;
}

/* EV_SWITCH_FROM */
static int process_switch_from(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!should_trace_task(&e->task))
		return 0;

	/* take into account task rename for switched-out task
	 * to maintain consistently named trace slice
	 */
	struct task_state *st = task_state(w, &e->task);
	const char *prev_name = st->rename_ts ? st->old_comm : st->comm;
	pb_iid prev_name_iid = emit_intern_str(w, prev_name);

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
			if (env.emit_numa)
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
		}
	}

	emit_slice_point(e->ts, &e->task,
			 prev_name_iid, prev_name,
			 IID_CAT_ONCPU, "ONCPU", false /*!start*/) {
		emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);

		emit_kv_str(IID_ANNK_SWITCH_TO, "switch_to",
			    emit_intern_str(w, e->swtch_from.next.comm), e->swtch_from.next.comm);
		if (env.emit_tidpid) {
			emit_kv_int(IID_ANNK_SWITCH_TO_TID, "switch_to_tid", task_tid(&e->swtch_from.next));
			emit_kv_int(IID_ANNK_SWITCH_TO_PID, "switch_to_pid", e->swtch_from.next.pid);
		}

		for (int i = 0; i < env.counter_cnt; i++) {
			const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[i]];
			const struct perf_counters *st_ctrs = &st->oncpu_ctrs;
			const struct perf_counters *ev_ctrs = &e->swtch_from.ctrs;
			int p = env.counter_pos[i];

			if (st_ctrs->val[p] && ev_ctrs->val[p]) {
				emit_kv_float(def->trace_name_iid, def->trace_name,
					      "%.6lf", (ev_ctrs->val[p] - st_ctrs->val[p]) * def->mul);
			}
		}

		if (st->rename_ts)
			emit_kv_str(IID_ANNK_RENAMED_TO, "renamed_to", IID_NONE, e->task.comm);
	}

	int strace_id = event_stack_trace_id(w, e, size);
	if (strace_id > 0)
		emit_stack_trace(e->ts, &e->task, strace_id);

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

	bool preempted = e->swtch_from.task_state == TASK_RUNNING;

	if (st->req_id) {
		emit_track_slice_end(e->ts, track_req_thread(st->req_id, &e->task),
				     IID_NAME_RUNNING, IID_CAT_REQUEST_ONCPU);
		emit_track_slice_start(e->ts, track_req_thread(st->req_id, &e->task),
				       preempted ? IID_NAME_PREEMPTED : IID_NAME_WAITING,
				       IID_CAT_REQUEST_OFFCPU);
	}

	if (st->rename_ts)
		st->rename_ts = 0;

	/* reset perf counters */
	memset(&st->oncpu_ctrs, 0, sizeof(struct perf_counters));
	st->oncpu_ts = 0;
	st->run_state = preempted ? TASK_STATE_PREEMPTED : TASK_STATE_WAITING;

	return 0;
}

/* EV_SWITCH_TO */
static int process_switch_to(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (e->swtch_to.waking_ts &&
	    is_ts_in_range(e->swtch_to.waking_ts) &&
	    should_trace_task(&e->swtch_to.waking)) {
		/* event on awaker's timeline */
		emit_instant(e->swtch_to.waking_ts, &e->swtch_to.waking,
			     e->swtch_to.waking_flags == WF_WOKEN_NEW ? IID_NAME_WAKEUP_NEW : IID_NAME_WAKING,
			     e->swtch_to.waking_flags == WF_WOKEN_NEW ? "WAKEUP_NEW" : "WAKING",
			     e->swtch_to.waking_flags == WF_WOKEN_NEW ? IID_CAT_WAKEUP_NEW : IID_CAT_WAKING,
			     e->swtch_to.waking_flags == WF_WOKEN_NEW ? "WAKEUP_NEW" : "WAKING") {
			emit_kv_int(IID_ANNK_CPU, "cpu", e->swtch_to.waking_cpu);
			if (env.emit_numa)
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->swtch_to.waking_numa_node);

			emit_kv_str(IID_ANNK_WAKING_TARGET, "waking_target",
				    emit_intern_str(w, e->task.comm), e->task.comm);
			if (env.emit_tidpid) {
				emit_kv_int(IID_ANNK_WAKING_TARGET_TID, "waking_target_tid", task_tid(&e->task));
				emit_kv_int(IID_ANNK_WAKING_TARGET_PID, "waking_target_pid", e->task.pid);
			}

			emit_flow_id(e->swtch_to.waking_ts);
		}
	}

	if (!should_trace_task(&e->task))
		return 0;

	struct task_state *st = task_state(w, &e->task);
	st->oncpu_ctrs = e->swtch_to.ctrs;
	st->oncpu_ts = e->ts;

	if (e->swtch_to.waking_ts &&
	    is_ts_in_range(e->swtch_to.waking_ts) &&
	    e->swtch_to.waking_cpu != e->cpu) {
		/* event on awoken's timeline */
		emit_instant(e->swtch_to.waking_ts, &e->task,
			     e->swtch_to.waking_flags == WF_WOKEN_NEW ? IID_NAME_WOKEN_NEW : IID_NAME_WOKEN,
			     e->swtch_to.waking_flags == WF_WOKEN_NEW ? "WOKEN_NEW" : "WOKEN",
			     e->swtch_to.waking_flags == WF_WOKEN_NEW ? IID_CAT_WOKEN_NEW : IID_CAT_WOKEN,
			     e->swtch_to.waking_flags == WF_WOKEN_NEW ? "WOKEN_NEW" : "WOKEN") {
			emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
			if (env.emit_numa)
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);

			emit_flow_id(e->swtch_to.waking_ts);
		}
	}

	emit_slice_point(e->ts, &e->task, st->name_iid, e->task.comm,
			 IID_CAT_ONCPU, "ONCPU", true /*start*/) {
		emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);

		if (e->swtch_to.waking_ts) {
			emit_kv_str(IID_ANNK_WAKING_BY, "waking_by",
				    emit_intern_str(w, e->swtch_to.waking.comm), e->swtch_to.waking.comm);
			if (env.emit_tidpid) {
				emit_kv_int(IID_ANNK_WAKING_BY_TID, "waking_by_tid", task_tid(&e->swtch_to.waking));
				emit_kv_int(IID_ANNK_WAKING_BY_PID, "waking_by_pid", e->swtch_to.waking.pid);
			}
			emit_kv_str(IID_ANNK_WAKING_REASON, "waking_reason",
				    IID_ANNV_WAKING_REASON + wreason_enum(e->swtch_to.waking_flags),
				    wreason_str(e->swtch_to.waking_flags));
			emit_kv_int(IID_ANNK_WAKING_CPU, "waking_cpu", e->swtch_to.waking_cpu);
			if (env.emit_numa)
				emit_kv_int(IID_ANNK_WAKING_NUMA_NODE, "waking_numa_node", e->swtch_to.waking_numa_node);
			emit_kv_float(IID_ANNK_WAKING_DELAY_US, "waking_delay_us",
				      "%.3lf", (e->ts - e->swtch_to.waking_ts) / 1000.0);
		}

		emit_kv_str(IID_ANNK_SWITCH_FROM, "switch_from",
			    emit_intern_str(w, e->swtch_to.prev.comm), e->swtch_to.prev.comm);
		if (env.emit_tidpid) {
			emit_kv_int(IID_ANNK_SWITCH_FROM_TID, "switch_from_tid", task_tid(&e->swtch_to.prev));
			emit_kv_int(IID_ANNK_SWITCH_FROM_PID, "switch_from_pid", e->swtch_to.prev.pid);
		}

		if (e->swtch_to.waking_ts && is_ts_in_range(e->swtch_to.waking_ts))
			emit_flow_id(e->swtch_to.waking_ts);
	}

	if (env.breakout_counters && e->swtch_to.waking_ts) {
		emit_counter(e->ts, &e->task, IID_NONE, "waking_delay") {
			emit_kv_float(IID_NONE, "us", "%.3lf", (e->ts - e->swtch_to.waking_ts) / 1000.0);
		}
	}

	if (st->req_id) {
		bool was_preempted = e->swtch_to.last_task_state == TASK_RUNNING;
		emit_track_slice_end(e->ts, track_req_thread(st->req_id, &e->task),
				     was_preempted ? IID_NAME_PREEMPTED : IID_NAME_WAITING,
				     IID_CAT_REQUEST_OFFCPU);
		emit_track_slice_start(e->ts, track_req_thread(st->req_id, &e->task),
				       IID_NAME_RUNNING, IID_CAT_REQUEST_ONCPU);
	}

	st->run_state = TASK_STATE_RUNNING;

	return 0;
}

/* EV_FORK */
static int process_fork(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (should_trace_task(&e->task)) {
		(void)task_state(w, &e->task);

		emit_instant(e->ts, &e->task, IID_NAME_FORKING, "FORKING", IID_CAT_FORKING, "FORKING") {
			emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
			if (env.emit_numa)
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);

			emit_kv_str(IID_ANNK_FORKED_INTO, "forked_into",
				    emit_intern_str(w, e->fork.child.comm), e->fork.child.comm);
			emit_flow_id(e->ts);
			if (env.emit_tidpid) {
				emit_kv_int(IID_ANNK_FORKED_INTO_TID, "forked_into_tid", task_tid(&e->fork.child));
				emit_kv_int(IID_ANNK_FORKED_INTO_PID, "forked_into_pid", e->fork.child.pid);
			}
		}
	}

	if (should_trace_task(&e->fork.child)) {
		(void)task_state(w, &e->fork.child);

		emit_instant(e->ts, &e->fork.child, IID_NAME_FORKED, "FORKED", IID_CAT_FORKED, "FORKED") {
			emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
			if (env.emit_numa)
				emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);

			emit_kv_str(IID_ANNK_FORKED_FROM, "forked_from",
				    emit_intern_str(w, e->task.comm), e->task.comm);
			emit_flow_id(e->ts);
			if (env.emit_tidpid) {
				emit_kv_int(IID_ANNK_FORKED_FROM_TID, "forked_from_tid", task_tid(&e->task));
				emit_kv_int(IID_ANNK_FORKED_FROM_PID, "forked_from_pid", e->task.pid);
			}
		}
	}

	return 0;
}

/* EV_EXEC */
static int process_exec(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!should_trace_task(&e->task))
		return 0;

	(void)task_state(w, &e->task);

	emit_instant(e->ts, &e->task, IID_NAME_EXEC, "EXEC", IID_CAT_EXEC, "EXEC") {
		emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);

		emit_kv_str(IID_ANNK_FILENAME, "filename", IID_NONE, e->exec.filename);
		if (e->task.tid != e->exec.old_tid)
			emit_kv_int(IID_ANNK_TID_CHANGED_FROM, "tid_changed_from", e->exec.old_tid);
	}

	return 0;
}

/* EV_TASK_RENAME */
static int process_task_rename(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!should_trace_task(&e->task))
		return 0;

	struct task_state *st = task_state(w, &e->task);

	if (st->rename_ts == 0) {
		memcpy(st->old_comm, e->task.comm, sizeof(st->old_comm));
		st->rename_ts = e->ts;
	}
	memcpy(st->comm, e->rename.new_comm, sizeof(st->comm));

	emit_instant(e->ts, &e->task, IID_NAME_RENAME, "RENAME", IID_CAT_RENAME, "RENAME") {
		emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);

		emit_kv_str(IID_ANNK_OLD_NAME, "old_name", IID_NONE, e->task.comm);
		emit_kv_str(IID_ANNK_NEW_NAME, "new_name", IID_NONE, e->rename.new_comm);
	}

	(void)emit_intern_str(w, e->rename.new_comm);
	emit_thread_track_descr(&w->stream, &e->task, e->rename.new_comm);

	return 0;
}

/* EV_TASK_EXIT */
static int process_task_exit(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!should_trace_task(&e->task))
		return 0;

	(void)task_state(w, &e->task);

	emit_instant(e->ts, &e->task, IID_NAME_EXIT, "EXIT", IID_CAT_EXIT, "EXIT") {
		emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
	}

	/* we still might be getting task events, too early to delete the state */
	return 0;
}

/* EV_TASK_FREE */
static int process_task_free(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!should_trace_task(&e->task))
		goto skip_emit;

	(void)task_state(w, &e->task);

	emit_instant(e->ts, &e->task, IID_NAME_FREE, "FREE", IID_CAT_FREE, "FREE") {
		emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
	}

skip_emit:
	/* now we should be done with the task */
	task_state_delete(&e->task);

	return 0;
}

/* EV_WAKEUP */
static int process_wakeup(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!should_trace_task(&e->task))
		return 0;

	(void)task_state(w, &e->task);

	emit_instant(e->ts, &e->task, IID_NAME_WAKEUP, "WAKEUP", IID_CAT_WAKEUP, "WAKEUP") {
		emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
	}

	return 0;
}

/* EV_WAKEUP_NEW */
static int process_wakeup_new(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!should_trace_task(&e->task))
		return 0;

	(void)task_state(w, &e->task);

	emit_instant(e->ts, &e->task, IID_NAME_WAKEUP_NEW, "WAKEUP_NEW", IID_CAT_WAKEUP_NEW, "WAKEUP_NEW") {
		emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
	}

	return 0;
}

/* EV_WAKING */
static int process_waking(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!should_trace_task(&e->task))
		return 0;

	(void)task_state(w, &e->task);

	emit_instant(e->ts, &e->task, IID_NAME_WAKING, "WAKING", IID_CAT_WAKING, "WAKING") {
		emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
	}

	return 0;
}

/* EV_HARDIRQ_EXIT */
static int process_hardirq_exit(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!should_trace_task(&e->task))
		return 0;

	(void)task_state(w, &e->task);

	u64 start_ts = is_ts_in_range(e->hardirq.hardirq_ts) ? e->hardirq.hardirq_ts : env.sess_start_ts;
	emit_slice_point(start_ts, &e->task,
			 IID_NAME_HARDIRQ, "HARDIRQ",
			 IID_CAT_HARDIRQ, "HARDIRQ", true /* start */) {
		emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
		emit_kv_int(IID_ANNK_IRQ, "irq", e->hardirq.irq);
		emit_kv_str(IID_ANNK_ACTION, "action", IID_NONE, e->hardirq.name);
	}
	emit_slice_point(e->ts, &e->task,
			 IID_NAME_HARDIRQ, "HARDIRQ",
			 IID_CAT_HARDIRQ, "HARDIRQ", false /* !start */) {
		for (int i = 0; i < env.counter_cnt; i++) {
			const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[i]];
			int p = env.counter_pos[i];

			emit_kv_float(def->trace_name_iid, def->trace_name,
				      "%.6lf", e->hardirq.ctrs.val[p] * def->mul);
		}
	}

	return 0;
}

/* EV_SOFTIRQ_EXIT */
static int process_softirq_exit(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!should_trace_task(&e->task))
		return 0;

	(void)task_state(w, &e->task);

	pb_iid name_iid, act_iid;
	if (e->softirq.vec_nr >= 0 && e->softirq.vec_nr < NR_SOFTIRQS) {
		name_iid = IID_NAME_SOFTIRQ + e->softirq.vec_nr;
		act_iid = IID_ANNV_SOFTIRQ_ACTION + e->softirq.vec_nr;
	} else {
		name_iid = IID_NONE;
		act_iid = IID_NONE;
	}

	u64 start_ts = is_ts_in_range(e->softirq.softirq_ts) ? e->softirq.softirq_ts : env.sess_start_ts;
	emit_slice_point(start_ts, &e->task,
			 name_iid, sfmt("%s:%s", "SOFTIRQ", softirq_str(e->softirq.vec_nr)),
			 IID_CAT_SOFTIRQ, "SOFTIRQ", true /* start */) {
		emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
		emit_kv_str(IID_ANNK_ACTION, "action", act_iid, softirq_str(e->softirq.vec_nr));
	}

	emit_slice_point(e->ts, &e->task,
			 name_iid, sfmt("%s:%s", "SOFTIRQ", softirq_str(e->softirq.vec_nr)),
			 IID_CAT_SOFTIRQ, "SOFTIRQ", false /* !start */) {
		for (int i = 0; i < env.counter_cnt; i++) {
			const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[i]];
			int p = env.counter_pos[i];

			emit_kv_float(def->trace_name_iid, def->trace_name,
				      "%.6lf", e->softirq.ctrs.val[p] * def->mul);
		}
	}

	return 0;
}

/* EV_WQ_END */
static int process_wq_end(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!should_trace_task(&e->task))
		return 0;

	(void)task_state(w, &e->task);

	u64 start_ts = is_ts_in_range(e->wq.wq_ts) ? e->wq.wq_ts : env.sess_start_ts;
	emit_slice_point(start_ts, &e->task,
			 IID_NONE, sfmt("%s:%s", "WQ", e->wq.desc),
			 IID_CAT_WQ, "WQ", true /* start */) {
		emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
		emit_kv_str(IID_ANNK_ACTION, "action", IID_NONE, e->wq.desc);
	}
	emit_slice_point(e->ts, &e->task,
			 IID_NONE, sfmt("%s:%s", "WQ", e->wq.desc),
			 IID_CAT_WQ, "WQ", false /* !start */) {
		for (int i = 0; i < env.counter_cnt; i++) {
			const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[i]];
			int p = env.counter_pos[i];

			emit_kv_float(def->trace_name_iid, def->trace_name,
				      "%.6lf", e->wq.ctrs.val[p] * def->mul);
		}
	}

	return 0;
}

/* EV_IPI_SEND */
static int process_ipi_send(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!should_trace_task(&e->task))
		return 0;

	(void)task_state(w, &e->task);

	pb_iid name_iid;
	if (e->ipi_send.kind >= 0 && e->ipi_send.kind < NR_IPIS)
		name_iid = IID_NAME_IPI_SEND + e->ipi_send.kind;
	else
		name_iid = IID_NAME_IPI_SEND + IPI_INVALID;
	const char *name = sfmt("%s:%s", "IPI_SEND", ipi_kind_str(e->ipi.kind));

	emit_instant(e->ts, &e->task, name_iid, name, IID_CAT_IPI_SEND, "IPI_SEND") {
		emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
		if (e->ipi_send.ipi_id > 0)
			emit_flow_id(e->ipi_send.ipi_id);
		if (e->ipi_send.target_cpu >= 0)
			emit_kv_int(IID_ANNK_TARGET_CPU, "target_cpu", e->ipi_send.target_cpu);
	}

	return 0;
}

/* EV_IPI_EXIT */
static int process_ipi_exit(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!should_trace_task(&e->task))
		return 0;

	(void)task_state(w, &e->task);

	pb_iid name_iid;
	if (e->ipi.kind >= 0 && e->ipi.kind < NR_IPIS)
		name_iid = IID_NAME_IPI + e->ipi.kind;
	else
		name_iid = IID_NAME_IPI + IPI_INVALID;
	const char *name = sfmt("%s:%s", "IPI", ipi_kind_str(e->ipi.kind));

	u64 start_ts = is_ts_in_range(e->ipi.ipi_ts) ? e->ipi.ipi_ts : env.sess_start_ts;
	emit_slice_point(start_ts, &e->task,
			 name_iid, name,
			 IID_CAT_IPI, "IPI", true /* start */) {
		emit_kv_int(IID_ANNK_CPU, "cpu", e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, "numa_node", e->numa_node);
	}
	emit_slice_point(e->ts, &e->task,
			 name_iid, name,
			 IID_CAT_IPI, "IPI", false /* !start */) {
		if (e->ipi.ipi_id > 0)
			emit_flow_id(e->ipi.ipi_id);
		if (e->ipi.send_ts > 0) {
			emit_kv_int(IID_ANNK_SENDER_CPU, "sender_cpu", e->ipi.send_cpu);
			emit_kv_float(IID_ANNK_IPI_DELAY_US, "ipi_delay_us",
				      "%.3lf", (e->ipi.ipi_ts - e->ipi.send_ts) / 1000.0);
		}
		for (int i = 0; i < env.counter_cnt; i++) {
			const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[i]];
			int p = env.counter_pos[i];

			emit_kv_float(def->trace_name_iid, def->trace_name,
				      "%.6lf", e->ipi.ctrs.val[p] * def->mul);
		}
	}

	return 0;
}

/* EV_REQ_EVENT */
static int process_req_event(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!should_trace_task(&e->task))
		return 0;

	const struct wprof_task *t = &e->task;
	struct task_state *st = task_state(w, t);

	u64 req_id = e->req.req_id;
	u64 parent_uuid = track_process_reqs(t);
	u64 req_track_uuid = track_req_process(req_id, t);
	u64 track_uuid = track_req_thread(req_id, t);

	pb_iid req_name_iid = emit_intern_str(w, e->req.req_name);

	switch (e->req.req_event) {
	case REQ_BEGIN:
		emit_track_descr(cur_stream, parent_uuid, TRACK_UUID_REQUESTS,
				 sfmt("%s %u", e->task.pcomm, e->task.pid));
		emit_track_descr(cur_stream, req_track_uuid, parent_uuid,
				 sfmt("REQ:%s (%llu)", e->req.req_name, e->req.req_id));

		emit_track_slice_start(e->ts, req_track_uuid,
				       iid_str(req_name_iid, e->req.req_name),
				       IID_CAT_REQUEST) {
			emit_kv_str2(IID_ANNK_REQ_NAME, iid_str(req_name_iid, e->req.req_name));
			emit_kv_int2(IID_ANNK_REQ_ID, e->req.req_id);
		}

		emit_track_instan2(e->ts, req_track_uuid,
				   IID_NAME_REQUEST_BEGIN, IID_CAT_REQUEST_BEGIN) {
			emit_kv_int2(IID_ANNK_CPU, e->cpu);
			emit_kv_str2(IID_ANNK_REQ_NAME, iid_str(req_name_iid, e->req.req_name));
			emit_kv_int2(IID_ANNK_REQ_ID, e->req.req_id);
		}

		st->req_id = e->req.req_id;
		break;
	case REQ_SET:
		emit_track_instan2(e->ts, req_track_uuid,
				   IID_NAME_REQUEST_SET, IID_CAT_REQUEST_SET) {
			emit_kv_int2(IID_ANNK_CPU, e->cpu);
			emit_kv_str2(IID_ANNK_REQ_NAME, iid_str(req_name_iid, e->req.req_name));
			emit_kv_int2(IID_ANNK_REQ_ID, e->req.req_id);
		}

		emit_track_descr(cur_stream, track_uuid, req_track_uuid,
				 sfmt("%s %u", e->task.comm, e->task.tid));

		emit_track_slice_start(e->ts, track_uuid,
				       iid_str(st->name_iid, st->comm),
				       IID_CAT_REQUEST_THREAD) {
			emit_kv_str2(IID_ANNK_REQ_NAME, iid_str(req_name_iid, e->req.req_name));
			emit_kv_int2(IID_ANNK_REQ_ID, e->req.req_id);
		}

		emit_track_slice_start(e->ts, track_uuid,
				       IID_NAME_RUNNING, IID_CAT_REQUEST_ONCPU);

		st->req_id = e->req.req_id;
		break;
	case REQ_UNSET:
		emit_track_instan2(e->ts, req_track_uuid,
				   IID_NAME_REQUEST_UNSET, IID_CAT_REQUEST_UNSET) {
			emit_kv_int2(IID_ANNK_CPU, e->cpu);
			emit_kv_str2(IID_ANNK_REQ_NAME, iid_str(req_name_iid, e->req.req_name));
			emit_kv_int2(IID_ANNK_REQ_ID, e->req.req_id);
		}

		emit_track_descr(cur_stream, track_uuid, req_track_uuid,
				 sfmt("%s %u", e->task.comm, e->task.tid));

		emit_track_slice_end(e->ts, track_uuid,
				     iid_str(st->name_iid, st->comm),
				     IID_CAT_REQUEST_THREAD);

		emit_track_slice_end(e->ts, track_uuid,
				     IID_NAME_RUNNING, IID_CAT_REQUEST_ONCPU);

		st->req_id = 0;
		break;
	case REQ_CLEAR:
		emit_track_instan2(e->ts, req_track_uuid,
				   IID_NAME_REQUEST_CLEAR, IID_CAT_REQUEST_CLEAR) {
			emit_kv_int2(IID_ANNK_CPU, e->cpu);
			emit_kv_str2(IID_ANNK_REQ_NAME, iid_str(req_name_iid, e->req.req_name));
			emit_kv_int2(IID_ANNK_REQ_ID, e->req.req_id);
		}
		break;
	case REQ_END:
		emit_track_slice_end(e->ts, req_track_uuid,
				     iid_str(req_name_iid, e->req.req_name), IID_CAT_REQUEST) {
			emit_kv_str2(IID_ANNK_REQ_NAME, iid_str(req_name_iid, e->req.req_name));
			emit_kv_int2(IID_ANNK_REQ_ID, e->req.req_id);
			emit_kv_float2(IID_ANNK_REQ_LATENCY_US, "%.6lf", (e->ts - e->req.req_ts) / 1000);
		}

		emit_track_instan2(e->ts, req_track_uuid,
				   IID_NAME_REQUEST_END, IID_CAT_REQUEST_END) {
			emit_kv_int2(IID_ANNK_CPU, e->cpu);
			emit_kv_str2(IID_ANNK_REQ_NAME, iid_str(req_name_iid, e->req.req_name));
			emit_kv_int2(IID_ANNK_REQ_ID, e->req.req_id);
			emit_kv_float2(IID_ANNK_REQ_LATENCY_US, "%.6lf", (e->ts - e->req.req_ts) / 1000);
		}

		emit_track_slice_end(e->ts, track_uuid,
				     IID_NAME_RUNNING, IID_CAT_REQUEST_ONCPU);

		st->req_id = 0;
		break;
	default:
		fprintf(stderr, "UNHANDLED REQ EVENT %d\n", e->req.req_event);
		exit(1);
	}

	return 0;
}

typedef int (*event_fn)(struct worker_state *w, struct wprof_event *e, size_t size);

static event_fn ev_fns[] = {
	[EV_TIMER] = process_timer,
	[EV_SWITCH_FROM] = process_switch_from,
	[EV_SWITCH_TO] = process_switch_to,
	[EV_WAKEUP_NEW] = process_wakeup_new,
	[EV_WAKEUP] = process_wakeup,
	[EV_WAKING] = process_waking,
	[EV_HARDIRQ_EXIT] = process_hardirq_exit,
	[EV_SOFTIRQ_EXIT] = process_softirq_exit,
	[EV_WQ_END] = process_wq_end,
	[EV_FORK] = process_fork,
	[EV_EXEC] = process_exec,
	[EV_TASK_RENAME] = process_task_rename,
	[EV_TASK_EXIT] = process_task_exit,
	[EV_TASK_FREE] = process_task_free,
	[EV_IPI_SEND] = process_ipi_send,
	[EV_IPI_EXIT] = process_ipi_exit,
	[EV_REQ_EVENT] = process_req_event,
};

static int process_event(struct worker_state *w, struct wprof_event *e, size_t size)
{
	event_fn ev_fn;

	if (!is_ts_in_range(e->ts))
		return 0;

	if (e->kind >= ARRAY_SIZE(ev_fns) || !(ev_fn = ev_fns[e->kind])) {
		fprintf(stderr, "UNHANDLED EVENT %d\n", e->kind);
		exit(1);
		return 0;
	}

	return ev_fn(w, e, size);
}

int emit_trace(struct worker_state *w)
{
	int err;

	fprintf(stderr, "Generating trace...\n");
	if (env.capture_stack_traces) {
		err = generate_stack_traces(w);
		if (err) {
			fprintf(stderr, "Failed to append stack traces to trace '%s': %d\n", env.trace_path, err);
			return err;
		}
	}

	if (env.capture_requests)
		emit_track_descr(cur_stream, TRACK_UUID_REQUESTS, 0, "REQUESTS");

	struct wprof_event_record *rec;
	wprof_for_each_event(rec, w->dump_hdr) {
		err = process_event(w, rec->e, rec->sz);
		if (err) {
			fprintf(stderr, "Failed to process event #%d (kind %d, size %zu, offset %zu): %d\n",
				rec->idx, rec->e->kind, rec->sz, (void *)rec->e - (void *)w->dump_hdr, err);
			return err; /* YEAH, I know about all the clean up, whatever */
		}
	}

	return 0;
}
