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
	pb_iid old_name_iid;
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

static __thread struct emit_state em;

__unused
static void __emit_kv_str(struct pb_str key, struct pb_str value)
{
	anns_add_str(&em.anns, key.iid, key.s, value.iid, value.s);
}

#define emit_kv_str(key, value) __emit_kv_str(__pb_str((key)), __pb_str((value)))

__unused
__attribute__((format(printf, 2, 3)))
static void emit_kv_fmt(struct pb_str key, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	anns_add_str(&em.anns, key.iid, key.s, IID_NONE, vsfmt(fmt, ap));

	va_end(ap);
}

__unused
static void __emit_kv_int(struct pb_str key, int64_t value)
{
	anns_add_int(&em.anns, key.iid, key.s, value);
}

#define emit_kv_int(key, value) __emit_kv_int(__pb_str((key)), (value))

__unused
static void __emit_kv_float(struct pb_str key, const char *fmt, double value)
{
	anns_add_double(&em.anns, key.iid, key.s, value);
}

#define emit_kv_float(key, fmt, value) __emit_kv_float(__pb_str((key)), (fmt), (value))

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

enum track_kind {
	TK_THREAD = 1,		/* thread track (by TID) */
	TK_THREAD_IDLE = 2,     /* idle "thread" (by CPU) */
	TK_PROCESS = 2,		/* process track (by PID) */
	TK_SPECIAL = 3,		/* special and fake groups (idle, kthread, kworker, requests folder) */
	TK_PROCESS_REQS = 4,	/* requests of given PID (by PID) */
	TK_REQ = 5,		/* single request of given PID (by REQ_ID + PID) */
	TK_REQ_THREAD = 6,	/* request-participating thread (by REQ_ID + TID) */

	TK_MULT = 10,
};

enum track_special {
	TKS_IDLE = 1,
	TKS_KWORKER = 2,
	TKS_KTHREAD = 3,

	TKS_REQUESTS = 4,
};

#define TRACK_UUID(kind, id) (((u64)(id) * TK_MULT) + (u64)kind)

#define TRACK_UUID_IDLE		TRACK_UUID(TK_SPECIAL, TKS_IDLE)
#define TRACK_UUID_KWORKER	TRACK_UUID(TK_SPECIAL, TKS_KWORKER)
#define TRACK_UUID_KTHREAD	TRACK_UUID(TK_SPECIAL, TKS_KTHREAD)
#define TRACK_UUID_REQUESTS	TRACK_UUID(TK_SPECIAL, TKS_REQUESTS)

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

#define TRACK_PID_IDLE		2000000000ULL
#define TRACK_PID_KWORKER	2000000001ULL
#define TRACK_PID_KTHREAD	2000000002ULL

static int track_pid(const struct wprof_task *t)
{
	enum task_kind kind = task_kind(t);

	switch (kind) {
	case TASK_NORMAL:
		return t->pid;
	case TASK_IDLE:
		return TRACK_PID_IDLE;
	case TASK_KWORKER:
		return TRACK_PID_KWORKER;
	case TASK_KTHREAD:
		return TRACK_PID_KTHREAD;
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
static const u64 kind_track_pid(enum task_kind kind)
{
	switch (kind) {
	case TASK_IDLE:
		return TRACK_PID_IDLE;
	case TASK_KWORKER:
		return TRACK_PID_KWORKER;
	case TASK_KTHREAD:
		return TRACK_PID_KTHREAD;
	default:
		fprintf(stderr, "BUG: unexpected task kind in kind_track_pid(): %d\n", kind);
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

static unsigned long hash_combine(unsigned long h, unsigned long value)
{
	return h * 31 + value;
}

static uint64_t trackid_thread(const struct wprof_task *t)
{
	enum task_kind k = task_kind(t);

	if (k == TASK_IDLE)
		return TRACK_UUID(TK_THREAD_IDLE, track_tid(t));
	else
		return TRACK_UUID(TK_THREAD, track_tid(t));
}

static uint64_t trackid_process(const struct wprof_task *t)
{
	enum task_kind k = task_kind(t);

	if (k == TASK_NORMAL)
		return TRACK_UUID(TK_PROCESS, t->pid);
	else
		return kind_track_uuid(k);
}

static inline u64 trackid_req_thread(u64 req_id, const struct wprof_task *t)
{
	return TRACK_UUID(TK_REQ_THREAD, hash_combine(req_id, t->tid));
}

static inline u64 trackid_req(u64 req_id, const struct wprof_task *t)
{
	return TRACK_UUID(TK_REQ, hash_combine(req_id, t->pid));
}

static inline u64 trackid_process_reqs(const struct wprof_task *t)
{
	return TRACK_UUID(TK_PROCESS_REQS, t->pid);
}

static const char *event_kind_str_map[] = {
	[EV_TIMER] = "TIMER",
	[EV_SWITCH] = "SWITCH",
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
static struct emit_rec emit_instant_pre(u64 ts, __u64 track_uuid,
					struct pb_str name, struct pb_str cat)
{
	em.pb = (TracePacket) {
		PB_INIT(timestamp) = ts - env.sess_start_ts,
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_track_event) = { .track_event = {
			PB_INIT(track_uuid) = track_uuid,
			PB_INIT(type) = perfetto_protos_TrackEvent_Type_TYPE_INSTANT,
			.category_iids = cat.iid ? PB_STRING_IID(cat.iid) : PB_NONE,
			.categories = cat.iid ? PB_NONE : PB_STRING(cat.s),
			PB_NAME(TrackEvent, name_field, name.iid, name.s),
			.debug_annotations = PB_ANNOTATIONS(&em.anns),
		}},
	};
	anns_reset(&em.anns);

	/* ... could have args emitted afterwards */
	return (struct emit_rec){};
}

#define emit_instant(ts, t, name, cat)					\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_instant_pre(ts, trackid_thread(t), __pb_str(name), __pb_str(cat));	\
	     !___r.done; ___r.done = true)

__unused
static struct emit_rec emit_slice_point_pre(u64 ts, u64 track_uuid,
					    struct pb_str name, struct pb_str cat, bool start)
{
	em.pb = (TracePacket) {
		PB_INIT(timestamp) = ts - env.sess_start_ts,
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_track_event) = { .track_event = {
			PB_INIT(track_uuid) = track_uuid,
			PB_INIT(type) = start ? perfetto_protos_TrackEvent_Type_TYPE_SLICE_BEGIN
					      : perfetto_protos_TrackEvent_Type_TYPE_SLICE_END,
			.category_iids = cat.iid ? PB_STRING_IID(cat.iid) : PB_NONE,
			.categories = cat.iid ? PB_NONE : PB_STRING(cat.s),
			PB_NAME(TrackEvent, name_field, name.iid, name.s),
			.debug_annotations = PB_ANNOTATIONS(&em.anns),
		}},
	};
	/* allow explicitly not providing the name */
	if (!name.iid && !name.s)
		em.pb.data.track_event.which_name_field = 0;
	/* end slice points don't need to repeat the name */
	if (!start)
		em.pb.data.track_event.which_name_field = 0;
	anns_reset(&em.anns);

	/* ... could have args emitted afterwards */
	return (struct emit_rec){};
}


static inline struct pb_str __pb_str_literal(const char *str) { return iid_str(0, str); }
static inline struct pb_str __pb_str_iid(enum pb_static_iid iid) { return iid_str(iid, pb_static_str(iid)); }
static inline struct pb_str __pb_str_iidstr(struct pb_str str) { return str; }

#define __pb_str(arg) _Generic((arg),								\
	const char *: __pb_str_literal,								\
	char *: __pb_str_literal,								\
	int: __pb_str_iid,									\
	unsigned int: __pb_str_iid,								\
	struct pb_str: __pb_str_iidstr								\
)((arg))

#define emit_slice_begin(ts, t, name, cat)							\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_slice_point_pre(ts, trackid_thread(t), __pb_str(name), __pb_str(cat), true /*start*/);	\
	     !___r.done; ___r.done = true)

#define emit_slice_end(ts, t, name, cat)							\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_slice_point_pre(ts, trackid_thread(t), __pb_str(name), __pb_str(cat), false /*!start*/);\
	     !___r.done; ___r.done = true)

#define emit_track_slice_start(ts, track, name, cat)						\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_slice_point_pre(ts, track, __pb_str(name), __pb_str(cat), true /*start*/);	\
	     !___r.done; ___r.done = true)

#define emit_track_slice_end(ts, track, name, cat)						\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_slice_point_pre(ts, track, __pb_str(name), __pb_str(cat), false /*!start*/);	\
	     !___r.done; ___r.done = true)

#define emit_track_instant(ts, track, name, cat)						\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_instant_pre(ts, track, __pb_str(name), __pb_str(cat));			\
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
	int track_pid = kind_track_pid(k);

	TracePacket desc_pb = {
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_track_descriptor) = { .track_descriptor = {
			PB_INIT(uuid) = track_uuid,
			PB_INIT(process) = {
				PB_INIT(pid) = track_pid,
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

static void emit_track_descr(pb_ostream_t *stream, __u64 track_uuid, __u64 parent_track_uuid, const char *name, int rank)
{
	TracePacket desc = {
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_track_descriptor) = { .track_descriptor = {
			PB_INIT(uuid) = track_uuid,
			PB_INIT(disallow_merging_with_system_tracks) = false,
			.parent_uuid = parent_track_uuid,
			.has_parent_uuid = parent_track_uuid != 0,
			PB_ONEOF(static_or_dynamic_name, TrackDescriptor_name) = { .name = PB_STRING(name) },
			PB_INIT(child_ordering) = perfetto_protos_TrackDescriptor_ChildTracksOrdering_CHRONOLOGICAL,
			.sibling_order_rank = rank,
			.has_sibling_order_rank = rank != 0,
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
			PB_INIT(uuid) = trackid_process(t),
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
			PB_INIT(uuid) = trackid_thread(t),
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

	if (env.emit_timer_ticks) {
		/* task keeps running on CPU */
		emit_instant(e->ts, &e->task, IID_NAME_TIMER, IID_CAT_TIMER) {
			emit_kv_int(IID_ANNK_CPU, e->cpu);
			if (env.emit_numa)
				emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
		}
	}

	int strace_id = event_stack_trace_id(w, e, size);
	if (strace_id > 0)
		emit_stack_trace(e->ts, &e->task, strace_id);

	return 0;
}

/* EV_SWITCH */
static int process_switch(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (e->swtch.waking_ts == 0 || !is_ts_in_range(e->swtch.waking_ts) ||
	    !should_trace_task(&e->swtch.waker))
		goto skip_waker_task;

	(void)task_state(w, &e->swtch.waker);
	/* event on awaker's timeline */
	emit_instant(e->swtch.waking_ts, &e->swtch.waker,
		     e->swtch.waking_flags == WF_WOKEN_NEW ? IID_NAME_WAKEUP_NEW : IID_NAME_WAKING,
		     e->swtch.waking_flags == WF_WOKEN_NEW ? IID_CAT_WAKEUP_NEW : IID_CAT_WAKING) {
		emit_kv_int(IID_ANNK_CPU, e->swtch.waker_cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->swtch.waker_numa_node);

		emit_kv_str(IID_ANNK_WAKING_TARGET,
			    iid_str(emit_intern_str(w, e->swtch.next.comm), e->swtch.next.comm));
		if (env.emit_tidpid) {
			emit_kv_int(IID_ANNK_WAKING_TARGET_TID, task_tid(&e->swtch.next));
			emit_kv_int(IID_ANNK_WAKING_TARGET_PID, e->swtch.next.pid);
		}

		emit_flow_id(e->swtch.waking_ts);
	}

skip_waker_task:
	if (!should_trace_task(&e->task))
		goto skip_prev_task;

	/* take into account task rename for switched-out task
	 * to maintain consistently named trace slice
	 */
	struct task_state *prev_st = task_state(w, &e->task);
	const char *cur_name = prev_st->rename_ts ? prev_st->old_comm : prev_st->comm;
	pb_iid cur_name_iid = prev_st->rename_ts ? prev_st->old_name_iid : prev_st->name_iid;

	/* We are about to emit SLICE_END without
	 * corresponding SLICE_BEGIN ever being emitted;
	 * normally, Perfetto will just skip such SLICE_END
	 * and won't render anything, which is annoying and
	 * confusing. We want to avoid this, so we'll emit
	 * a fake SLICE_BEGIN with fake timestamp ZERO.
	 */
	if (prev_st->oncpu_ts == 0) {
		emit_slice_begin(env.sess_start_ts, &e->task,
				 iid_str(cur_name_iid, cur_name), IID_CAT_ONCPU) {
			emit_kv_int(IID_ANNK_CPU, e->cpu);
			if (env.emit_numa)
				emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
		}
	}

	emit_slice_end(e->ts, &e->task, iid_str(cur_name_iid, cur_name), IID_CAT_ONCPU) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);

		emit_kv_str(IID_ANNK_SWITCH_TO,
			    iid_str(emit_intern_str(w, e->swtch.next.comm), e->swtch.next.comm));
		if (env.emit_tidpid) {
			emit_kv_int(IID_ANNK_SWITCH_TO_TID, task_tid(&e->swtch.next));
			emit_kv_int(IID_ANNK_SWITCH_TO_PID, e->swtch.next.pid);
		}

		for (int i = 0; i < env.counter_cnt; i++) {
			const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[i]];
			const struct perf_counters *st_ctrs = &prev_st->oncpu_ctrs;
			const struct perf_counters *ev_ctrs = &e->swtch.ctrs;
			int p = env.counter_pos[i];

			if (st_ctrs->val[p] && ev_ctrs->val[p]) {
				emit_kv_float(iid_str(def->trace_name_iid, def->trace_name),
					      "%.6lf", (ev_ctrs->val[p] - st_ctrs->val[p]) * def->mul);
			}
		}

		if (prev_st->rename_ts)
			emit_kv_str(IID_ANNK_RENAMED_TO, e->task.comm);
	}

	int strace_id = event_stack_trace_id(w, e, size);
	if (strace_id > 0)
		emit_stack_trace(e->ts, &e->task, strace_id);

	bool preempted = e->swtch.prev_task_state == TASK_RUNNING;

	if (prev_st->req_id) {
		emit_track_slice_end(e->ts, trackid_req_thread(prev_st->req_id, &e->task),
				     IID_NAME_RUNNING, IID_CAT_REQUEST_ONCPU);
		emit_track_slice_start(e->ts, trackid_req_thread(prev_st->req_id, &e->task),
				       preempted ? IID_NAME_PREEMPTED : IID_NAME_WAITING,
				       IID_CAT_REQUEST_OFFCPU);
	}

	if (prev_st->rename_ts)
		prev_st->rename_ts = 0;

	/* reset perf counters */
	memset(&prev_st->oncpu_ctrs, 0, sizeof(struct perf_counters));
	prev_st->oncpu_ts = 0;
	prev_st->run_state = preempted ? TASK_STATE_PREEMPTED : TASK_STATE_WAITING;

skip_prev_task:
	if (!should_trace_task(&e->swtch.next))
		goto skip_next_task;

	struct task_state *next_st = task_state(w, &e->swtch.next);
	next_st->oncpu_ctrs = e->swtch.ctrs;
	next_st->oncpu_ts = e->ts;

	if (e->swtch.waking_ts && is_ts_in_range(e->swtch.waking_ts) && e->swtch.waker_cpu != e->cpu) {
		/* event on awoken's timeline */
		emit_instant(e->swtch.waking_ts, &e->swtch.next,
			     e->swtch.waking_flags == WF_WOKEN_NEW ? IID_NAME_WOKEN_NEW : IID_NAME_WOKEN,
			     e->swtch.waking_flags == WF_WOKEN_NEW ? IID_CAT_WOKEN_NEW : IID_CAT_WOKEN) {
			emit_kv_int(IID_ANNK_CPU, e->cpu);
			if (env.emit_numa)
				emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);

			emit_flow_id(e->swtch.waking_ts);
		}
	}

	emit_slice_begin(e->ts, &e->swtch.next, iid_str(next_st->name_iid, e->swtch.next.comm), IID_CAT_ONCPU) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);

		if (e->swtch.waking_ts) {
			emit_kv_str(IID_ANNK_WAKING_BY,
				    iid_str(emit_intern_str(w, e->swtch.waker.comm), e->swtch.waker.comm));
			if (env.emit_tidpid) {
				emit_kv_int(IID_ANNK_WAKING_BY_TID, task_tid(&e->swtch.waker));
				emit_kv_int(IID_ANNK_WAKING_BY_PID, e->swtch.waker.pid);
			}
			emit_kv_str(IID_ANNK_WAKING_REASON,
				    IID_ANNV_WAKING_REASON + wreason_enum(e->swtch.waking_flags));
			emit_kv_int(IID_ANNK_WAKING_CPU, e->swtch.waker_cpu);
			if (env.emit_numa)
				emit_kv_int(IID_ANNK_WAKING_NUMA_NODE, e->swtch.waker_numa_node);
			emit_kv_float(IID_ANNK_WAKING_DELAY_US, "%.3lf", (e->ts - e->swtch.waking_ts) / 1000.0);
		}

		emit_kv_str(IID_ANNK_SWITCH_FROM,
			    iid_str(emit_intern_str(w, e->task.comm), e->task.comm));
		if (env.emit_tidpid) {
			emit_kv_int(IID_ANNK_SWITCH_FROM_TID, task_tid(&e->task));
			emit_kv_int(IID_ANNK_SWITCH_FROM_PID, e->task.pid);
		}

		if (env.capture_scx_layer_info && e->swtch.next_task_scx_layer_id >= 0) {
			emit_kv_int(IID_ANNK_SCX_LAYER_ID, e->swtch.next_task_scx_layer_id);
			emit_kv_int(IID_ANNK_SCX_DSQ_ID, e->swtch.next_task_scx_dsq_id);
		}

		if (e->swtch.waking_ts && is_ts_in_range(e->swtch.waking_ts))
			emit_flow_id(e->swtch.waking_ts);
	}

	if (next_st->req_id) {
		bool was_preempted = e->swtch.last_next_task_state == TASK_RUNNING;
		emit_track_slice_end(e->ts, trackid_req_thread(next_st->req_id, &e->swtch.next),
				     was_preempted ? IID_NAME_PREEMPTED : IID_NAME_WAITING,
				     IID_CAT_REQUEST_OFFCPU);
		emit_track_slice_start(e->ts, trackid_req_thread(next_st->req_id, &e->swtch.next),
				       IID_NAME_RUNNING, IID_CAT_REQUEST_ONCPU);
	}

	next_st->run_state = TASK_STATE_RUNNING;

skip_next_task:
	return 0;
}

/* EV_FORK */
static int process_fork(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (should_trace_task(&e->task)) {
		(void)task_state(w, &e->task);

		emit_instant(e->ts, &e->task, IID_NAME_FORKING, IID_CAT_FORKING) {
			emit_kv_int(IID_ANNK_CPU, e->cpu);
			if (env.emit_numa)
				emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);

			emit_kv_str(IID_ANNK_FORKED_INTO,
				    iid_str(emit_intern_str(w, e->fork.child.comm), e->fork.child.comm));
			emit_flow_id(e->ts);
			if (env.emit_tidpid) {
				emit_kv_int(IID_ANNK_FORKED_INTO_TID, task_tid(&e->fork.child));
				emit_kv_int(IID_ANNK_FORKED_INTO_PID, e->fork.child.pid);
			}
		}
	}

	if (should_trace_task(&e->fork.child)) {
		(void)task_state(w, &e->fork.child);

		emit_instant(e->ts, &e->fork.child, IID_NAME_FORKED, IID_CAT_FORKED) {
			emit_kv_int(IID_ANNK_CPU, e->cpu);
			if (env.emit_numa)
				emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);

			emit_kv_str(IID_ANNK_FORKED_FROM,
				    iid_str(emit_intern_str(w, e->task.comm), e->task.comm));
			emit_flow_id(e->ts);
			if (env.emit_tidpid) {
				emit_kv_int(IID_ANNK_FORKED_FROM_TID, task_tid(&e->task));
				emit_kv_int(IID_ANNK_FORKED_FROM_PID, e->task.pid);
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

	emit_instant(e->ts, &e->task, IID_NAME_EXEC, IID_CAT_EXEC) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);

		emit_kv_str(IID_ANNK_FILENAME, e->exec.filename);
		if (e->task.tid != e->exec.old_tid)
			emit_kv_int(IID_ANNK_TID_CHANGED_FROM, e->exec.old_tid);
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
		st->old_name_iid = st->name_iid;
	}
	memcpy(st->comm, e->rename.new_comm, sizeof(st->comm));
	st->name_iid = emit_intern_str(w, e->rename.new_comm);

	emit_instant(e->ts, &e->task, IID_NAME_RENAME, IID_CAT_RENAME) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);

		emit_kv_str(IID_ANNK_OLD_NAME, e->task.comm);
		emit_kv_str(IID_ANNK_NEW_NAME, e->rename.new_comm);
	}

	emit_thread_track_descr(&w->stream, &e->task, e->rename.new_comm);

	return 0;
}

/* EV_TASK_EXIT */
static int process_task_exit(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!should_trace_task(&e->task))
		return 0;

	(void)task_state(w, &e->task);

	emit_instant(e->ts, &e->task, IID_NAME_EXIT, IID_CAT_EXIT) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
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

	emit_instant(e->ts, &e->task, IID_NAME_FREE, IID_CAT_FREE) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
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

	emit_instant(e->ts, &e->task, IID_NAME_WAKEUP, IID_CAT_WAKEUP) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
	}

	return 0;
}

/* EV_WAKEUP_NEW */
static int process_wakeup_new(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!should_trace_task(&e->task))
		return 0;

	(void)task_state(w, &e->task);

	emit_instant(e->ts, &e->task, IID_NAME_WAKEUP_NEW, IID_CAT_WAKEUP_NEW) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
	}

	return 0;
}

/* EV_WAKING */
static int process_waking(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!should_trace_task(&e->task))
		return 0;

	(void)task_state(w, &e->task);

	emit_instant(e->ts, &e->task, IID_NAME_WAKING, IID_CAT_WAKING) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
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
	emit_slice_begin(start_ts, &e->task, IID_NAME_HARDIRQ, IID_CAT_HARDIRQ) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
		emit_kv_int(IID_ANNK_IRQ, e->hardirq.irq);
		emit_kv_str(IID_ANNK_ACTION, e->hardirq.name);
	}
	emit_slice_end(e->ts, &e->task, IID_NAME_HARDIRQ, IID_CAT_HARDIRQ) {
		for (int i = 0; i < env.counter_cnt; i++) {
			const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[i]];
			int p = env.counter_pos[i];

			emit_kv_float(iid_str(def->trace_name_iid, def->trace_name),
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
	emit_slice_begin(start_ts, &e->task,
			     iid_str(name_iid, sfmt("%s:%s", "SOFTIRQ", softirq_str(e->softirq.vec_nr))),
			     IID_CAT_SOFTIRQ) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
		emit_kv_str(IID_ANNK_ACTION, iid_str(act_iid, softirq_str(e->softirq.vec_nr)));
	}

	emit_slice_end(e->ts, &e->task,
		       iid_str(name_iid, sfmt("%s:%s", "SOFTIRQ", softirq_str(e->softirq.vec_nr))),
		       IID_CAT_SOFTIRQ) {
		for (int i = 0; i < env.counter_cnt; i++) {
			const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[i]];
			int p = env.counter_pos[i];

			emit_kv_float(iid_str(def->trace_name_iid, def->trace_name),
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
	emit_slice_begin(start_ts, &e->task,
			 iid_str(IID_NONE, sfmt("%s:%s", "WQ", e->wq.desc)),
			 IID_CAT_WQ) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
		emit_kv_str(IID_ANNK_ACTION, e->wq.desc);
	}
	emit_slice_end(e->ts, &e->task,
		       iid_str(IID_NONE, sfmt("%s:%s", "WQ", e->wq.desc)),
		       IID_CAT_WQ) {
		for (int i = 0; i < env.counter_cnt; i++) {
			const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[i]];
			int p = env.counter_pos[i];

			emit_kv_float(iid_str(def->trace_name_iid, def->trace_name),
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

	emit_instant(e->ts, &e->task, iid_str(name_iid, name), IID_CAT_IPI_SEND) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
		if (e->ipi_send.ipi_id > 0)
			emit_flow_id(e->ipi_send.ipi_id);
		if (e->ipi_send.target_cpu >= 0)
			emit_kv_int(IID_ANNK_TARGET_CPU, e->ipi_send.target_cpu);
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
	emit_slice_begin(start_ts, &e->task, iid_str(name_iid, name), IID_CAT_IPI) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
	}
	emit_slice_end(e->ts, &e->task, iid_str(name_iid, name), IID_CAT_IPI) {
		if (e->ipi.ipi_id > 0)
			emit_flow_id(e->ipi.ipi_id);
		if (e->ipi.send_ts > 0) {
			emit_kv_int(IID_ANNK_SENDER_CPU, e->ipi.send_cpu);
			emit_kv_float(IID_ANNK_IPI_DELAY_US,
				      "%.3lf", (e->ipi.ipi_ts - e->ipi.send_ts) / 1000.0);
		}
		for (int i = 0; i < env.counter_cnt; i++) {
			const struct perf_counter_def *def = &perf_counter_defs[env.counter_ids[i]];
			int p = env.counter_pos[i];

			emit_kv_float(iid_str(def->trace_name_iid, def->trace_name),
				      "%.6lf", e->ipi.ctrs.val[p] * def->mul);
		}
	}

	return 0;
}

/* EV_REQ_EVENT */
static int process_req_event(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!env.capture_requests)
		return 0;
	if (!should_trace_task(&e->task))
		return 0;

	const struct wprof_task *t = &e->task;
	struct task_state *st = task_state(w, t);

	u64 req_id = e->req.req_id;
	u64 parent_uuid = trackid_process_reqs(t);
	u64 req_track_uuid = trackid_req(req_id, t);
	u64 track_uuid = trackid_req_thread(req_id, t);

	pb_iid req_name_iid = emit_intern_str(w, e->req.req_name);

	switch (e->req.req_event) {
	case REQ_BEGIN:
		emit_track_descr(cur_stream, parent_uuid, TRACK_UUID_REQUESTS,
				 sfmt("%s %u", e->task.pcomm, e->task.pid), 0);
		emit_track_descr(cur_stream, req_track_uuid, parent_uuid,
				 sfmt("REQ:%s (%llu)", e->req.req_name, e->req.req_id), 0);

		emit_track_slice_start(e->ts, req_track_uuid,
				       iid_str(req_name_iid, e->req.req_name),
				       IID_CAT_REQUEST) {
			emit_kv_str(IID_ANNK_REQ_NAME, iid_str(req_name_iid, e->req.req_name));
			emit_kv_int(IID_ANNK_REQ_ID, e->req.req_id);
		}

		if (env.emit_req_extras) {
			emit_track_instant(e->ts, track_uuid,
					   IID_NAME_REQUEST_BEGIN, IID_CAT_REQUEST_BEGIN) {
				emit_kv_int(IID_ANNK_CPU, e->cpu);
				emit_kv_str(IID_ANNK_REQ_NAME, iid_str(req_name_iid, e->req.req_name));
				emit_kv_int(IID_ANNK_REQ_ID, e->req.req_id);
			}
		}

		st->req_id = e->req.req_id;
		break;
	case REQ_SET:
		emit_track_descr(cur_stream, track_uuid, req_track_uuid,
				 sfmt("%s %u", e->task.comm, e->task.tid), 0);

		emit_track_slice_start(e->ts, track_uuid,
				       iid_str(st->name_iid, st->comm),
				       IID_CAT_REQUEST_THREAD) {
			emit_kv_str(IID_ANNK_REQ_NAME, iid_str(req_name_iid, e->req.req_name));
			emit_kv_int(IID_ANNK_REQ_ID, e->req.req_id);
		}

		emit_track_slice_start(e->ts, track_uuid,
				       IID_NAME_RUNNING, IID_CAT_REQUEST_ONCPU);

		if (env.emit_req_extras) {
			emit_track_instant(e->ts, track_uuid,
					   IID_NAME_REQUEST_SET, IID_CAT_REQUEST_SET) {
				emit_kv_int(IID_ANNK_CPU, e->cpu);
				emit_kv_str(IID_ANNK_REQ_NAME, iid_str(req_name_iid, e->req.req_name));
				emit_kv_int(IID_ANNK_REQ_ID, e->req.req_id);
			}
		}

		st->req_id = e->req.req_id;
		break;
	case REQ_UNSET:
		if (env.emit_req_extras) {
			emit_track_instant(e->ts, track_uuid,
					   IID_NAME_REQUEST_UNSET, IID_CAT_REQUEST_UNSET) {
				emit_kv_int(IID_ANNK_CPU, e->cpu);
				emit_kv_str(IID_ANNK_REQ_NAME, iid_str(req_name_iid, e->req.req_name));
				emit_kv_int(IID_ANNK_REQ_ID, e->req.req_id);
			}
		}

		emit_track_slice_end(e->ts, track_uuid,
				     iid_str(st->name_iid, st->comm),
				     IID_CAT_REQUEST_THREAD);

		emit_track_slice_end(e->ts, track_uuid,
				     IID_NAME_RUNNING, IID_CAT_REQUEST_ONCPU);

		st->req_id = 0;
		break;
	case REQ_CLEAR:
		/* don't care */
		break;
	case REQ_END:
		emit_track_slice_end(e->ts, req_track_uuid,
				     iid_str(req_name_iid, e->req.req_name), IID_CAT_REQUEST) {
			emit_kv_str(IID_ANNK_REQ_NAME, iid_str(req_name_iid, e->req.req_name));
			emit_kv_int(IID_ANNK_REQ_ID, e->req.req_id);
			emit_kv_float(IID_ANNK_REQ_LATENCY_US, "%.6lf", (e->ts - e->req.req_ts) / 1000);
		}
		emit_track_slice_end(e->ts, track_uuid,
				     IID_NAME_RUNNING, IID_CAT_REQUEST_ONCPU);

		if (env.emit_req_extras) {
			emit_track_instant(e->ts, track_uuid,
					   IID_NAME_REQUEST_END, IID_CAT_REQUEST_END) {
				emit_kv_int(IID_ANNK_CPU, e->cpu);
				emit_kv_str(IID_ANNK_REQ_NAME, iid_str(req_name_iid, e->req.req_name));
				emit_kv_int(IID_ANNK_REQ_ID, e->req.req_id);
				emit_kv_float(IID_ANNK_REQ_LATENCY_US, "%.6lf", (e->ts - e->req.req_ts) / 1000);
			}
		}

		st->req_id = 0;
		break;
	default:
		fprintf(stderr, "UNHANDLED REQ EVENT %d\n", e->req.req_event);
		exit(1);
	}

	return 0;
}

/* EV_REQ_TASK_EVENT */
static int process_req_task_event(struct worker_state *w, struct wprof_event *e, size_t size)
{
	if (!env.capture_req_experimental)
		return 0;
	if (!should_trace_task(&e->task))
		return 0;

	const struct wprof_task *t = &e->task;

	u64 req_id = e->req_task.req_id;
	u64 parent_uuid = trackid_process_reqs(t);
	u64 req_track_uuid = trackid_req(req_id, t);
	u64 track_uuid = trackid_req_thread(req_id, t);

	emit_track_descr(cur_stream, parent_uuid, TRACK_UUID_REQUESTS,
			 sfmt("%s %u", e->task.pcomm, e->task.pid), 0);
	emit_track_descr(cur_stream, req_track_uuid, parent_uuid,
			 sfmt("REQ (%llu)", e->req_task.req_id), 0);
	emit_track_descr(cur_stream, track_uuid, req_track_uuid,
			 sfmt("%s %u", e->task.comm, e->task.tid), 0);

	switch (e->req_task.req_task_event) {
	case REQ_TASK_ENQUEUE:
		emit_track_instant(e->ts, track_uuid,
				   IID_NAME_REQUEST_TASK_ENQUEUE, IID_CAT_REQUEST_TASK_ENQUEUE) {
			emit_kv_int(IID_ANNK_REQ_ID, e->req_task.req_id);
			emit_kv_int(IID_ANNK_REQ_TASK_ID, e->req_task.task_id);
			//emit_kv_int("enqueue_ts", e->req_task.enqueue_ts);

			u64 flow_id = hash_combine(e->req_task.req_id, hash_combine(e->req_task.task_id, e->req_task.enqueue_ts));
			emit_flow_id(flow_id);
		}
		break;
	case REQ_TASK_DEQUEUE:
		emit_track_instant(e->ts, track_uuid,
				   IID_NAME_REQUEST_TASK_DEQUEUE, IID_CAT_REQUEST_TASK_DEQUEUE) {
			emit_kv_int(IID_ANNK_REQ_ID, e->req_task.req_id);
			emit_kv_int(IID_ANNK_REQ_TASK_ID, e->req_task.task_id);
			emit_kv_int(IID_ANNK_REQ_WAIT_TIME_NS, e->req_task.wait_time_ns);
			//emit_kv_int("enqueue_ts", e->req_task.enqueue_ts);

			u64 flow_id = hash_combine(e->req_task.req_id, hash_combine(e->req_task.task_id, e->req_task.enqueue_ts));
			emit_flow_id(flow_id);
		}
		break;
	case REQ_TASK_STATS:
		emit_track_instant(e->ts, track_uuid,
				   IID_NAME_REQUEST_TASK_COMPLETE, IID_CAT_REQUEST_TASK_COMPLETE) {
			emit_kv_int(IID_ANNK_REQ_ID, e->req_task.req_id);
			emit_kv_int(IID_ANNK_REQ_TASK_ID, e->req_task.task_id);
			emit_kv_int(IID_ANNK_REQ_WAIT_TIME_NS, e->req_task.wait_time_ns);
			//emit_kv_int("enqueue_ts", e->req_task.enqueue_ts);
			//emit_kv_int("run_time_ns", e->req_task.run_time_ns);

			u64 flow_id = hash_combine(e->req_task.req_id, hash_combine(e->req_task.task_id, e->req_task.enqueue_ts));
			emit_flow_id(flow_id);
		}
		break;
	default:
		fprintf(stderr, "UNHANDLED REQ TASK EVENT %d\n", e->req_task.req_task_event);
		exit(1);
	}

	return 0;
}

typedef int (*event_fn)(struct worker_state *w, struct wprof_event *e, size_t size);

static event_fn ev_fns[] = {
	[EV_TIMER] = process_timer,
	[EV_SWITCH] = process_switch,
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
	[EV_REQ_TASK_EVENT] = process_req_task_event,
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
		emit_track_descr(cur_stream, TRACK_UUID_REQUESTS, 0, "REQUESTS", 1000);

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
