// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#include "wevent.h"
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include "hashmap.h"
#include "utils.h"
#include "protobuf.h"
#include "wprof.h"
#include "data.h"
#include "env.h"
#include "stacktrace.h"
#include "cuda_data.h"
#include "wprof_cupti.h"
#include "demangle.h"

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
	u64 offcpu_ts;
	u64 req_id; /* active ongoing request ID */
	u32 waker_callstack_id;
	/* perf counters */
	const u64 *oncpu_ctrs;
	u64 compound_delay_ns; /* scheduling/running delay, including dependency tasks' ones */
	u64 compound_chain_len; /* length of continuous waker-wakee chain */
};

static struct hashmap *tasks;
static __thread pb_ostream_t *cur_stream;

enum track_kind {
	TK_THREAD = 1,		/* thread track (by TID) */
	TK_THREAD_IDLE = 2,     /* idle "thread" (by CPU) */
	TK_PROCESS = 2,		/* process track (by PID) */
	TK_SPECIAL = 3,		/* special and fake groups (idle, kthread, kworker, requests folder) */

	TK_PROC_REQS = 4,	/* requests of given PID (by PID) */
	TK_REQ = 5,		/* single request of given PID (by REQ_ID + PID) */
	TK_REQ_THREAD = 6,	/* request-participating thread (by REQ_ID + TID) */

	TK_CUDA_PROC = 7, 	/* CUDA-using process track (by PID) */
	TK_CUDA_PROC_GPU = 8, 	/* CUDA-using process's GPU track (by PID + GPU ID) */
	TK_CUDA_PROC_STREAM = 9,/* CUDA-using process's GPU stream track (by PID + CUDA stream ID) */

	TK_MULT = 10,
};

enum track_special {
	TKS_IDLE = 1,
	TKS_KWORKER = 2,
	TKS_KTHREAD = 3,

	TKS_REQUESTS = 4,
	TKS_CUDA = 5,
};

#define TRACK_UUID(kind, id) (((u64)(id) * TK_MULT) + (u64)kind)

#define TRACK_UUID_IDLE		TRACK_UUID(TK_SPECIAL, TKS_IDLE)
#define TRACK_UUID_KWORKER	TRACK_UUID(TK_SPECIAL, TKS_KWORKER)
#define TRACK_UUID_KTHREAD	TRACK_UUID(TK_SPECIAL, TKS_KTHREAD)
#define TRACK_UUID_REQUESTS	TRACK_UUID(TK_SPECIAL, TKS_REQUESTS)
#define TRACK_UUID_CUDA		TRACK_UUID(TK_SPECIAL, TKS_CUDA)

struct track_key {
	enum track_kind kind;
	u32 id1;
	u64 id2;
};

struct track_state {
	bool exists;
};

static inline size_t track_hash_fn(long key, void *ctx)
{
	struct track_key *p = (void *)key;

	return hash_combine(((u64)p->kind << 32) | p->id1, p->id2);
}

static inline bool track_equal_fn(long k1, long k2, void *ctx)
{
	struct track_key *p1 = (void *)k1;
	struct track_key *p2 = (void *)k2;

	return p1->kind == p2->kind &&
	       p1->id1 == p2->id1 &&
	       p1->id2 == p2->id2;
}

static struct hashmap *tracks;

static inline struct track_key track_key(enum track_kind kind, u32 id1, u64 id2)
{
	return (struct track_key) { .kind = kind, .id1 = id1, .id2 = id2 };
}

static struct track_state *track_state_get_or_add(enum track_kind kind, u32 id1, u64 id2)
{
	struct track_key k = track_key(kind, id1, id2);
	struct track_state *s;

	if (hashmap__find(tracks, &k, &s))
		return s;

	struct track_key *pk = calloc(1, sizeof(struct track_key));
	struct track_state *ps = calloc(1, sizeof(struct track_state));

	*pk = k;
	hashmap__add(tracks, pk, ps);

	return ps;
}

static struct track_state *track_state_find(enum track_kind kind, u32 id1, u64 id2)
{
	struct track_key k = track_key(kind, id1, id2);
	struct track_state *s;

	if (hashmap__find(tracks, &k, &s))
		return s;

	return NULL;
}

static bool track_state_delete(enum track_kind kind, u32 id1, u64 id2)
{
	struct track_key k = track_key(kind, id1, id2);
	struct track_key *old_k;
	struct track_state *old_s;

	if (hashmap__delete(tracks, &k, &old_k, &old_s)) {
		free(old_k);
		free(old_s);
		return true;
	}

	return false;
}

static struct hashmap *cuda_corrs;

static inline u64 cuda_corr_key(u32 pid, u32 corr_id)
{
	return ((u64)pid << 32) | corr_id;
}

struct cuda_corr_info {
	u64 api_ts;
};

static struct cuda_corr_info *cuda_corr_get(u32 pid, u32 corr_id)
{
	u64 key = cuda_corr_key(pid, corr_id);
	struct cuda_corr_info *info;

	if (hashmap__find(cuda_corrs, key, &info))
		return info;

	info = calloc(1, sizeof(*info));
	hashmap__set(cuda_corrs, key, info, NULL, NULL);

	return info;
}

static struct cuda_corr_info *cuda_corr_pop(u32 pid, u32 corr_id)
{
	u64 key = cuda_corr_key(pid, corr_id);
	struct cuda_corr_info *info;

	if (hashmap__delete(cuda_corrs, key, NULL, &info))
		return info;

	return NULL;
}

int init_emit(struct worker_state *w)
{
	tasks = hashmap__new(hash_identity_fn, hash_equal_fn, NULL);
	if (!tasks)
		return -ENOMEM;

	tracks = hashmap__new(track_hash_fn, track_equal_fn, NULL);
	if (!tracks)
		return -ENOMEM;

	cuda_corrs = hashmap__new(hash_identity_fn, hash_equal_fn, NULL);
	if (!cuda_corrs)
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
	struct pb_id_set flow_ids;
	int callstack_iid;
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
	ids_append_id(&em.flow_ids, flow_id);
}

__unused
static void emit_callstack(struct worker_state *w, int iid)
{
	if (iid <= 0)
		return;
	mark_stack_trace_used(w, iid);
	em.callstack_iid = iid;
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
			eprintf("BUG: interned_data.event_names is already set!\n");
			exit(1);
		}
		if (pb->has_interned_data && pb->interned_data.debug_annotation_string_values.funcs.encode) {
			eprintf("BUG: interned_data.debug_annotation_string_values is already set!\n");
			exit(1);
		}
		if (pb->has_interned_data && pb->interned_data.debug_annotation_names.funcs.encode) {
			eprintf("BUG: interned_data.debug_annotation_names is already set!\n");
			exit(1);
		}
		pb->has_interned_data = true;
		pb->interned_data.event_names = PB_STR_IIDS(&em.str_iids);
		pb->interned_data.debug_annotation_string_values = PB_STR_IIDS(&em.str_iids);
		/* The event would disappear in perfetto UI without debug_annotation_names */
		pb->interned_data.debug_annotation_names = PB_STR_IIDS(&em.str_iids);
	}

	if (em.flow_ids.cnt > 0)
		pb->data.track_event.flow_ids = PB_FLOW_IDS(&em.flow_ids);

	if (em.callstack_iid > 0) {
		pb->data.track_event.which_callstack_field = perfetto_protos_TrackEvent_callstack_iid_tag;
		pb->data.track_event.callstack_field.callstack_iid = em.callstack_iid;
	}

	enc_trace_packet(stream, pb);

	reset_str_iids(&em.str_iids);
	ids_reset(&em.flow_ids);
	em.callstack_iid = 0;
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
	/*
	 * Even though it would be natural to assing TID 0 to swapper/0, this
	 * interferes with native ftrace scheduler view of Perfetto, so we
	 * need to avoid having any thread with TID 0, so swapper/N have N+1
	 * TID...
	 */
	return t->pid ? t->tid : -t->tid;
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
		eprintf("BUG: unexpected task kind in track_pid(): %d\n", kind);
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
		eprintf("BUG: unexpected task kind in track_process_rank(): %d\n", kind);
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
		eprintf("BUG: unexpected task kind in track_pcomm(): %d\n", kind);
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
		eprintf("BUG: unexpected task kind in kind_track_uuid(): %d\n", kind);
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
		eprintf("BUG: unexpected task kind in kind_track_pid(): %d\n", kind);
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
		eprintf("BUG: unexpected task kind in kind_track_name(): %d\n", kind);
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
		eprintf("BUG: unexpected task kind in kind_track_rank(): %d\n", kind);
		exit(1);
	}
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
	return TRACK_UUID(TK_PROC_REQS, t->pid);
}

static inline u64 trackid_cuda_proc(int pid)
{
	return TRACK_UUID(TK_CUDA_PROC, pid);
}

static inline u64 trackid_cuda_proc_gpu(int pid, u32 dev_id)
{
	return TRACK_UUID(TK_CUDA_PROC_GPU, pid | ((u64)dev_id << 32));
}

static inline u64 trackid_cuda_proc_stream(int pid, u32 stream_id)
{
	return TRACK_UUID(TK_CUDA_PROC_STREAM, pid | ((u64)stream_id << 32));
}

static const char *event_kind_str_map[] = {
	/* BPF-produced events */
	[EV_TIMER] = "TIMER",
	[EV_SWITCH] = "SWITCH",
	[EV_WAKEUP_NEW] = "WAKEUP_NEW",
	//[EV_WAKEUP] = "WAKEUP",
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
	[EV_SCX_DSQ_END] = "SCX_DSQ_END",

	/* CUDA/CUPTI-produced events */
	[EV_CUDA_KERNEL] = "CUDA_KERNEL",
	[EV_CUDA_MEMCPY] = "CUDA_MEMCPY",
	[EV_CUDA_MEMSET] = "CUDA_MEMSET",
	[EV_CUDA_SYNC] = "CUDA_SYNC",
	[EV_CUDA_API] = "CUDA_API",
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

enum emit_flags {
	EM_START = 0x01,
	EM_END = 0x02,
	EM_THREAD = 0x04, /* thread-associated */
};

__unused
static struct emit_rec emit_instant_pre(u64 ts, __u64 track_uuid,
					struct pb_str name, struct pb_str cat,
					enum emit_flags flags)
{
	em.pb = (TracePacket) {
		PB_INIT(timestamp) = ts - env.sess_start_ts,
		PB_TRUST_SEQ_ID((flags & EM_THREAD) ? PB_SEQ_ID_THREADS : PB_SEQ_ID_GENERIC),
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
	     emit_instant_pre(ts, trackid_thread(t), __pb_str(name), __pb_str(cat), EM_THREAD);	\
	     !___r.done; ___r.done = true)

__unused
static struct emit_rec emit_slice_point_pre(u64 ts, u64 track_uuid,
					    struct pb_str name, struct pb_str cat,
					    enum emit_flags flags)
{
	em.pb = (TracePacket) {
		PB_INIT(timestamp) = ts - env.sess_start_ts,
		PB_TRUST_SEQ_ID((flags & EM_THREAD) ? PB_SEQ_ID_THREADS : PB_SEQ_ID_GENERIC),
		PB_ONEOF(data, TracePacket_track_event) = { .track_event = {
			PB_INIT(track_uuid) = track_uuid,
			PB_INIT(type) = (flags & EM_END)
				? perfetto_protos_TrackEvent_Type_TYPE_SLICE_END
				: perfetto_protos_TrackEvent_Type_TYPE_SLICE_BEGIN,
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
	if (flags & EM_END)
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
	     emit_slice_point_pre(ts, trackid_thread(t), __pb_str(name), __pb_str(cat), 	\
				  EM_START | EM_THREAD);					\
	     !___r.done; ___r.done = true)

#define emit_slice_end(ts, t, name, cat)							\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_slice_point_pre(ts, trackid_thread(t), __pb_str(name), __pb_str(cat), 	\
				  EM_END | EM_THREAD); 						\
	     !___r.done; ___r.done = true)

#define emit_track_slice_start(ts, track, name, cat)						\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_slice_point_pre(ts, track, __pb_str(name), __pb_str(cat), EM_START);		\
	     !___r.done; ___r.done = true)

#define emit_track_slice_end(ts, track, name, cat)						\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_slice_point_pre(ts, track, __pb_str(name), __pb_str(cat), EM_END);		\
	     !___r.done; ___r.done = true)

#define emit_track_instant(ts, track, name, cat)						\
	for (struct emit_rec ___r __cleanup(emit_cleanup) =					\
	     emit_instant_pre(ts, track, __pb_str(name), __pb_str(cat), 0);			\
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
	int track_pid = kind_track_pid(k);

	TracePacket desc_pb = {
		PB_TRUST_SEQ_ID(PB_SEQ_ID_THREADS),
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
		PB_TRUST_SEQ_ID(PB_SEQ_ID_GENERIC),
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
		PB_TRUST_SEQ_ID(PB_SEQ_ID_THREADS),
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
		PB_TRUST_SEQ_ID(PB_SEQ_ID_THREADS),
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

static void emit_pmu_intern_names(struct worker_state *w, pb_ostream_t *stream)
{
	if (env.pmu_real_cnt + env.pmu_deriv_cnt == 0)
		return;

	struct pb_str_iids iids = {};
	char buf[256];
	const char *s;

	for (int i = 0; i < env.pmu_real_cnt; i++) {
		struct pmu_event *pmu = &env.pmu_reals[i];
		snprintf(buf, sizeof(buf), "pmu:%s", pmu->name);
		pmu->name_iid = str_iid_for(&w->name_iids, buf, NULL, &s);
		append_str_iid(&iids, pmu->name_iid, s);
	}
	for (int i = 0; i < env.pmu_deriv_cnt; i++) {
		struct pmu_event *pmu = &env.pmu_derivs[i];
		snprintf(buf, sizeof(buf), "pmu:%s", pmu->name);
		pmu->name_iid = str_iid_for(&w->name_iids, buf, NULL, &s);
		append_str_iid(&iids, pmu->name_iid, s);
	}

	TracePacket pkt = {
		PB_INIT(timestamp) = 0,
		PB_TRUST_SEQ_ID(PB_SEQ_ID_THREADS),
		PB_INIT(interned_data) = {
			.event_names = PB_STR_IIDS(&iids),
			.debug_annotation_names = PB_STR_IIDS(&iids),
			.debug_annotation_string_values = PB_STR_IIDS(&iids),
		},
	};
	enc_trace_packet(stream, &pkt);

	free(iids.iids);
	free(iids.strs);
}

/**
 * emit_perf_counters - Emit perf counter with derived metrics support
 * @st_ctrs: start counter value (may be null)
 * @ev_ctrs: end counter value (may be null)
 *
 * Context switch has a pair of values, the rest of entries (e.g. ipi, wq) have just one perf
 * value. For the latter case, diffs should be set to true and ev_ctrs used for final values.
 */
static void emit_perf_counters(const u64 *st_ctrs, const u64 *ev_ctrs, bool diffs)
{
	if (!ev_ctrs)
		return;
	if (!diffs && !st_ctrs)
		return;

	for (int i = 0; i < env.pmu_real_cnt; i++) {
		const struct pmu_event *ev = &env.pmu_reals[i];
		double value = diffs ? ev_ctrs[ev->stored_idx] : ev_ctrs[ev->stored_idx] - st_ctrs[ev->stored_idx];
		emit_kv_float(iid_str(ev->name_iid, ev->name), "%.6lf", value);
	}
	for (int i = 0; i < env.pmu_deriv_cnt; i++) {
		const struct pmu_event *ev = &env.pmu_derivs[i];
		int num_idx = (int)ev->config1;
		int denom_idx = (int)ev->config2;
		double num = diffs ? ev_ctrs[num_idx] : ev_ctrs[num_idx] - st_ctrs[num_idx];
		double denom = diffs ? ev_ctrs[denom_idx] : ev_ctrs[denom_idx] - st_ctrs[denom_idx];
		emit_kv_float(iid_str(ev->name_iid, ev->name), "%.6lf", num / denom);
	}
}

static struct task_state *task_state_try_get(struct worker_state *w, const struct wprof_task *t)
{
	unsigned long key = t->tid;
	struct task_state *st;

	if (hashmap__find(tasks, key, &st))
		return st;

	return NULL;
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
				.comm = t->pcomm,
				.pcomm = t->pcomm,
			};

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
static int process_timer(struct worker_state *w, const struct wevent *e)
{
	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	if (!should_trace_task(&task))
		return 0;

	(void)task_state(w, &task);

	int tr_id = (env.requested_stack_traces & ST_TIMER) ? e->timer.timer_stack_id : 0;

	if (env.emit_timer_ticks || tr_id > 0) {
		/* task keeps running on CPU */
		emit_instant(e->ts, &task, IID_NAME_TIMER, IID_CAT_TIMER) {
			emit_kv_int(IID_ANNK_CPU, e->cpu);
			if (env.emit_numa)
				emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
			emit_callstack(w, tr_id);
		}
	}

	return 0;
}

static void flush_ftrace_bundle(struct worker_state *w, int cpu)
{
	struct ftrace_cpu_bundle *bundle = &w->ftrace_bundles[cpu];
	struct ftrace_event_buffer *buf = &bundle->buffer;

	if (buf->cnt == 0)
		return;

	TracePacket pb = {
		PB_TRUST_SEQ_ID(PB_SEQ_ID_THREADS),
		PB_ONEOF(data, TracePacket_ftrace_events) = { .ftrace_events = {
			PB_INIT(cpu) = cpu,
			.event = PB_FTRACE_EVENTS(buf),
		}},
	};
	emit_trace_packet(&w->stream, &pb);

	ftrace_buffer_reset(buf);
}

static struct ftrace_cpu_bundle *ftrace_get_bundle(struct worker_state *w, int cpu)
{
	if (cpu >= w->ftrace_bundle_cnt) {

		w->ftrace_bundles = realloc(w->ftrace_bundles, (cpu + 1) * sizeof(*w->ftrace_bundles));
		for (int i = w->ftrace_bundle_cnt; i <= cpu; i++)
			ftrace_buffer_init(&w->ftrace_bundles[i].buffer);
		w->ftrace_bundle_cnt = cpu + 1;
	}

	return &w->ftrace_bundles[cpu];
}

static FtraceEvent *add_ftrace_event(struct worker_state *w, int cpu, u64 ts, u32 pid)
{
	struct ftrace_cpu_bundle *bundle = ftrace_get_bundle(w, cpu);
	struct ftrace_event_buffer *buf = &bundle->buffer;

	if (buf->cnt >= MAX_FTRACE_EVENTS_PER_BUNDLE)
		flush_ftrace_bundle(w, cpu);

	FtraceEvent *ev = ftrace_buffer_add(buf);
	if (!ev)
		return NULL;

	ev->has_timestamp = true;
	ev->timestamp = ts - env.sess_start_ts;
	ev->has_pid = true;
	ev->pid = pid;

	return ev;
}

/* EV_SWITCH */
static int process_switch(struct worker_state *w, const struct wevent *e)
{
	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);
	struct wprof_task next = wevent_resolve_task(hdr, e->swtch.next_task_id);
	struct wprof_task waker = wevent_resolve_task(hdr, e->swtch.waker_task_id);
	struct task_state *waker_st = NULL;

	if (e->swtch.waking_ts == 0 || !is_ts_in_range(e->swtch.waking_ts) ||
	    !should_trace_task(&waker))
		goto skip_waker_task;

	waker_st = task_state(w, &waker);

	/* event on awaker's timeline */
	pb_iid waker_ev_name, waker_ev_cat;
	if (e->swtch.waking_flags == WF_PREEMPTED) {
		waker_ev_name = IID_NAME_PREEMPTOR;
		waker_ev_cat = IID_CAT_PREEMPTOR;
	} else if (e->swtch.waking_flags == WF_WOKEN) {
		waker_ev_name = IID_NAME_WAKER;
		waker_ev_cat = IID_CAT_WAKER;
	} else if (e->swtch.waking_flags == WF_WOKEN_NEW) {
		waker_ev_name = IID_NAME_WAKER_NEW;
		waker_ev_cat = IID_CAT_WAKER_NEW;
	} else {
		waker_ev_name = IID_NAME_WAKER_UNKN;
		waker_ev_cat = IID_CAT_WAKER_UNKN;
	}
	emit_instant(e->swtch.waking_ts, &waker, waker_ev_name, waker_ev_cat) {
		emit_kv_int(IID_ANNK_CPU, e->swtch.waker_cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->swtch.waker_numa_node);

		emit_kv_str(IID_ANNK_WAKEE,
			    iid_str(emit_intern_str(w, next.comm), next.comm));
		if (env.emit_tidpid) {
			emit_kv_int(IID_ANNK_WAKEE_TID, task_tid(&next));
			emit_kv_int(IID_ANNK_WAKEE_PID, next.pid);
		}

		emit_flow_id(e->swtch.waking_ts);

		struct task_state *wakee_st = task_state_try_get(w, &next);
		if (wakee_st) {
			emit_callstack(w, wakee_st->waker_callstack_id);
			wakee_st->waker_callstack_id = 0;
		}
	}

skip_waker_task:
	if (!should_trace_task(&task))
		goto skip_prev_task;

	/* take into account task rename for switched-out task
	 * to maintain consistently named trace slice
	 */
	struct task_state *prev_st = task_state(w, &task);
	const char *cur_name = prev_st->rename_ts ? prev_st->old_comm : prev_st->comm;
	pb_iid cur_name_iid = prev_st->rename_ts ? prev_st->old_name_iid : prev_st->name_iid;
	bool preempted = e->swtch.prev_task_state == TASK_RUNNING;

	/* We are about to emit SLICE_END without
	 * corresponding SLICE_BEGIN ever being emitted;
	 * normally, Perfetto will just skip such SLICE_END
	 * and won't render anything, which is annoying and
	 * confusing. We want to avoid this, so we'll emit
	 * a fake SLICE_BEGIN with fake timestamp ZERO.
	 */
	if (prev_st->oncpu_ts == 0) {
		emit_slice_begin(env.sess_start_ts, &task,
				 iid_str(cur_name_iid, cur_name), IID_CAT_ONCPU) {
			emit_kv_int(IID_ANNK_CPU, e->cpu);
			if (env.emit_numa)
				emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
		}
	}

	emit_slice_end(e->ts, &task, iid_str(cur_name_iid, cur_name), IID_CAT_ONCPU) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);

		/* IDLE threads always go off-cpu to run something else */
		if (prev_st->pid != 0)
			emit_kv_str(IID_ANNK_OFFCPU_REASON, preempted ? IID_ANNV_OFFCPU_PREEMPTED : IID_ANNV_OFFCPU_BLOCKED);

		emit_kv_str(IID_ANNK_SWITCH_TO,
			    iid_str(emit_intern_str(w, next.comm), next.comm));
		if (env.emit_tidpid) {
			emit_kv_int(IID_ANNK_SWITCH_TO_TID, task_tid(&next));
			emit_kv_int(IID_ANNK_SWITCH_TO_PID, next.pid);
		}

		const u64 *pmu_vals = wevent_pmu_vals(hdr, e->swtch.pmu_vals_id);
		emit_perf_counters(prev_st->oncpu_ctrs, pmu_vals, false /* !diffs */);

		if (prev_st->rename_ts)
			emit_kv_str(IID_ANNK_RENAMED_TO, task.comm);

		if (env.requested_stack_traces & ST_OFFCPU)
			emit_callstack(w, e->swtch.offcpu_stack_id);
	}

	if (prev_st->req_id) {
		emit_track_slice_end(e->ts, trackid_req_thread(prev_st->req_id, &task),
				     IID_NAME_RUNNING, IID_CAT_REQUEST_ONCPU);
		emit_track_slice_start(e->ts, trackid_req_thread(prev_st->req_id, &task),
				       preempted ? IID_NAME_PREEMPTED : IID_NAME_WAITING,
				       IID_CAT_REQUEST_OFFCPU);
	}

	if (prev_st->rename_ts)
		prev_st->rename_ts = 0;

	/* reset perf counters */
	prev_st->oncpu_ctrs = NULL;
	prev_st->oncpu_ts = 0;
	prev_st->offcpu_ts = e->ts;
	prev_st->run_state = preempted ? TASK_STATE_PREEMPTED : TASK_STATE_WAITING;

skip_prev_task:
	if (!should_trace_task(&next))
		goto skip_next_task;

	struct task_state *next_st = task_state(w, &next);
	next_st->oncpu_ctrs = wevent_pmu_vals(hdr, e->swtch.pmu_vals_id);
	next_st->oncpu_ts = e->ts;

	u64 offcpu_dur_ns = next_st->offcpu_ts ? e->ts - next_st->offcpu_ts : e->ts - env.sess_start_ts;
	next_st->offcpu_ts = 0;

	if (!e->swtch.waking_ts)
		goto skip_waking;

	if (e->swtch.waking_flags == WF_PREEMPTED) {
		/*
		 * for preemption case, we just accummulate preempted time,
		 * without paying attention to compound delay of our preemptor
		 */
		next_st->compound_delay_ns += e->ts - e->swtch.waking_ts;
		next_st->compound_chain_len += 1;
	} else  {
		/*
		 * for non-preemption, we "inherit" our waker's compound chain
		 * and delay, and add our own wakeup delay to it to keep the
		 * chain going
		 */
		next_st->compound_delay_ns = e->ts - e->swtch.waking_ts;
		next_st->compound_chain_len = 1;

		next_st->compound_delay_ns += waker_st ? waker_st->compound_delay_ns : 0;
		next_st->compound_chain_len += waker_st ? waker_st->compound_chain_len : 0;
	}

	if (is_ts_in_range(e->swtch.waking_ts)/* && e->swtch.waker_cpu != e->cpu*/) {
		/* event on wakee's timeline */
		pb_iid wakee_ev_name, wakee_ev_cat;
		if (e->swtch.waking_flags == WF_PREEMPTED) {
			wakee_ev_name = IID_NAME_PREEMPTEE;
			wakee_ev_cat = IID_CAT_PREEMPTEE;
		} else if (e->swtch.waking_flags == WF_WOKEN) {
			wakee_ev_name = IID_NAME_WAKEE;
			wakee_ev_cat = IID_CAT_WAKEE;
		} else if (e->swtch.waking_flags == WF_WOKEN_NEW) {
			wakee_ev_name = IID_NAME_WAKEE_NEW;
			wakee_ev_cat = IID_CAT_WAKEE_NEW;
		} else {
			wakee_ev_name = IID_NAME_WAKEE_UNKN;
			wakee_ev_cat = IID_CAT_WAKEE_UNKN;
		}
		emit_instant(e->swtch.waking_ts, &next, wakee_ev_name, wakee_ev_cat) {
			emit_kv_int(IID_ANNK_CPU, e->cpu);
			if (env.emit_numa)
				emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);

			emit_flow_id(e->swtch.waking_ts);
		}
	}

skip_waking:
	emit_slice_begin(e->ts, &next, iid_str(next_st->name_iid, next.comm), IID_CAT_ONCPU) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);

		if (offcpu_dur_ns)
			emit_kv_float(IID_ANNK_OFFCPU_DUR_US, "%.3lf", offcpu_dur_ns / 1000.0);

		if (e->swtch.waking_ts) {
			emit_kv_str(IID_ANNK_WAKER,
				    iid_str(emit_intern_str(w, waker.comm), waker.comm));
			if (env.emit_tidpid) {
				emit_kv_int(IID_ANNK_WAKER_TID, task_tid(&waker));
				emit_kv_int(IID_ANNK_WAKER_PID, waker.pid);
			}
			emit_kv_str(IID_ANNK_WAKING_REASON,
				    IID_ANNV_WAKING_REASON + wreason_enum(e->swtch.waking_flags));
			emit_kv_int(IID_ANNK_WAKER_CPU, e->swtch.waker_cpu);
			if (env.emit_numa)
				emit_kv_int(IID_ANNK_WAKER_NUMA_NODE, e->swtch.waker_numa_node);
			emit_kv_float(IID_ANNK_WAKING_DELAY_US, "%.3lf", (e->ts - e->swtch.waking_ts) / 1000.0);
		}

		if (env.emit_sched_extras && next_st->compound_delay_ns) {
			emit_kv_float(IID_ANNK_COMPOUND_DELAY_US, "%.3lf", next_st->compound_delay_ns / 1000.0);
			emit_kv_int(IID_ANNK_COMPOUND_CHAIN_LEN, next_st->compound_chain_len);
		}

		emit_kv_str(IID_ANNK_SWITCH_FROM,
			    iid_str(emit_intern_str(w, task.comm), task.comm));
		if (env.emit_tidpid) {
			emit_kv_int(IID_ANNK_SWITCH_FROM_TID, task_tid(&task));
			emit_kv_int(IID_ANNK_SWITCH_FROM_PID, task.pid);
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
		emit_track_slice_end(e->ts, trackid_req_thread(next_st->req_id, &next),
				     was_preempted ? IID_NAME_PREEMPTED : IID_NAME_WAITING,
				     IID_CAT_REQUEST_OFFCPU);
		emit_track_slice_start(e->ts, trackid_req_thread(next_st->req_id, &next),
				       IID_NAME_RUNNING, IID_CAT_REQUEST_ONCPU);
	}

	next_st->run_state = TASK_STATE_RUNNING;

skip_next_task:
	if (!env.emit_sched_view)
		goto skip_sched_view;

	if (should_trace_task(&task) || should_trace_task(&next)) {
		FtraceEvent *fev = add_ftrace_event(w, e->cpu, e->ts, task_tid(&task));

		fev->which_event = perfetto_protos_FtraceEvent_sched_switch_tag;
		fev->event.sched_switch = (SchedSwitchFtraceEvent) {
			.prev_comm = task.pid ? PB_STRING(task.comm) : PB_NONE,
			PB_INIT(prev_pid) = task_tid(&task),
			PB_INIT(prev_prio) = e->swtch.prev_prio,
			PB_INIT(prev_state) = e->swtch.prev_task_state,
			.next_comm = next.pid ? PB_STRING(next.comm) : PB_NONE,
			PB_INIT(next_pid) = task_tid(&next),
			PB_INIT(next_prio) = e->swtch.next_prio,
		};
	}

	if (e->swtch.waking_ts &&
	    is_ts_in_range(e->swtch.waking_ts) &&
	    should_trace_task(&waker)) {
		FtraceEvent *fev = add_ftrace_event(w, e->swtch.waker_cpu, e->swtch.waking_ts,
						    task_tid(&task));
		fev->which_event = e->swtch.waking_flags == WF_WOKEN_NEW
			? perfetto_protos_FtraceEvent_sched_wakeup_new_tag
			: perfetto_protos_FtraceEvent_sched_waking_tag;
		fev->event.sched_waking = (SchedWakingFtraceEvent) {
			.comm = PB_STRING(next.comm),
			PB_INIT(pid) = task_tid(&next),
			PB_INIT(prio) = e->swtch.next_prio,
			PB_INIT(target_cpu) = e->cpu,
		};
	}

skip_sched_view:
	return 0;
}

/* EV_FORK */
static int process_fork(struct worker_state *w, const struct wevent *e)
{
	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);
	struct wprof_task child = wevent_resolve_task(hdr, e->fork.child_task_id);

	if (should_trace_task(&task)) {
		(void)task_state(w, &task);

		emit_instant(e->ts, &task, IID_NAME_FORKING, IID_CAT_FORKING) {
			emit_kv_int(IID_ANNK_CPU, e->cpu);
			if (env.emit_numa)
				emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);

			emit_kv_str(IID_ANNK_FORKED_INTO,
				    iid_str(emit_intern_str(w, child.comm), child.comm));
			emit_flow_id(e->ts);
			if (env.emit_tidpid) {
				emit_kv_int(IID_ANNK_FORKED_INTO_TID, task_tid(&child));
				emit_kv_int(IID_ANNK_FORKED_INTO_PID, child.pid);
			}
		}
	}

	if (should_trace_task(&child)) {
		(void)task_state(w, &child);

		emit_instant(e->ts, &child, IID_NAME_FORKED, IID_CAT_FORKED) {
			emit_kv_int(IID_ANNK_CPU, e->cpu);
			if (env.emit_numa)
				emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);

			emit_kv_str(IID_ANNK_FORKED_FROM,
				    iid_str(emit_intern_str(w, task.comm), task.comm));
			emit_flow_id(e->ts);
			if (env.emit_tidpid) {
				emit_kv_int(IID_ANNK_FORKED_FROM_TID, task_tid(&task));
				emit_kv_int(IID_ANNK_FORKED_FROM_PID, task.pid);
			}
		}
	}

	return 0;
}

/* EV_EXEC */
static int process_exec(struct worker_state *w, const struct wevent *e)
{
	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	if (!should_trace_task(&task))
		return 0;

	(void)task_state(w, &task);

	emit_instant(e->ts, &task, IID_NAME_EXEC, IID_CAT_EXEC) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);

		emit_kv_str(IID_ANNK_FILENAME, wevent_str(hdr, e->exec.filename_stroff));
		if (task.tid != e->exec.old_tid)
			emit_kv_int(IID_ANNK_TID_CHANGED_FROM, e->exec.old_tid);
	}

	return 0;
}

/* EV_TASK_RENAME */
static int process_task_rename(struct worker_state *w, const struct wevent *e)
{
	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	if (!should_trace_task(&task))
		return 0;

	struct task_state *st = task_state(w, &task);


	if (st->rename_ts == 0) {
		wprof_strlcpy(st->old_comm, task.comm, sizeof(st->old_comm));
		st->rename_ts = e->ts;
		st->old_name_iid = st->name_iid;
	}
	;
	const char *new_comm = wevent_str(hdr, e->rename.new_comm_stroff);
	wprof_strlcpy(st->comm, new_comm, sizeof(st->comm));
	st->name_iid = emit_intern_str(w, new_comm);

	emit_instant(e->ts, &task, IID_NAME_RENAME, IID_CAT_RENAME) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);

		emit_kv_str(IID_ANNK_OLD_NAME, task.comm);
		emit_kv_str(IID_ANNK_NEW_NAME, new_comm);
	}

	emit_thread_track_descr(&w->stream, &task, new_comm);

	return 0;
}

/* EV_TASK_EXIT */
static int process_task_exit(struct worker_state *w, const struct wevent *e)
{
	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	if (!should_trace_task(&task))
		return 0;

	(void)task_state(w, &task);

	emit_instant(e->ts, &task, IID_NAME_EXIT, IID_CAT_EXIT) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
	}

	/* we still might be getting task events, too early to delete the state */
	return 0;
}

/* EV_TASK_FREE */
static int process_task_free(struct worker_state *w, const struct wevent *e)
{
	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	if (!should_trace_task(&task))
		goto skip_emit;

	(void)task_state(w, &task);

	emit_instant(e->ts, &task, IID_NAME_FREE, IID_CAT_FREE) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
	}

skip_emit:
	/* now we should be done with the task */
	task_state_delete(&task);

	return 0;
}

/* EV_WAKEUP */
/*
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
*/

/* EV_WAKEUP_NEW */
static int process_wakeup_new(struct worker_state *w, const struct wevent *e)
{
	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	if (!should_trace_task(&task))
		return 0;

	(void)task_state(w, &task);

	int tr_id = (env.requested_stack_traces & ST_WAKER) ? e->wakeup_new.waker_stack_id : 0;
	if (tr_id <= 0)
		return 0;

	struct wprof_task wakee = wevent_resolve_task(hdr, e->wakeup_new.wakee_task_id);
	struct task_state *wakee_st = task_state(w, &wakee);
	wakee_st->waker_callstack_id = tr_id;

	return 0;
}

/* EV_WAKING */
static int process_waking(struct worker_state *w, const struct wevent *e)
{
	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	if (!should_trace_task(&task))
		return 0;

	(void)task_state(w, &task);

	int tr_id = (env.requested_stack_traces & ST_WAKER) ? e->waking.waker_stack_id : 0;
	if (tr_id <= 0)
		return 0;

	struct wprof_task wakee = wevent_resolve_task(hdr, e->waking.wakee_task_id);
	struct task_state *wakee_st = task_state(w, &wakee);
	wakee_st->waker_callstack_id = tr_id;

	return 0;
}

/* EV_HARDIRQ_EXIT */
static int process_hardirq_exit(struct worker_state *w, const struct wevent *e)
{
	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	if (!should_trace_task(&task))
		return 0;

	(void)task_state(w, &task);

	u64 start_ts = is_ts_in_range(e->hardirq.hardirq_ts) ? e->hardirq.hardirq_ts : env.sess_start_ts;
	emit_slice_begin(start_ts, &task, IID_NAME_HARDIRQ, IID_CAT_HARDIRQ) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
		emit_kv_int(IID_ANNK_IRQ, e->hardirq.irq);
		emit_kv_str(IID_ANNK_ACTION, wevent_str(hdr, e->hardirq.name_stroff));
	}
	emit_slice_end(e->ts, &task, IID_NAME_HARDIRQ, IID_CAT_HARDIRQ) {
		const u64 *pmu_vals = wevent_pmu_vals(hdr, e->hardirq.pmu_vals_id);
		emit_perf_counters(NULL, pmu_vals, true /* diffs */);
	}

	return 0;
}

/* EV_SOFTIRQ_EXIT */
static int process_softirq_exit(struct worker_state *w, const struct wevent *e)
{
	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	if (!should_trace_task(&task))
		return 0;

	(void)task_state(w, &task);

	pb_iid name_iid, act_iid;
	if (e->softirq.vec_nr >= 0 && e->softirq.vec_nr < NR_SOFTIRQS) {
		name_iid = IID_NAME_SOFTIRQ + e->softirq.vec_nr;
		act_iid = IID_ANNV_SOFTIRQ_ACTION + e->softirq.vec_nr;
	} else {
		name_iid = IID_NONE;
		act_iid = IID_NONE;
	}

	u64 start_ts = is_ts_in_range(e->softirq.softirq_ts) ? e->softirq.softirq_ts : env.sess_start_ts;
	emit_slice_begin(start_ts, &task,
			     iid_str(name_iid, sfmt("%s:%s", "SOFTIRQ", softirq_str(e->softirq.vec_nr))),
			     IID_CAT_SOFTIRQ) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
		emit_kv_str(IID_ANNK_ACTION, iid_str(act_iid, softirq_str(e->softirq.vec_nr)));
	}

	emit_slice_end(e->ts, &task,
		       iid_str(name_iid, sfmt("%s:%s", "SOFTIRQ", softirq_str(e->softirq.vec_nr))),
		       IID_CAT_SOFTIRQ) {
		const u64 *pmu_vals = wevent_pmu_vals(hdr, e->softirq.pmu_vals_id);
		emit_perf_counters(NULL, pmu_vals, true /* diffs */);
	}

	return 0;
}

/* EV_WQ_END */
static int process_wq_end(struct worker_state *w, const struct wevent *e)
{
	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	if (!should_trace_task(&task))
		return 0;

	(void)task_state(w, &task);

	const char *desc = wevent_str(hdr, e->wq.desc_stroff);

	u64 start_ts = is_ts_in_range(e->wq.wq_ts) ? e->wq.wq_ts : env.sess_start_ts;
	emit_slice_begin(start_ts, &task,
			 iid_str(IID_NONE, sfmt("%s:%s", "WQ", desc)),
			 IID_CAT_WQ) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
		emit_kv_str(IID_ANNK_ACTION, desc);
	}
	emit_slice_end(e->ts, &task,
		       iid_str(IID_NONE, sfmt("%s:%s", "WQ", desc)),
		       IID_CAT_WQ) {
		const u64 *pmu_vals = wevent_pmu_vals(hdr, e->wq.pmu_vals_id);
		emit_perf_counters(NULL, pmu_vals, true /* diffs */);
	}

	return 0;
}

static const char *scx_dsq_insert_type_str(enum scx_dsq_insert_type type)
{
	switch (type) {
	case SCX_DSQ_INSERT: return "dsq_insert";
	case SCX_DSQ_INSERT_VTIME: return "dsq_insert_vtime";
	case SCX_DSQ_DISPATCH: return "dispatch";
	case SCX_DSQ_DISPATCH_VTIME: return "dispatch_vtime";
	case SCX_DSQ_MOVE: return "dsq_move";
	case SCX_DSQ_MOVE_VTIME: return "dsq_move_vtime";
	case SCX_DSQ_DISPATCH_FROM_DSQ: return "dispatch_from_dsq";
	case SCX_DSQ_DISPATCH_VTIME_FROM_DSQ: return "dispatch_vtime_from_dsq";
	default: return "unknown";
	}
}

/* EV_SCX_DSQ_END */
static int process_scx_dsq_end(struct worker_state *w, const struct wevent *e)
{
	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	if (!should_trace_task(&task))
		return 0;

	(void)task_state(w, &task);

	const char *insert_type_str = scx_dsq_insert_type_str(e->scx_dsq.scx_dsq_insert_type);
	pb_iid insert_type_str_iid = emit_intern_str(w, insert_type_str);

	const char *name = sfmt("DSQ:%s_0x%llx", insert_type_str, (u64)e->scx_dsq.scx_dsq_id);
	pb_iid name_iid = emit_intern_str(w, name);

	u64 start_ts = is_ts_in_range(e->scx_dsq.scx_dsq_insert_ts) ? e->scx_dsq.scx_dsq_insert_ts : env.sess_start_ts;
	emit_slice_begin(start_ts, &task, iid_str(name_iid, name), IID_CAT_SCX_DSQ) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
		emit_kv_str(IID_ANNK_ACTION, iid_str(insert_type_str_iid, insert_type_str));
	}
	emit_slice_end(e->ts, &task, iid_str(name_iid, name), IID_CAT_SCX_DSQ) {
		emit_kv_int(iid_str(IID_NONE, "dsq_id"), e->scx_dsq.scx_dsq_id);
		emit_kv_int(iid_str(IID_NONE, "layer_id"), e->scx_dsq.scx_layer_id);
	}

	return 0;
}

/* EV_IPI_SEND */
static int process_ipi_send(struct worker_state *w, const struct wevent *e)
{
	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	if (!should_trace_task(&task))
		return 0;

	(void)task_state(w, &task);

	pb_iid name_iid;
	if (e->ipi_send.kind >= 0 && e->ipi_send.kind < NR_IPIS)
		name_iid = IID_NAME_IPI_SEND + e->ipi_send.kind;
	else
		name_iid = IID_NAME_IPI_SEND + IPI_INVALID;
	const char *name = sfmt("%s:%s", "IPI_SEND", ipi_kind_str(e->ipi_send.kind));

	emit_instant(e->ts, &task, iid_str(name_iid, name), IID_CAT_IPI_SEND) {
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
static int process_ipi_exit(struct worker_state *w, const struct wevent *e)
{
	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	if (!should_trace_task(&task))
		return 0;

	(void)task_state(w, &task);

	pb_iid name_iid;
	if (e->ipi.kind >= 0 && e->ipi.kind < NR_IPIS)
		name_iid = IID_NAME_IPI + e->ipi.kind;
	else
		name_iid = IID_NAME_IPI + IPI_INVALID;
	const char *name = sfmt("%s:%s", "IPI", ipi_kind_str(e->ipi.kind));

	u64 start_ts = is_ts_in_range(e->ipi.ipi_ts) ? e->ipi.ipi_ts : env.sess_start_ts;
	emit_slice_begin(start_ts, &task, iid_str(name_iid, name), IID_CAT_IPI) {
		emit_kv_int(IID_ANNK_CPU, e->cpu);
		if (env.emit_numa)
			emit_kv_int(IID_ANNK_NUMA_NODE, e->numa_node);
	}
	emit_slice_end(e->ts, &task, iid_str(name_iid, name), IID_CAT_IPI) {
		if (e->ipi.ipi_id > 0)
			emit_flow_id(e->ipi.ipi_id);
		if (e->ipi.send_ts > 0) {
			emit_kv_int(IID_ANNK_SENDER_CPU, e->ipi.send_cpu);
			emit_kv_float(IID_ANNK_IPI_DELAY_US,
				      "%.3lf", (e->ipi.ipi_ts - e->ipi.send_ts) / 1000.0);
		}
		const u64 *pmu_vals = wevent_pmu_vals(hdr, e->ipi.pmu_vals_id);
		emit_perf_counters(NULL, pmu_vals, true /* diffs */);
	}

	return 0;
}

static u64 ensure_process_reqs_track(const struct wprof_task *t)
{
	struct track_state *s = track_state_get_or_add(TK_PROC_REQS, t->pid, 0);
	u64 track_uuid = trackid_process_reqs(t);

	if (!s->exists) {
		emit_track_descr(cur_stream, track_uuid, TRACK_UUID_REQUESTS,
				 sfmt("%s %u", t->pcomm, t->pid), 0);
		s->exists = true;
	}
	return track_uuid;
}

static u64 ensure_req_track(const struct wprof_task *t, u64 req_id, const char *req_name)
{
	struct track_state *s = track_state_get_or_add(TK_REQ, t->pid, req_id);
	u64 track_uuid = trackid_req(req_id, t);

	if (!s->exists) {
		emit_track_descr(cur_stream, track_uuid, trackid_process_reqs(t),
				 sfmt("REQ:%s (%llu)", req_name, req_id), 0);
		s->exists = true;
	}
	return track_uuid;
}

static u64 ensure_req_thread_track(const struct wprof_task *t, u64 req_id, const char *req_name)
{
	struct track_state *s = track_state_get_or_add(TK_REQ_THREAD, t->tid, req_id);
	u64 track_uuid = trackid_req_thread(req_id, t);

	if (!s->exists) {
		emit_track_descr(cur_stream, track_uuid, trackid_req(req_id, t),
				 sfmt("%s %u", t->comm, t->tid), 0);
		s->exists = true;
	}
	return track_uuid;
}

static void clear_req_tracks(const struct wprof_task *t, u64 req_id)
{
	track_state_delete(TK_REQ, t->pid, req_id);
	track_state_delete(TK_REQ_THREAD, t->tid, req_id);
}

/* EV_REQ_EVENT */
static int process_req_event(struct worker_state *w, const struct wevent *e)
{
	if (env.capture_requests != TRUE)
		return 0;

	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	if (!should_trace_task(&task))
		return 0;

	struct task_state *st = task_state(w, &task);

	u64 req_id = e->req.req_id;
	const char *req_name = wevent_str(hdr, e->req.req_name_stroff);

	ensure_process_reqs_track(&task);
	u64 req_track_uuid = ensure_req_track(&task, req_id, req_name);
	u64 track_uuid = ensure_req_thread_track(&task, req_id, req_name);

	pb_iid req_name_iid = emit_intern_str(w, req_name);

	switch (e->req.req_event) {
	case REQ_BEGIN:
		emit_track_slice_start(e->ts, req_track_uuid,
				       iid_str(req_name_iid, req_name),
				       IID_CAT_REQUEST) {
			emit_kv_str(IID_ANNK_REQ_NAME, iid_str(req_name_iid, req_name));
			emit_kv_int(IID_ANNK_REQ_ID, e->req.req_id);
		}

		if (env.emit_req_extras) {
			emit_track_instant(e->ts, track_uuid,
					   IID_NAME_REQUEST_BEGIN, IID_CAT_REQUEST_BEGIN) {
				emit_kv_int(IID_ANNK_CPU, e->cpu);
				emit_kv_str(IID_ANNK_REQ_NAME, iid_str(req_name_iid, req_name));
				emit_kv_int(IID_ANNK_REQ_ID, e->req.req_id);
			}
		}

		st->req_id = e->req.req_id;
		break;
	case REQ_SET:
		emit_track_slice_start(e->ts, track_uuid,
				       iid_str(st->name_iid, st->comm),
				       IID_CAT_REQUEST_THREAD) {
			emit_kv_str(IID_ANNK_REQ_NAME, iid_str(req_name_iid, req_name));
			emit_kv_int(IID_ANNK_REQ_ID, e->req.req_id);
		}

		emit_track_slice_start(e->ts, track_uuid,
				       IID_NAME_RUNNING, IID_CAT_REQUEST_ONCPU);

		if (env.emit_req_extras) {
			emit_track_instant(e->ts, track_uuid,
					   IID_NAME_REQUEST_SET, IID_CAT_REQUEST_SET) {
				emit_kv_int(IID_ANNK_CPU, e->cpu);
				emit_kv_str(IID_ANNK_REQ_NAME, iid_str(req_name_iid, req_name));
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
				emit_kv_str(IID_ANNK_REQ_NAME, iid_str(req_name_iid, req_name));
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
				     iid_str(req_name_iid, req_name), IID_CAT_REQUEST) {
			emit_kv_str(IID_ANNK_REQ_NAME, iid_str(req_name_iid, req_name));
			emit_kv_int(IID_ANNK_REQ_ID, e->req.req_id);
			emit_kv_float(IID_ANNK_REQ_LATENCY_US, "%.6lf", (e->ts - e->req.req_ts) / 1000);
		}
		emit_track_slice_end(e->ts, track_uuid,
				     IID_NAME_RUNNING, IID_CAT_REQUEST_ONCPU);

		if (env.emit_req_extras) {
			emit_track_instant(e->ts, track_uuid,
					   IID_NAME_REQUEST_END, IID_CAT_REQUEST_END) {
				emit_kv_int(IID_ANNK_CPU, e->cpu);
				emit_kv_str(IID_ANNK_REQ_NAME, iid_str(req_name_iid, req_name));
				emit_kv_int(IID_ANNK_REQ_ID, e->req.req_id);
				emit_kv_float(IID_ANNK_REQ_LATENCY_US, "%.6lf", (e->ts - e->req.req_ts) / 1000);
			}
		}

		st->req_id = 0;

		clear_req_tracks(&task, req_id);
		break;
	default:
		eprintf("UNHANDLED REQ EVENT %d\n", e->req.req_event);
		exit(1);
	}

	return 0;
}

/* EV_REQ_TASK_EVENT */
static int process_req_task_event(struct worker_state *w, const struct wevent *e)
{
	if (env.capture_req_experimental != TRUE)
		return 0;

	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	if (!should_trace_task(&task))
		return 0;

	u64 req_id = e->req_task.req_id;

	ensure_process_reqs_track(&task);
	u64 track_uuid = ensure_req_thread_track(&task, req_id, "");

	switch (e->req_task.req_task_event) {
	case REQ_TASK_ENQUEUE:
		emit_track_instant(e->ts, track_uuid,
				   IID_NAME_REQUEST_TASK_ENQUEUE, IID_CAT_REQUEST_TASK_ENQUEUE) {
			emit_kv_int(IID_ANNK_REQ_ID, e->req_task.req_id);
			emit_kv_int(IID_ANNK_REQ_TASK_ID, e->req_task.req_task_id);
			//emit_kv_int("enqueue_ts", e->req_task.enqueue_ts);

			u64 flow_id = hash_combine(e->req_task.req_id,
				      hash_combine(e->req_task.req_task_id,
						   e->req_task.enqueue_ts));
			emit_flow_id(flow_id);
		}
		break;
	case REQ_TASK_DEQUEUE:
		emit_track_instant(e->ts, track_uuid,
				   IID_NAME_REQUEST_TASK_DEQUEUE, IID_CAT_REQUEST_TASK_DEQUEUE) {
			emit_kv_int(IID_ANNK_REQ_ID, e->req_task.req_id);
			emit_kv_int(IID_ANNK_REQ_TASK_ID, e->req_task.req_task_id);
			//emit_kv_int("enqueue_ts", e->req_task.enqueue_ts);
			emit_kv_int(IID_ANNK_REQ_WAIT_TIME_NS, e->req_task.wait_time_ns);

			u64 flow_id = hash_combine(e->req_task.req_id,
				      hash_combine(e->req_task.req_task_id,
						   e->req_task.enqueue_ts));
			emit_flow_id(flow_id);
		}
		break;
	case REQ_TASK_STATS:
		emit_track_instant(e->ts, track_uuid,
				   IID_NAME_REQUEST_TASK_COMPLETE, IID_CAT_REQUEST_TASK_COMPLETE) {
			emit_kv_int(IID_ANNK_REQ_ID, e->req_task.req_id);
			emit_kv_int(IID_ANNK_REQ_TASK_ID, e->req_task.req_task_id);
			emit_kv_int(IID_ANNK_REQ_WAIT_TIME_NS, e->req_task.wait_time_ns);

			//emit_kv_int("enqueue_ts", e->req_task.enqueue_ts);
			//emit_kv_int("run_time_ns", e->req_task.run_time_ns);

			u64 flow_id = hash_combine(e->req_task.req_id,
				      hash_combine(e->req_task.req_task_id,
						   e->req_task.enqueue_ts));
			emit_flow_id(flow_id);
		}
		break;
	default:
		eprintf("UNHANDLED REQ TASK EVENT %d\n", e->req_task.req_task_event);
		exit(1);
	}

	return 0;
}

static u64 ensure_cuda_proc_track(int pid, const char *proc_name)
{
	struct track_state *s = track_state_get_or_add(TK_CUDA_PROC, pid, 0);
	u64 track_uuid = trackid_cuda_proc(pid);

	if (!s->exists) {
		emit_track_descr(cur_stream, track_uuid, TRACK_UUID_CUDA,
				 sfmt("%s %d (CUDA)", proc_name, pid), 0);
		s->exists = true;
	}
	return track_uuid;
}

static u64 ensure_cuda_proc_gpu_track(int pid, u32 gpu_id)
{
	struct track_state *s = track_state_get_or_add(TK_CUDA_PROC_GPU, pid, gpu_id);
	u64 track_uuid = trackid_cuda_proc_gpu(pid, gpu_id);

	if (!s->exists) {
		emit_track_descr(cur_stream, track_uuid, trackid_cuda_proc(pid),
				 sfmt("GPU #%u", gpu_id), 0);
		s->exists = true;
	}
	return track_uuid;
}

static u64 ensure_cuda_proc_stream_track(int pid, u32 gpu_id, u32 stream_id)
{
	struct track_state *s = track_state_get_or_add(TK_CUDA_PROC_STREAM, pid, stream_id);
	u64 track_uuid = trackid_cuda_proc_stream(pid, stream_id);

	if (!s->exists) {
		emit_track_descr(cur_stream, track_uuid, trackid_cuda_proc_gpu(pid, gpu_id),
				 sfmt("Stream #%u", stream_id), 0);
		s->exists = true;
	}
	return track_uuid;
}

static inline u64 clamp_ts(u64 ts)
{
	if ((long)(ts - env.sess_start_ts) < 0)
		return env.sess_start_ts;
	if ((long)(ts - env.sess_end_ts) > 0)
		return env.sess_end_ts;
	return ts;
}

static bool is_time_range_in_session(u64 start_ts, u64 end_ts)
{
	if ((long)(end_ts - env.sess_start_ts) < 0)
		return false;
	if ((long)(start_ts - env.sess_end_ts) > 0)
		return false;
	return true;
}

/*
 * Simplify a demangled C++ function name by stripping template parameters,
 * anonymous namespace markers, and function arguments, in place. Examples:
 *   "foo::bar<int, std::vector<char>>::baz(int, char*)" -> "foo::bar::baz"
 *   "foo::(anonymous namespace)::bar(void)" -> "foo::::bar"
 */
static void simplify_demangled_name(char *name)
{
	int i, j, nest_lvl = 0;

	for (i = 0, j = 0; name[i]; i++) {
		/* blah<whatever> -> blah (handles nested templates) */
		if (name[i] == '<') {
			nest_lvl++;
			continue;
		}
		if (name[i] == '>') {
			nest_lvl--;
			continue;
		}
		/* ::(anonymous namespace):: -> :::: */
		if (i >= 2 && name[i] == '(' && name[i - 1] == ':' && name[i - 2] == ':') {
			nest_lvl++;
			continue;
		}
		if (name[i] == ')' && name[i + 1] == ':' && name[i + 2] == ':') {
			nest_lvl--;
			continue;
		}

		/* func(args...) -> func (stop at top-level opening paren) */
		if (nest_lvl == 0 && name[i] == '(') {
			break;
		}

		if (nest_lvl == 0) {
			name[j] = name[i];
			j++;
		}
	}
	name[j] = '\0';
}

static void emit_gpu_delay(u64 ts, int pid, u32 corr_id)
{
	struct cuda_corr_info *ci = cuda_corr_pop(pid, corr_id);
	if (ci && ci->api_ts)
		emit_kv_float(IID_ANNK_CUDA_GPU_DELAY_US, "%.3lf", (ts - ci->api_ts) / 1000.0);
	free(ci);
}

/* EV_CUDA_KERNEL */
static int process_cuda_kernel(struct worker_state *w, const struct wevent *e)
{
	if (env.capture_cuda != TRUE)
		return 0;

	const struct wevent_cuda_kernel *cu = &e->cuda_kernel;

	if (!is_time_range_in_session(e->ts, cu->end_ts))
		return 0;

	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	ensure_cuda_proc_track(task.pid, task.pcomm);
	ensure_cuda_proc_gpu_track(task.pid, cu->device_id);
	u64 track_uuid = ensure_cuda_proc_stream_track(task.pid, cu->device_id, cu->stream_id);

	const char *cuda_kern_name = wevent_str(hdr, cu->name_stroff);

	char demangled_buf[4096];
	const char *cuda_kern_name_demangled = NULL;
	if (demangle_symbol(cuda_kern_name, demangled_buf, sizeof(demangled_buf)) >= 0) {
		simplify_demangled_name(demangled_buf);
		cuda_kern_name_demangled = demangled_buf;
	}

	const char *name = cuda_kern_name_demangled ?: cuda_kern_name;
	pb_iid name_iid = emit_intern_str(w, name);

	emit_track_slice_start(clamp_ts(e->ts), track_uuid,
			       iid_str(name_iid, name), IID_CAT_CUDA_KERNEL) {
		if (name != cuda_kern_name) {
			pb_iid mangled_name_iid = emit_intern_str(w, cuda_kern_name);
			emit_kv_str(IID_ANNK_CUDA_MANGLED_NAME, iid_str(mangled_name_iid, cuda_kern_name));
		}

		emit_gpu_delay(e->ts, task.pid, cu->corr_id);

		emit_kv_int(IID_ANNK_CUDA_DEVICE_ID, cu->device_id);
		emit_kv_int(IID_ANNK_CUDA_STREAM_ID, cu->stream_id);
		emit_kv_int(IID_ANNK_CUDA_CONTEXT_ID, cu->ctx_id);
		emit_kv_int(IID_ANNK_CUDA_BLOCK_X, cu->block_x);
		emit_kv_int(IID_ANNK_CUDA_BLOCK_Y, cu->block_y);
		emit_kv_int(IID_ANNK_CUDA_BLOCK_Z, cu->block_z);
		emit_kv_int(IID_ANNK_CUDA_GRID_X, cu->grid_x);
		emit_kv_int(IID_ANNK_CUDA_GRID_Y, cu->grid_y);
		emit_kv_int(IID_ANNK_CUDA_GRID_Z, cu->grid_z);

		emit_flow_id(((u64)task.pid << 32) | cu->corr_id);
	}

	emit_track_slice_end(clamp_ts(cu->end_ts), track_uuid,
			     iid_str(name_iid, name), IID_CAT_CUDA_KERNEL);

	return 0;
}

/* EV_CUDA_MEMCPY */
static int process_cuda_memcpy(struct worker_state *w, const struct wevent *e)
{
	if (env.capture_cuda != TRUE)
		return 0;

	const struct wevent_cuda_memcpy *cu = &e->cuda_memcpy;

	if (!is_time_range_in_session(e->ts, cu->end_ts))
		return 0;

	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	ensure_cuda_proc_track(task.pid, task.pcomm);
	ensure_cuda_proc_gpu_track(task.pid, cu->device_id);
	u64 track_uuid = ensure_cuda_proc_stream_track(task.pid, cu->device_id, cu->stream_id);

	pb_iid name_iid, kind_iid;
	if (cu->copy_kind >= CUDA_MEMCPY_UNKN && cu->copy_kind < NR_CUDA_MEMCPY_KIND) {
		name_iid = IID_NAME_CUDA_MEMCPY + cu->copy_kind;
		kind_iid = IID_ANNV_CUDA_MEMCPY_KIND + cu->copy_kind;
	} else {
		name_iid = IID_NONE;
		kind_iid = IID_NONE;
	}

	const char *copy_kind_str = cuda_memcpy_kind_str(cu->copy_kind);
	struct pb_str name = iid_str(name_iid, sfmt("%s:%s", "memcpy", copy_kind_str));

	emit_track_slice_start(clamp_ts(e->ts), track_uuid, name, IID_CAT_CUDA_MEMCPY) {
		emit_gpu_delay(e->ts, task.pid, cu->corr_id);

		emit_kv_int(IID_ANNK_CUDA_BYTE_CNT, cu->byte_cnt);
		emit_kv_str(IID_ANNK_CUDA_KIND, iid_str(kind_iid, copy_kind_str));

		pb_iid src_kind_iid = cu->src_kind >= CUDA_MEM_UNKN && cu->src_kind < NR_CUDA_MEMORY_KIND
			? IID_ANNV_CUDA_MEMORY_KIND + cu->src_kind : IID_NONE;
		pb_iid dst_kind_iid = cu->dst_kind >= CUDA_MEM_UNKN && cu->dst_kind < NR_CUDA_MEMORY_KIND
			? IID_ANNV_CUDA_MEMORY_KIND + cu->dst_kind : IID_NONE;
		emit_kv_str(IID_ANNK_CUDA_SRC_KIND, iid_str(src_kind_iid, cuda_memory_kind_str(cu->src_kind)));
		emit_kv_str(IID_ANNK_CUDA_DST_KIND, iid_str(dst_kind_iid, cuda_memory_kind_str(cu->dst_kind)));

		emit_kv_int(IID_ANNK_CUDA_DEVICE_ID, cu->device_id);
		emit_kv_int(IID_ANNK_CUDA_STREAM_ID, cu->stream_id);
		emit_kv_int(IID_ANNK_CUDA_CONTEXT_ID, cu->ctx_id);

		emit_flow_id(((u64)task.pid << 32) | cu->corr_id);
	}

	emit_track_slice_end(clamp_ts(cu->end_ts), track_uuid, name, IID_CAT_CUDA_MEMCPY);

	return 0;
}

/* EV_CUDA_MEMSET */
static int process_cuda_memset(struct worker_state *w, const struct wevent *e)
{
	if (env.capture_cuda != TRUE)
		return 0;

	const struct wevent_cuda_memset *cu = &e->cuda_memset;

	if (!is_time_range_in_session(e->ts, cu->end_ts))
		return 0;

	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	ensure_cuda_proc_track(task.pid, task.pcomm);
	ensure_cuda_proc_gpu_track(task.pid, cu->device_id);
	u64 track_uuid = ensure_cuda_proc_stream_track(task.pid, cu->device_id, cu->stream_id);

	pb_iid name_iid, kind_iid;
	if (cu->mem_kind >= CUDA_MEM_UNKN && cu->mem_kind < NR_CUDA_MEMORY_KIND) {
		name_iid = IID_NAME_CUDA_MEMSET + cu->mem_kind;
		kind_iid = IID_ANNV_CUDA_MEMORY_KIND + cu->mem_kind;
	} else {
		name_iid = IID_NONE;
		kind_iid = IID_NONE;
	}
	const char *mem_kind_str = cuda_memory_kind_str(cu->mem_kind);
	struct pb_str name = iid_str(name_iid, sfmt("%s:%s", "memset", mem_kind_str));

	emit_track_slice_start(clamp_ts(e->ts), track_uuid, name, IID_CAT_CUDA_MEMSET) {
		emit_gpu_delay(e->ts, task.pid, cu->corr_id);

		emit_kv_int(IID_ANNK_CUDA_BYTE_CNT, cu->byte_cnt);
		emit_kv_str(IID_ANNK_CUDA_KIND, iid_str(kind_iid, mem_kind_str));
		emit_kv_int(IID_ANNK_CUDA_DEVICE_ID, cu->device_id);
		emit_kv_int(IID_ANNK_CUDA_STREAM_ID, cu->stream_id);
		emit_kv_int(IID_ANNK_CUDA_CONTEXT_ID, cu->ctx_id);

		emit_flow_id(((u64)task.pid << 32) | cu->corr_id);
	}

	emit_track_slice_end(clamp_ts(cu->end_ts), track_uuid, name, IID_CAT_CUDA_MEMSET);

	return 0;
}

/* EV_CUDA_SYNC */
static int process_cuda_sync(struct worker_state *w, const struct wevent *e)
{
	if (env.capture_cuda != TRUE)
		return 0;

	const struct wevent_cuda_sync *cu = &e->cuda_sync;

	if (!is_time_range_in_session(e->ts, cu->end_ts))
		return 0;

	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	u64 proc_track_uuid = ensure_cuda_proc_track(task.pid, task.pcomm);
	u64 track_uuid;

	if ((int)cu->stream_id == -1 /* CUPTI_SYNCHRONIZATION_INVALID_VALUE */) {
		/*
		 * some SYNC events don't have stream association,
		 * so we put them on "global" (CUDA) process track
		 */
		track_uuid = proc_track_uuid;
	} else if (track_state_find(TK_CUDA_PROC_STREAM, task.pid, cu->stream_id)) {
		/*
		 * SYNC events don't record device ID (only in CUDA 13+, which we don't take
		 * advantage of just yet), so put SYNC onto stream track if we already previously
		 * emitted a properly structured track descriptor that belongs to a specific GPU
		 */
		track_uuid = trackid_cuda_proc_stream(task.pid, cu->stream_id);
	} else {
		/*
		 * otherwise we don't have GPU ID to ensure proper track structure, so put this
		 * sync event on (CUDA) process track
		 */
		track_uuid = proc_track_uuid;
	}

	pb_iid name_iid, kind_iid;
	if (cu->sync_type >= CUDA_SYNC_UNKN && cu->sync_type < NR_CUDA_SYNC_TYPE) {
		name_iid = IID_NAME_CUDA_SYNC + cu->sync_type;
		kind_iid = IID_ANNV_CUDA_SYNC_TYPE + cu->sync_type;
	} else {
		name_iid = IID_NONE;
		kind_iid = IID_NONE;
	}

	const char *sync_type_str = cuda_sync_type_str(cu->sync_type);
	struct pb_str name = iid_str(name_iid, sfmt("%s:%s", "sync", sync_type_str));

	emit_track_slice_start(clamp_ts(e->ts), track_uuid, name, IID_CAT_CUDA_SYNC) {
		emit_gpu_delay(e->ts, task.pid, cu->corr_id);

		emit_kv_str(IID_ANNK_CUDA_KIND, iid_str(kind_iid, sync_type_str));
		emit_kv_int(IID_ANNK_CUDA_STREAM_ID, cu->stream_id);
		emit_kv_int(IID_ANNK_CUDA_CONTEXT_ID, cu->ctx_id);
		emit_kv_int(IID_ANNK_CUDA_EVENT_ID, cu->event_id);

		emit_flow_id(((u64)task.pid << 32) | cu->corr_id);
	}

	emit_track_slice_end(clamp_ts(cu->end_ts), track_uuid, name, IID_CAT_CUDA_SYNC);

	return 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
extern const char *cupti_driver_cbid_str_map[];
extern int cupti_driver_cbid_str_map_sz;

extern const char *cupti_runtime_cbid_str_map[];
extern int cupti_runtime_cbid_str_map_sz;

static const char *cuda_driver_cbid_str(int cbid)
{
	if (cbid <= 0 || cbid >= cupti_driver_cbid_str_map_sz)
		return "???";

	const char *s = cupti_driver_cbid_str_map[cbid];
	return s ?: "???";
}

static const char *cuda_runtime_cbid_str(int cbid)
{
	if (cbid <= 0 || cbid >= cupti_runtime_cbid_str_map_sz)
		return "???";

	const char *s = cupti_runtime_cbid_str_map[cbid];
	return s ?: "???";
}
#pragma GCC diagnostic pop

/* WCK_CUDA_API */
static int process_cuda_api(struct worker_state *w, const struct wevent *e)
{
	if (env.capture_cuda != TRUE)
		return 0;

	struct wprof_data_hdr *hdr = w->dump_hdr;
	struct wprof_task task = wevent_resolve_task(hdr, e->task_id);

	if (!is_time_range_in_session(e->ts, e->cuda_api.end_ts))
		return 0;

	/* check if we failed to resolve TID at data capture time */
	if (task.tid == 0)
		return 0;

	(void)task_state(w, &task);

	/* remember host-side API call timestamp */
	struct cuda_corr_info *ci = cuda_corr_get(task.pid, e->cuda_api.corr_id);
	ci->api_ts = e->ts;

	u64 track_uuid = TRACK_UUID(TK_THREAD, task.tid);

	const char *name;
	switch (e->cuda_api.kind) {
	case WCUDA_CUDA_API_DRIVER: name = cuda_driver_cbid_str(e->cuda_api.cbid); break;
	case WCUDA_CUDA_API_RUNTIME: name = cuda_runtime_cbid_str(e->cuda_api.cbid); break;
	default: name = "???"; break;
	}

	pb_iid name_iid = emit_intern_str(w, name);

	emit_track_slice_start(clamp_ts(e->ts), track_uuid,
			       iid_str(name_iid, name), IID_CAT_CUDA_API) {
		emit_callstack(w, e->cuda_api.cuda_stack_id);

		emit_flow_id(((u64)task.pid << 32) | e->cuda_api.corr_id);
	}

	emit_track_slice_end(clamp_ts(e->cuda_api.end_ts), track_uuid,
			     iid_str(name_iid, name), IID_CAT_CUDA_API);


	return 0;
}

typedef int (*event_fn)(struct worker_state *w, const struct wevent *e);

static event_fn ev_fns[] = {
	[EV_TIMER] = process_timer,
	[EV_SWITCH] = process_switch,
	[EV_WAKEUP_NEW] = process_wakeup_new,
	//[EV_WAKEUP] = process_wakeup,
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
	[EV_SCX_DSQ_END] = process_scx_dsq_end,
	[EV_CUDA_KERNEL] = process_cuda_kernel,
	[EV_CUDA_MEMCPY] = process_cuda_memcpy,
	[EV_CUDA_MEMSET] = process_cuda_memset,
	[EV_CUDA_SYNC] = process_cuda_sync,
	[EV_CUDA_API] = process_cuda_api,
};

static int process_event(struct worker_state *w, const struct wevent *e)
{
	event_fn ev_fn;

	if (!is_ts_in_range(e->ts))
		return 0;

	if (e->kind >= ARRAY_SIZE(ev_fns) || !(ev_fn = ev_fns[e->kind])) {
		eprintf("UNHANDLED EVENT %d\n", e->kind);
		exit(1);
		return 0;
	}

	return ev_fn(w, e);
}

int emit_trace(struct worker_state *w)
{
	int err;

	wprintf("Generating trace...\n");

	emit_pmu_intern_names(w, cur_stream);

	if (env.capture_requests)
		emit_track_descr(cur_stream, TRACK_UUID_REQUESTS, 0, "REQUESTS", 1000);
	if (env.capture_cuda)
		emit_track_descr(cur_stream, TRACK_UUID_CUDA, 0, "CUDA", 2000);

	if (env.requested_stack_traces) {
		struct wprof_stacks_hdr *shdr = wprof_stacks_hdr(w->dump_hdr);
		w->stacks_used = calloc((shdr->stack_cnt + 63) / 64, sizeof(u64));
		w->frames_used = calloc((shdr->frame_cnt + 63) / 64, sizeof(u64));
	}

	struct wevent_record *rec;
	wevent_for_each_event(rec, w->dump_hdr) {
		err = process_event(w, rec->e);
		if (err) {
			eprintf("Failed to process event #%d (kind %d, offset %zu): %d\n",
				rec->idx, rec->e->kind, (void *)rec->e - (void *)w->dump_hdr, err);
			return err; /* YEAH, I know about all the clean up, whatever */
		}
	}

	if (env.emit_sched_view) {
		for (int cpu = 0; cpu < w->ftrace_bundle_cnt; cpu++) {
			flush_ftrace_bundle(w, cpu);
		}
	}

	if (env.requested_stack_traces) {
		err = generate_stack_traces(w);
		if (err) {
			eprintf("Failed to append stack traces to trace '%s': %d\n", env.trace_path, err);
			return err;
		}
	}

	return 0;
}
