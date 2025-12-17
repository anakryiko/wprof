/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __PROTOBUF_H_
#define __PROTOBUF_H_

#include "utils.h"
#include "wprof.h"
#include "pb_common.h"
#include "pb_encode.h"
#include "perfetto_trace.pb.h"

typedef u32 pb_iid;

typedef perfetto_protos_TracePacket TracePacket;
typedef perfetto_protos_TrackEvent TrackEvent;
typedef perfetto_protos_DebugAnnotation DebugAnnotation;
typedef perfetto_protos_InternedString InternedString;
typedef perfetto_protos_FtraceEvent FtraceEvent;
typedef perfetto_protos_FtraceEventBundle FtraceEventBundle;
typedef perfetto_protos_SchedSwitchFtraceEvent SchedSwitchFtraceEvent;
typedef perfetto_protos_SchedWakingFtraceEvent SchedWakingFtraceEvent;
typedef perfetto_protos_SchedWakeupNewFtraceEvent SchedWakeupNewFtraceEvent;

/* from include/linux/interrupt.h */
enum irq_vec {
	HI_SOFTIRQ=0,
	TIMER_SOFTIRQ,
	NET_TX_SOFTIRQ,
	NET_RX_SOFTIRQ,
	BLOCK_SOFTIRQ,
	IRQ_POLL_SOFTIRQ,
	TASKLET_SOFTIRQ,
	SCHED_SOFTIRQ,
	HRTIMER_SOFTIRQ,
	RCU_SOFTIRQ,

	NR_SOFTIRQS
};

const char *softirq_str(int vec_nr);
const char *ipi_kind_str(enum wprof_ipi_kind kind);

enum waking_reason {
	WREASON_UNKNOWN,
	WREASON_WOKEN,
	WREASON_WOKEN_NEW,
	WREASON_PREEMPTED,
	WREASON_INVALID,

	NR_WREASON,
};

enum waking_reason wreason_enum(enum waking_flags flags);
const char *wreason_str(enum waking_flags flags);

/* numeric values match CUPTI_ACTIVITY_MEMCPY_KIND_xxx definitions */
enum cuda_memcpy_kind {
	CUDA_MEMCPY_UNKN = 0,

	CUDA_MEMCPY_HTOD = 1,
	CUDA_MEMCPY_DTOH = 2,
	CUDA_MEMCPY_HTOA = 3,
	CUDA_MEMCPY_ATOH = 4,
	CUDA_MEMCPY_ATOA = 5,
	CUDA_MEMCPY_ATOD = 6,
	CUDA_MEMCPY_DTOA = 7,
	CUDA_MEMCPY_DTOD = 8,
	CUDA_MEMCPY_HTOH = 9,
	CUDA_MEMCPY_PTOP = 10,

	NR_CUDA_MEMCPY_KIND,
};

enum cuda_memory_kind {
	CUDA_MEM_UNKN = 0,

	CUDA_MEM_PAGEABLE = 1,		/* CUPTI_ACTIVITY_MEMORY_KIND_PAGEABLE */
	CUDA_MEM_PINNED = 2,		/* CUPTI_ACTIVITY_MEMORY_KIND_PINNED */
	CUDA_MEM_DEVICE = 3,		/* CUPTI_ACTIVITY_MEMORY_KIND_DEVICE */
	CUDA_MEM_ARRAY = 4,		/* CUPTI_ACTIVITY_MEMORY_KIND_ARRAY */
	CUDA_MEM_MANAGED = 5,		/* CUPTI_ACTIVITY_MEMORY_KIND_MANAGED */
	CUDA_MEM_DEVICE_STATIC = 6,	/* CUPTI_ACTIVITY_MEMORY_KIND_DEVICE_STATIC */
	CUDA_MEM_MANAGED_STATIC = 7,	/* CUPTI_ACTIVITY_MEMORY_KIND_MANAGED_STATIC */

	NR_CUDA_MEMORY_KIND,
};

enum cuda_sync_type {
	CUDA_SYNC_UNKN = 0,

	CUDA_SYNC_EVENT_SYNC = 1,	/* CUPTI_ACTIVITY_SYNCHRONIZATION_TYPE_EVENT_SYNCHRONIZE */
	CUDA_SYNC_STREAM_WAIT_EVENT = 2,/* CUPTI_ACTIVITY_SYNCHRONIZATION_TYPE_STREAM_WAIT_EVENT */
	CUDA_SYNC_STREAM_SYNC = 3,	/* CUPTI_ACTIVITY_SYNCHRONIZATION_TYPE_STREAM_SYNCHRONIZE */
	CUDA_SYNC_CONTEXT_SYNC = 4,	/* CUPTI_ACTIVITY_SYNCHRONIZATION_TYPE_CONTEXT_SYNCHRONIZE */

	NR_CUDA_SYNC_TYPE,
};

const char *cuda_memcpy_kind_str(enum cuda_memcpy_kind);
const char *cuda_sync_type_str(int type);
const char *cuda_memory_kind_str(int kind);

enum pb_static_iid {
	IID_NONE = 0,

	CAT_START_IID, __CAT_RESET_IID = CAT_START_IID - 1,
		IID_CAT_ONCPU,					/* ONCPU */
		IID_CAT_OFFCPU,					/* OFFCPU */
		IID_CAT_HARDIRQ,				/* HARDIRQ */
		IID_CAT_SOFTIRQ,				/* SOFTIRQ */
		IID_CAT_WQ,					/* WQ */
		IID_CAT_TIMER,					/* TIMER */
		IID_CAT_EXEC,					/* EXEC */
		IID_CAT_EXIT,					/* EXIT */
		IID_CAT_FREE,					/* FREE */
		IID_CAT_WAKEUP,					/* WAKEUP */
		IID_CAT_WAKER_NEW,				/* WAKER_NEW */
		IID_CAT_WAKEE_NEW,				/* WAKEE_NEW */
		IID_CAT_WAKER,					/* WAKER */
		IID_CAT_WAKEE,					/* WAKEE */
		IID_CAT_PREEMPTOR,				/* PREEMPTOR */
		IID_CAT_PREEMPTEE,				/* PREEMPTEE */
		IID_CAT_WAKER_UNKN,				/* WAKER_UNKNOWN */
		IID_CAT_WAKEE_UNKN,				/* WAKEE_UNKNOWN */
		IID_CAT_FORKING,				/* FORKING */
		IID_CAT_FORKED,					/* FORKED */
		IID_CAT_RENAME,					/* RENAME */
		IID_CAT_IPI,					/* IPI */
		IID_CAT_IPI_SEND,				/* IPI_SEND */
		IID_CAT_REQUEST,				/* REQUEST */
		IID_CAT_REQUEST_THREAD,				/* REQUEST_THREAD */
		IID_CAT_REQUEST_ONCPU,				/* REQUEST_ONCPU */
		IID_CAT_REQUEST_OFFCPU,				/* REQUEST_OFFCPU */
		IID_CAT_REQUEST_BEGIN,				/* REQUEST_BEGIN */
		IID_CAT_REQUEST_SET,				/* REQUEST_SET */
		IID_CAT_REQUEST_UNSET,				/* REQUEST_UNSET */
		IID_CAT_REQUEST_END,				/* REQUEST_END */
		IID_CAT_REQUEST_TASK_ENQUEUE,			/* REQUEST_TASK_ENQUEUE */
		IID_CAT_REQUEST_TASK_DEQUEUE,			/* REQUEST_TASK_DEQUEUE */
		IID_CAT_REQUEST_TASK_COMPLETE,			/* REQUEST_TASK_COMPLETE */
		IID_CAT_CUDA_KERNEL, 				/* CUDA_KERNEL */
		IID_CAT_CUDA_MEMCPY, 				/* CUDA_MEMCPY */
		IID_CAT_CUDA_API, 				/* CUDA_API */
		IID_CAT_CUDA_MEMSET, 				/* CUDA_MEMSET */
		IID_CAT_CUDA_SYNC,				/* CUDA_SYNC */
		IID_CAT_SCX_DSQ,				/* SCX_DSQ */
	CAT_END_IID,

	NAME_START_IID, __NAME_RESET_IID = NAME_START_IID - 1,
		IID_NAME_TIMER,					/* TIMER */
		IID_NAME_EXEC,					/* EXEC */
		IID_NAME_EXIT,					/* EXIT */
		IID_NAME_FREE,					/* FREE */
		IID_NAME_WAKEUP,				/* WAKEUP */
		IID_NAME_WAKER_NEW,				/* WAKER_NEW */
		IID_NAME_WAKEE_NEW,				/* WAKEE_NEW */
		IID_NAME_WAKER,					/* WAKER */
		IID_NAME_WAKEE,					/* WAKEE */
		IID_NAME_PREEMPTOR,				/* PREEMPTOR */
		IID_NAME_PREEMPTEE,				/* PREEMPTEE */
		IID_NAME_WAKER_UNKN,				/* WAKER_UNKNOWN */
		IID_NAME_WAKEE_UNKN,				/* WAKEE_UNKNOWN */
		IID_NAME_FORKING,				/* FORKING */
		IID_NAME_FORKED,				/* FORKED */
		IID_NAME_RENAME,				/* RENAME */
		IID_NAME_HARDIRQ,				/* HARDIRQ */
		IID_NAME_SOFTIRQ,				/* SOFTIRQ:... */
		IID_NAME_SOFTIRQ_LAST = IID_NAME_SOFTIRQ + NR_SOFTIRQS - 1,
		IID_NAME_IPI,					/* IPI:... */
		IID_NAME_IPI_LAST = IID_NAME_IPI + NR_IPIS - 1,
		IID_NAME_IPI_SEND,				/* IPI_SEND:... */
		IID_NAME_IPI_SEND_LAST = IID_NAME_IPI_SEND + NR_IPIS - 1,
		IID_NAME_RUNNING,				/* RUNNING */
		IID_NAME_WAITING,				/* WAITING */
		IID_NAME_PREEMPTED,				/* PREEMPTED */
		IID_NAME_REQUEST_BEGIN,				/* REQUEST_BEGIN */
		IID_NAME_REQUEST_SET,				/* REQUEST_SET */
		IID_NAME_REQUEST_UNSET,				/* REQUEST_UNSET */
		IID_NAME_REQUEST_END,				/* REQUEST_END */
		IID_NAME_REQUEST_TASK_ENQUEUE,			/* REQUEST_TASK_ENQUEUE */
		IID_NAME_REQUEST_TASK_DEQUEUE,			/* REQUEST_TASK_DEQUEUE */
		IID_NAME_REQUEST_TASK_COMPLETE,			/* REQUEST_TASK_COMPLETE */
		IID_NAME_CUDA_MEMCPY,				/* cudaMemcpy:... */
		IID_NAME_CUDA_MEMCPY_LAST = IID_NAME_CUDA_MEMCPY + NR_CUDA_MEMCPY_KIND - 1,
		IID_NAME_CUDA_MEMSET,				/* memset:... */
		IID_NAME_CUDA_MEMSET_LAST = IID_NAME_CUDA_MEMSET + NR_CUDA_MEMORY_KIND - 1,
		IID_NAME_CUDA_SYNC,				/* sync:... */
		IID_NAME_CUDA_SYNC_LAST = IID_NAME_CUDA_SYNC + NR_CUDA_SYNC_TYPE - 1,
	NAME_END_IID,

	ANNK_START_IID, __ANNK_RESET_IID = ANNK_START_IID - 1,
		IID_ANNK_CPU,					/* cpu */
		IID_ANNK_NUMA_NODE,				/* numa_node */
		IID_ANNK_SWITCH_TO,				/* switch_to */
		IID_ANNK_SWITCH_TO_TID,				/* switch_to_tid */
		IID_ANNK_SWITCH_TO_PID,				/* switch_to_pid */
		IID_ANNK_SWITCH_FROM,				/* switch_from */
		IID_ANNK_SWITCH_FROM_TID,			/* switch_from_tid */
		IID_ANNK_SWITCH_FROM_PID,			/* switch_from_pid */
		IID_ANNK_RENAMED_TO,				/* renamed_to */
		IID_ANNK_WAKER_CPU,				/* waker_cpu */
		IID_ANNK_WAKER_NUMA_NODE,			/* waker_numa_node */
		IID_ANNK_WAKING_DELAY_US,			/* waking_delay_us */
		IID_ANNK_COMPOUND_DELAY_US,			/* compound_delay_us */
		IID_ANNK_COMPOUND_CHAIN_LEN,			/* compound_chain_len */
		IID_ANNK_WAKER,					/* waker */
		IID_ANNK_WAKER_TID,				/* waker_tid */
		IID_ANNK_WAKER_PID,				/* waker_pid */
		IID_ANNK_WAKING_REASON,				/* waking_reason */
		IID_ANNK_OFFCPU_REASON,				/* offcpu_reason */
		IID_ANNK_OFFCPU_DUR_US,				/* offcpu_dur_us */
		IID_ANNK_WAKEE,					/* wakee */
		IID_ANNK_WAKEE_TID,				/* wakee_tid */
		IID_ANNK_WAKEE_PID,				/* wakee_pid */
		IID_ANNK_FORKED_INTO,				/* forked_into */
		IID_ANNK_FORKED_INTO_TID,			/* forked_into_tid */
		IID_ANNK_FORKED_INTO_PID,			/* forked_into_pid */
		IID_ANNK_FORKED_FROM,				/* forked_from */
		IID_ANNK_FORKED_FROM_TID,			/* forked_from_tid */
		IID_ANNK_FORKED_FROM_PID,			/* forked_from_pid */
		IID_ANNK_FILENAME,				/* filename */
		IID_ANNK_TID_CHANGED_FROM,			/* tid_changed_from */
		IID_ANNK_OLD_NAME,				/* old_name */
		IID_ANNK_NEW_NAME,				/* new_name */
		IID_ANNK_ACTION,				/* action */
		IID_ANNK_IRQ,					/* irq */
		IID_ANNK_SENDER_CPU,				/* sender_cpu */
		IID_ANNK_TARGET_CPU,				/* target_cpu */
		IID_ANNK_IPI_DELAY_US,				/* ipi_delay_us */
		IID_ANNK_PERF_CPU_CYCLES,			/* cpu_cycles_kilo */
		IID_ANNK_PERF_CPU_INSNS,			/* cpu_insns_kilo */
		IID_ANNK_PERF_CACHE_HITS,			/* cache_hits_kilo */
		IID_ANNK_PERF_CACHE_MISSES,			/* cache_misses_kilo */
		IID_ANNK_PERF_STALL_CYCLES_FE,			/* stalled_cycles_fe_kilo */
		IID_ANNK_PERF_STALL_CYCLES_BE,			/* stalled_cycles_be_kilo */
		IID_ANNK_REQ_NAME,				/* req_name */
		IID_ANNK_REQ_ID,				/* req_id */
		IID_ANNK_REQ_LATENCY_US,			/* req_latency_us */
		IID_ANNK_SCX_LAYER_ID,				/* scx_layer_id */
		IID_ANNK_SCX_DSQ_ID,				/* scx_dsq_id */
		IID_ANNK_REQ_TASK_ID,				/* task_id */
		IID_ANNK_REQ_WAIT_TIME_NS,			/* wait_time_ns */
		IID_ANNK_CUDA_DEVICE_ID,			/* device_id */
		IID_ANNK_CUDA_STREAM_ID,			/* stream_id */
		IID_ANNK_CUDA_BLOCK_X,				/* block_x */
		IID_ANNK_CUDA_BLOCK_Y,				/* block_y */
		IID_ANNK_CUDA_BLOCK_Z,				/* block_z */
		IID_ANNK_CUDA_GRID_X,				/* grid_x */
		IID_ANNK_CUDA_GRID_Y,				/* grid_y */
		IID_ANNK_CUDA_GRID_Z,				/* grid_z */
		IID_ANNK_CUDA_KIND,				/* kind */
		IID_ANNK_CUDA_BYTE_CNT, 			/* byte_cnt */
		IID_ANNK_CUDA_SRC_KIND,				/* src_kind */
		IID_ANNK_CUDA_DST_KIND,				/* dst_kind */
		IID_ANNK_CUDA_CONTEXT_ID,			/* context_id */
		IID_ANNK_CUDA_EVENT_ID,				/* event_id */
		IID_ANNK_CUDA_MANGLED_NAME,			/* mangled_name */
		IID_ANNK_CUDA_GPU_DELAY_US,			/* gpu_delay_us */
	ANNK_END_IID,

	ANNV_START_IID, __ANNV_RESET_IID = ANNV_START_IID - 1,
		IID_ANNV_SOFTIRQ_ACTION,			/* sched, net-rx, rcu, ... */
		IID_ANNV_SOFTIRQ_ACTION_LAST = IID_ANNV_SOFTIRQ_ACTION + NR_SOFTIRQS - 1,
		IID_ANNV_WAKING_REASON,				/* preempted, waking, etc. */
		IID_ANNV_WAKING_REASON_LAST = IID_ANNV_WAKING_REASON + NR_WREASON - 1,
		IID_ANNV_OFFCPU_BLOCKED,			/* blocked */
		IID_ANNV_OFFCPU_PREEMPTED,			/* preempted */
		IID_ANNV_CUDA_MEMCPY_KIND,			/* DtoH, HtoD, etc. */
		IID_ANNV_CUDA_MEMCPY_KIND_LAST = IID_ANNV_CUDA_MEMCPY_KIND + NR_CUDA_MEMCPY_KIND - 1,
		IID_ANNV_CUDA_MEMORY_KIND,			/* pageable, pinned, device, etc. */
		IID_ANNV_CUDA_MEMORY_KIND_LAST = IID_ANNV_CUDA_MEMORY_KIND + NR_CUDA_MEMORY_KIND - 1,
		IID_ANNV_CUDA_SYNC_TYPE,			/* event_sync, stream_sync, etc. */
		IID_ANNV_CUDA_SYNC_TYPE_LAST = IID_ANNV_CUDA_SYNC_TYPE + NR_CUDA_SYNC_TYPE - 1,
	ANNV_END_IID,

	IID_FIXED_LAST_ID,
};

const char *pb_static_str(enum pb_static_iid);

bool file_stream_cb(pb_ostream_t *stream, const uint8_t *buf, size_t count);

struct pb_str {
	int iid;
	const char *s;
};

#define iid_str(id, str) ((struct pb_str){.iid=(id),.s=(str)})

#define PB_INIT(field) .has_##field = true, .field

#define PB_SEQ_ID_THREADS 0x7
#define PB_SEQ_ID_GENERIC 0x7

#define PB_TRUST_SEQ_ID(id) \
	.which_optional_trusted_packet_sequence_id = perfetto_protos_TracePacket_trusted_packet_sequence_id_tag, \
	.optional_trusted_packet_sequence_id = { (id) }

#define PB_NONE ((pb_callback_t){})
#define PB_ONEOF(field, _type) .which_##field = perfetto_protos_##_type##_tag, .field

bool enc_string(pb_ostream_t *stream, const pb_field_t *field, void * const *arg);
bool enc_string_iid(pb_ostream_t *stream, const pb_field_t *field, void * const *arg);

#define PB_STRING(s) ((pb_callback_t){{.encode=enc_string}, (void *)(s)})
#define PB_STRING_IID(iid) ((pb_callback_t){{.encode=enc_string_iid}, (void *)(unsigned long)(iid)})

#define PB_NAME(_type, field, iid, name_str)							\
	.which_##field = (iid && !env.pb_disable_interns)					\
			 ? perfetto_protos_##_type##_name_iid_tag				\
			 : perfetto_protos_##_type##_name_tag,					\
	.field = { .name = (iid && !env.pb_disable_interns)					\
			   ? (pb_callback_t){.funcs={(void *)(long)(iid)}}			\
			   : PB_STRING(name_str) }

struct pb_id_set {
	u64 *ids;
	int cnt;
	int cap;
};

void ids_reset(struct pb_id_set *ids);
void ids_append_id(struct pb_id_set *ids, u64 id);

bool enc_flow_id(pb_ostream_t *stream, const pb_field_t *field, void * const *arg);
#define PB_FLOW_ID(id) ((pb_callback_t){{.encode=enc_flow_id}, (void *)(id)})

bool enc_flow_ids(pb_ostream_t *stream, const pb_field_t *field, void * const *arg);
#define PB_FLOW_IDS(ids) ((pb_callback_t){{.encode=enc_flow_ids}, (void *)(ids)})

enum pb_ann_kind {
	PB_ANN_BOOL,
	PB_ANN_UINT,
	PB_ANN_INT,
	PB_ANN_DOUBLE,
	PB_ANN_PTR,
	PB_ANN_STR,
	PB_ANN_STR_IID,
};

struct pb_ann_val {
	enum pb_ann_kind kind;
	union {
		bool val_bool;
		uint64_t val_uint;
		int64_t val_int;
		double val_double;
		const void *val_ptr;
		const char *val_str;
		u64 val_str_iid;
	};
};

struct pb_ann_kv {
	const char *name;
	u64 name_iid;
	struct pb_ann_val val;
};

struct pb_ann {
	const char *name;
	u64 name_iid;
	struct pb_ann_kv **dict;
	struct pb_ann_val **arr;
	struct pb_ann_val *val;
};

#define MAX_ANN_CNT 16
struct pb_anns {
	int cnt;
	struct pb_ann *ann_ptrs[MAX_ANN_CNT];
	struct pb_ann anns[MAX_ANN_CNT];
	struct pb_ann_val vals[MAX_ANN_CNT];
};

void anns_reset(struct pb_anns *anns);
void anns_add_ann(struct pb_anns *anns, struct pb_ann *ann);
struct pb_ann_val *anns_add_val(struct pb_anns *anns, pb_iid key_iid, const char *key);
void anns_add_str(struct pb_anns *anns, pb_iid key_iid, const char *key, pb_iid value_iid, const char *value);
void anns_add_uint(struct pb_anns *anns, pb_iid key_iid, const char *key, uint64_t value);
void anns_add_int(struct pb_anns *anns, pb_iid key_iid, const char *key, int64_t value);
void anns_add_double(struct pb_anns *anns, pb_iid key_iid, const char *key, double value);
void ann_set_value(DebugAnnotation *ann_proto, const struct pb_ann_val *val);
bool enc_ann_dict(pb_ostream_t *stream, const pb_field_t *field, void * const *arg);
bool enc_ann_arr(pb_ostream_t *stream, const pb_field_t *field, void * const *arg);
bool enc_annotations(pb_ostream_t *stream, const pb_field_t *field, void * const *arg);

#define PB_ANNOTATIONS(p) ((pb_callback_t){{.encode=enc_annotations}, (void *)(p)})

struct pb_str_iid {
	pb_iid iid;
	const char *s;
};

struct pb_str_iid_range {
	int start_id;
	int end_id;
};

struct pb_str_iids {
	int cnt, cap;
	int *iids;
	const char **strs;
};

bool enc_str_iid(pb_ostream_t *stream, const pb_field_t *field, void * const *arg);
bool enc_str_iid_range(pb_ostream_t *stream, const pb_field_t *field, void * const *arg);
bool enc_str_iids(pb_ostream_t *stream, const pb_field_t *field, void * const *arg);

#define PB_STR_IID(iid, str) ((pb_callback_t){{.encode=enc_str_iid}, (void *)&((struct pb_str_iid){ iid, str })})
#define PB_STR_IID_RANGE(start_id, end_id) ((pb_callback_t){{.encode=enc_str_iid_range},	\
					    (void *)&((struct pb_str_iid_range){ start_id, end_id })})
#define PB_STR_IIDS(p) ((pb_callback_t){{.encode=enc_str_iids}, (void *)(p)})

struct pb_mapping {
	int iid;
	u64 start;
	u64 end;
	u64 start_offset;
};

struct pb_mapping_iids {
	int cnt, cap;
	struct pb_mapping *mappings;
};

bool enc_mappings(pb_ostream_t *stream, const pb_field_t *field, void * const *arg);

#define PB_MAPPINGS(p) ((pb_callback_t){{.encode=enc_mappings}, (void *)(p)})

struct pb_frame {
	int iid;
	int function_name_id;
	int mapping_id;
	u64 rel_pc;
};

struct pb_frame_iids {
	int cnt, cap;
	struct pb_frame *frames;
};

bool enc_frames(pb_ostream_t *stream, const pb_field_t *field, void * const *arg);

#define PB_FRAMES(p) ((pb_callback_t){{.encode=enc_frames}, (void *)(p)})

struct pb_callstack {
	int iid;
	int frame_cnt;
	int *frame_ids;
};

struct pb_callstack_iids {
	int cnt, cap;
	struct pb_callstack *callstacks;
};

bool enc_callstack_frame_ids(pb_ostream_t *stream, const pb_field_t *field, void * const *arg);

#define PB_CALLSTACK_FRAME_IDS(p) ((pb_callback_t){{.encode=enc_callstack_frame_ids}, (void *)(p)})

bool enc_callstacks(pb_ostream_t *stream, const pb_field_t *field, void * const *arg);

#define PB_CALLSTACKS(p) ((pb_callback_t){{.encode=enc_callstacks}, (void *)(p)})

void reset_str_iids(struct pb_str_iids *iids);
void append_str_iid(struct pb_str_iids *iids, int iid, const char *s);
void append_mapping_iid(struct pb_mapping_iids *iids, int iid, u64 start, u64 end, u64 offset);
void append_frame_iid(struct pb_frame_iids *iids, int iid, int mapping_iid, int fname_iid, u64 rel_pc);
void append_callstack_frame_iid(struct pb_callstack_iids *iids, int iid, int frame_iid);

struct pb_clock {
	uint32_t clock_id;
	uint64_t timestamp;
};

bool enc_clock(pb_ostream_t *stream, const pb_field_t *field, void * const *arg);

#define PB_CLOCK(s) ((pb_callback_t){{.encode=enc_clock}, (void *)(s)})

void enc_trace_packet(pb_ostream_t *stream, TracePacket *msg);

int init_pb_trace(pb_ostream_t *stream);

struct hashmap;

struct str_iid_domain {
	struct hashmap *str_iids;
	int next_str_iid;
	const char *domain_desc;
};

struct stack_trace_iids {
	struct pb_str_iids func_names;
	struct pb_frame_iids frames;
	struct pb_callstack_iids callstacks;
	struct pb_mapping_iids mappings;
};

pb_iid str_iid_for(struct str_iid_domain *d, const char *s, bool *new_iid, const char **out_str);

/* FtraceEvent buffering for per-CPU bundles */
#define MAX_FTRACE_EVENTS_PER_BUNDLE 1024

struct ftrace_event_buffer {
	FtraceEvent *events;
	int cnt;
	int cap;
};

struct ftrace_cpu_bundle {
	struct ftrace_event_buffer buffer;
};

void ftrace_buffer_init(struct ftrace_event_buffer *buf);
void ftrace_buffer_reset(struct ftrace_event_buffer *buf);
void ftrace_buffer_free(struct ftrace_event_buffer *buf);
FtraceEvent *ftrace_buffer_add(struct ftrace_event_buffer *buf);

bool enc_ftrace_events(pb_ostream_t *stream, const pb_field_t *field, void * const *arg);
#define PB_FTRACE_EVENTS(buf) ((pb_callback_t){{.encode=enc_ftrace_events}, (void *)(buf)})

#endif /* __PROTOBUF_H_ */
