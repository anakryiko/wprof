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

#include "protobuf.h"
#include "env.h"

bool file_stream_cb(pb_ostream_t *stream, const uint8_t *buf, size_t count)
{
	FILE *f = stream->state;

	return fwrite(buf, 1, count, f) == count;
}

static const char *softirq_str_map[] = {
	[HI_SOFTIRQ] = "hi",
	[TIMER_SOFTIRQ] = "timer",
	[NET_TX_SOFTIRQ] = "net-tx",
	[NET_RX_SOFTIRQ] = "net-rx",
	[BLOCK_SOFTIRQ] = "block",
	[IRQ_POLL_SOFTIRQ] = "irq-poll",
	[TASKLET_SOFTIRQ] = "tasklet",
	[SCHED_SOFTIRQ] = "sched",
	[HRTIMER_SOFTIRQ] = "hrtimer",
	[RCU_SOFTIRQ] = "rcu",
};

const char *softirq_str(int vec_nr)
{
	if (vec_nr >= 0 && vec_nr < ARRAY_SIZE(softirq_str_map))
		return softirq_str_map[vec_nr];
	return NULL;
}

const char *ipi_kind_str(enum wprof_ipi_kind kind)
{
	switch (kind) {
		case IPI_SINGLE: return "single";
		case IPI_MULTI:  return "multi";
		case IPI_RESCHED: return "resched";
		default: return "???";
	}
}

static const char *wreason_str_map[] = {
	[WREASON_UNKNOWN] = "unknown",
	[WREASON_WOKEN] = "woken",
	[WREASON_WOKEN_NEW] = "woken_new",
	[WREASON_PREEMPTED] = "preempted",
	[WREASON_INVALID] = "???",
};

enum waking_reason wreason_enum(enum waking_flags flags)
{
	switch (flags) {
		case WF_UNKNOWN:   return WREASON_UNKNOWN;
		case WF_WOKEN:     return WREASON_WOKEN;
		case WF_WOKEN_NEW: return WREASON_WOKEN_NEW;
		case WF_PREEMPTED: return WREASON_PREEMPTED;
		default:           return WREASON_UNKNOWN;
	}
}

const char *wreason_str(enum waking_flags flags)
{
	return wreason_str_map[wreason_enum(flags)];
}


/*
 * PROTOBUF UTILS
 */
static const char *pb_static_strs[] = {
	[IID_CAT_ONCPU] = "ONCPU",
	[IID_CAT_OFFCPU] = "OFFCPU",
	[IID_CAT_HARDIRQ] = "HARDIRQ",
	[IID_CAT_SOFTIRQ] = "SOFTIRQ",
	[IID_CAT_WQ] = "WQ",
	[IID_CAT_TIMER] = "TIMER",
	[IID_CAT_EXEC] = "EXEC",
	[IID_CAT_EXIT] = "EXIT",
	[IID_CAT_FREE] = "FREE",
	[IID_CAT_WAKEUP] = "WAKEUP",
	[IID_CAT_WAKEUP_NEW] = "WAKEUP_NEW",
	[IID_CAT_WAKING] = "WAKING",
	[IID_CAT_WOKEN_NEW] = "WOKEN_NEW",
	[IID_CAT_WOKEN] = "WOKEN",
	[IID_CAT_FORKING] = "FORKING",
	[IID_CAT_FORKED] = "FORKED",
	[IID_CAT_RENAME] = "RENAME",
	[IID_CAT_IPI] = "IPI",
	[IID_CAT_IPI_SEND] = "IPI_SEND",

	[IID_NAME_TIMER] = "TIMER",
	[IID_NAME_EXEC] = "EXEC",
	[IID_NAME_EXIT] = "EXIT",
	[IID_NAME_FREE] = "FREE",
	[IID_NAME_WAKEUP] = "WAKEUP",
	[IID_NAME_WAKEUP_NEW] = "WAKEUP_NEW",
	[IID_NAME_WAKING] = "WAKING",
	[IID_NAME_WOKEN_NEW] = "WOKEN_NEW",
	[IID_NAME_WOKEN] = "WOKEN",
	[IID_NAME_FORKING] = "FORKING",
	[IID_NAME_FORKED] = "FORKED",
	[IID_NAME_RENAME] = "RENAME",
	[IID_NAME_HARDIRQ] = "HARDIRQ",
	[IID_NAME_SOFTIRQ + HI_SOFTIRQ] = "SOFTIRQ:hi",
	[IID_NAME_SOFTIRQ + TIMER_SOFTIRQ] = "SOFTIRQ:timer",
	[IID_NAME_SOFTIRQ + NET_TX_SOFTIRQ] = "SOFTIRQ:net-tx",
	[IID_NAME_SOFTIRQ + NET_RX_SOFTIRQ] = "SOFTIRQ:net-rx",
	[IID_NAME_SOFTIRQ + BLOCK_SOFTIRQ] = "SOFTIRQ:block",
	[IID_NAME_SOFTIRQ + IRQ_POLL_SOFTIRQ] = "SOFTIRQ:irq-poll",
	[IID_NAME_SOFTIRQ + TASKLET_SOFTIRQ] = "SOFTIRQ:tasklet",
	[IID_NAME_SOFTIRQ + SCHED_SOFTIRQ] = "SOFTIRQ:sched",
	[IID_NAME_SOFTIRQ + HRTIMER_SOFTIRQ] = "SOFTIRQ:hrtimer",
	[IID_NAME_SOFTIRQ + RCU_SOFTIRQ] = "SOFTIRQ:rcu",
	[IID_NAME_IPI + IPI_INVALID] = "IPI:???",
	[IID_NAME_IPI + IPI_SINGLE] = "IPI:single",
	[IID_NAME_IPI + IPI_MULTI] = "IPI:multi",
	[IID_NAME_IPI + IPI_RESCHED] = "IPI:resched",
	[IID_NAME_IPI_SEND + IPI_INVALID] = "IPI_SEND:???",
	[IID_NAME_IPI_SEND + IPI_SINGLE] = "IPI_SEND:single",
	[IID_NAME_IPI_SEND + IPI_MULTI] = "IPI_SEND:multi",
	[IID_NAME_IPI_SEND + IPI_RESCHED] = "IPI_SEND:resched",

	[IID_ANNK_CPU] = "cpu",
	[IID_ANNK_NUMA_NODE] = "numa_node",
	[IID_ANNK_SWITCH_TO] = "switch_to",
	[IID_ANNK_SWITCH_TO_TID] = "switch_to_tid",
	[IID_ANNK_SWITCH_TO_PID] = "switch_to_pid",
	[IID_ANNK_SWITCH_FROM] = "switch_from",
	[IID_ANNK_SWITCH_FROM_TID] = "switch_from_tid",
	[IID_ANNK_SWITCH_FROM_PID] = "switch_from_pid",
	[IID_ANNK_CPU_MEGA_CYCLES] = "cpu_mega_cycles",
	[IID_ANNK_RENAMED_TO] = "renamed_to",
	[IID_ANNK_WAKING_CPU] = "waking_cpu",
	[IID_ANNK_WAKING_NUMA_NODE] = "waking_numa_node",
	[IID_ANNK_WAKING_DELAY_US] = "waking_delay_us",
	[IID_ANNK_WAKING_BY] = "waking_by",
	[IID_ANNK_WAKING_BY_TID] = "waking_by_tid",
	[IID_ANNK_WAKING_BY_PID] = "waking_by_pid",
	[IID_ANNK_WAKING_REASON] = "waking_reason",
	[IID_ANNK_WAKING_TARGET] = "waking_target",
	[IID_ANNK_WAKING_TARGET_TID] = "waking_target_tid",
	[IID_ANNK_WAKING_TARGET_PID] = "waking_target_pid",
	[IID_ANNK_FORKED_INTO] = "forked_into",
	[IID_ANNK_FORKED_INTO_TID] = "forked_into_tid",
	[IID_ANNK_FORKED_INTO_PID] = "forked_into_pid",
	[IID_ANNK_FORKED_FROM] = "forked_from",
	[IID_ANNK_FORKED_FROM_TID] = "forked_from_tid",
	[IID_ANNK_FORKED_FROM_PID] = "forked_from_pid",
	[IID_ANNK_FILENAME] = "filename",
	[IID_ANNK_TID_CHANGED_FROM] = "tid_changed_from",
	[IID_ANNK_OLD_NAME] = "old_name",
	[IID_ANNK_NEW_NAME] = "new_name",
	[IID_ANNK_ACTION] = "action",
	[IID_ANNK_IRQ] = "irq",
	[IID_ANNK_SENDER_CPU] = "sender_cpu",
	[IID_ANNK_TARGET_CPU] = "target_cpu",
	[IID_ANNK_IPI_DELAY_US] = "ipi_delay_us",
	[IID_ANNK_PERF_CPU_CYCLES] = "cpu_cycles_kilo",
	[IID_ANNK_PERF_CPU_INSNS] = "cpu_insns_kilo",
	[IID_ANNK_PERF_CACHE_HITS] = "cache_hits_kilo",
	[IID_ANNK_PERF_CACHE_MISSES] = "cache_misses_kilo",
	[IID_ANNK_PERF_STALL_CYCLES_FE] = "stalled_cycles_fe_kilo",
	[IID_ANNK_PERF_STALL_CYCLES_BE] = "stalled_cycles_be_kilo",

	[IID_ANNV_SOFTIRQ_ACTION + HI_SOFTIRQ] = "hi",
	[IID_ANNV_SOFTIRQ_ACTION + TIMER_SOFTIRQ] = "timer",
	[IID_ANNV_SOFTIRQ_ACTION + NET_TX_SOFTIRQ] = "net-tx",
	[IID_ANNV_SOFTIRQ_ACTION + NET_RX_SOFTIRQ] = "net-rx",
	[IID_ANNV_SOFTIRQ_ACTION + BLOCK_SOFTIRQ] = "block",
	[IID_ANNV_SOFTIRQ_ACTION + IRQ_POLL_SOFTIRQ] = "irq-poll",
	[IID_ANNV_SOFTIRQ_ACTION + TASKLET_SOFTIRQ] = "tasklet",
	[IID_ANNV_SOFTIRQ_ACTION + SCHED_SOFTIRQ] = "sched",
	[IID_ANNV_SOFTIRQ_ACTION + HRTIMER_SOFTIRQ] = "hrtimer",
	[IID_ANNV_SOFTIRQ_ACTION + RCU_SOFTIRQ] = "rcu",

	[IID_ANNV_WAKING_REASON + WREASON_UNKNOWN] = "unknown",
	[IID_ANNV_WAKING_REASON + WREASON_WOKEN] = "woken",
	[IID_ANNV_WAKING_REASON + WREASON_WOKEN_NEW] = "woken_new",
	[IID_ANNV_WAKING_REASON + WREASON_PREEMPTED] = "preempted",
	[IID_ANNV_WAKING_REASON + WREASON_INVALID] = "???",
};

const char *pb_static_str(enum pb_static_iid iid)
{
	if (iid < 0 || iid >= ARRAY_SIZE(pb_static_strs) || !pb_static_strs[iid]) {
		fprintf(stderr, "Missing string value mapping for IID #%d!\n", iid);
		exit(1);
	}

	return pb_static_strs[iid];
}

bool enc_string(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const char *s = *arg;

	return pb_encode_tag_for_field(stream, field) &&
	       pb_encode_string(stream, (void *)s, strlen(s));
}

bool enc_string_iid(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	pb_iid iid = *(pb_iid *)arg;

	return pb_encode_tag_for_field(stream, field) &&
	       pb_encode_varint(stream, iid);
}

bool enc_flow_id(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	u64 flow_id = (u64)*arg;

	return pb_encode_tag_for_field(stream, field) &&
	       pb_encode_fixed64(stream, &flow_id);
}

void anns_reset(struct pb_anns *anns)
{
	anns->cnt = 0;
}

void anns_add_ann(struct pb_anns *anns, struct pb_ann *ann)
{
	if (anns->cnt == MAX_ANN_CNT) {
		fprintf(stderr, "Annotations overflow!\n");
		exit(1);
	}

	anns->ann_ptrs[anns->cnt++] = ann;
}

struct pb_ann_val *anns_add_val(struct pb_anns *anns, pb_iid key_iid, const char *key)
{
	struct pb_ann_val *val;
	struct pb_ann *ann;

	if (anns->cnt == ARRAY_SIZE(anns->anns)) {
		fprintf(stderr, "Annotations overflow!\n");
		exit(1);
	}

	val = &anns->vals[anns->cnt];
	ann = &anns->anns[anns->cnt];
	anns->ann_ptrs[anns->cnt++] = ann;

	ann->name = key;
	ann->name_iid = key_iid;
	ann->val = val;
	ann->dict = NULL;
	ann->arr = NULL;

	return val;
}

void anns_add_str(struct pb_anns *anns, pb_iid key_iid, const char *key,
			 pb_iid value_iid, const char *value)
{
	struct pb_ann_val *val = anns_add_val(anns, key_iid, key);

	if (value_iid && !env.pb_disable_interns) {
		val->kind = PB_ANN_STR_IID;
		val->val_str_iid = value_iid;
	} else {
		val->kind = PB_ANN_STR;
		val->val_str = value;
	}
}

void anns_add_uint(struct pb_anns *anns, pb_iid key_iid, const char *key, uint64_t value)
{
	struct pb_ann_val *val = anns_add_val(anns, key_iid, key);

	val->kind = PB_ANN_UINT;
	val->val_int = value;
}

void anns_add_int(struct pb_anns *anns, pb_iid key_iid, const char *key, int64_t value)
{
	struct pb_ann_val *val = anns_add_val(anns, key_iid, key);

	val->kind = PB_ANN_INT;
	val->val_int = value;
}

void anns_add_double(struct pb_anns *anns, pb_iid key_iid, const char *key, double value)
{
	struct pb_ann_val *val = anns_add_val(anns, key_iid, key);

	val->kind = PB_ANN_DOUBLE;
	val->val_double = value;
}

void ann_set_value(DebugAnnotation *ann_proto, const struct pb_ann_val *val)
{
	switch (val->kind) {
		case PB_ANN_BOOL:
			ann_proto->which_value = perfetto_protos_DebugAnnotation_bool_value_tag;
			ann_proto->value.bool_value = val->val_bool;
			break;
		case PB_ANN_UINT:
			ann_proto->which_value = perfetto_protos_DebugAnnotation_uint_value_tag;
			ann_proto->value.uint_value = val->val_uint;
			break;
		case PB_ANN_INT:
			ann_proto->which_value = perfetto_protos_DebugAnnotation_int_value_tag;
			ann_proto->value.int_value = val->val_int;
			break;
		case PB_ANN_DOUBLE:
			ann_proto->which_value = perfetto_protos_DebugAnnotation_double_value_tag;
			ann_proto->value.double_value = val->val_double;
			break;
		case PB_ANN_PTR:
			ann_proto->which_value = perfetto_protos_DebugAnnotation_pointer_value_tag;
			ann_proto->value.pointer_value = (uint64_t)val->val_ptr;
			break;
		case PB_ANN_STR:
			ann_proto->which_value = perfetto_protos_DebugAnnotation_string_value_tag;
			ann_proto->value.string_value = PB_STRING(val->val_str);
			break;
		case PB_ANN_STR_IID:
			ann_proto->which_value = perfetto_protos_DebugAnnotation_string_value_iid_tag;
			ann_proto->value.string_value_iid = val->val_str_iid;
			break;
	}
}

bool enc_ann_dict(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_ann *ann = *arg;
	struct pb_ann_kv **kvs = ann->dict;

	while (*kvs) {
		const struct pb_ann_kv *kv = *kvs;
		DebugAnnotation ann_proto = {
			PB_NAME(DebugAnnotation, name_field, kv->name_iid, kv->name),
		};

		if (!pb_encode_tag_for_field(stream, field))
			return false;

		ann_set_value(&ann_proto, &kv->val);

		if (!pb_encode_submessage(stream, perfetto_protos_DebugAnnotation_fields, &ann_proto))
			return false;
		kvs++;
	}

	return true;
}

bool enc_ann_arr(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_ann *ann = *arg;
	struct pb_ann_val **vals = ann->arr;

	while (*vals) {
		const struct pb_ann_val *v = *vals;
		DebugAnnotation ann_proto = {};

		ann_set_value(&ann_proto, v);

		if (!pb_encode_tag_for_field(stream, field))
			return false;

		if (!pb_encode_submessage(stream, perfetto_protos_DebugAnnotation_fields, &ann_proto))
			return false;
		vals++;
	}

	return true;
}

bool enc_annotations(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_anns *anns = *arg;

	for (int i = 0; i < anns->cnt; i++) {
		const struct pb_ann *ann = anns->ann_ptrs[i];
		DebugAnnotation ann_proto = {
			PB_NAME(DebugAnnotation, name_field, ann->name_iid, ann->name),
		};

		if (ann->dict)
			ann_proto.dict_entries = (pb_callback_t){{.encode=enc_ann_dict}, (void *)ann};
		if (ann->arr)
			ann_proto.array_values = (pb_callback_t){{.encode=enc_ann_arr}, (void *)ann};
		if (ann->val)
			ann_set_value(&ann_proto, ann->val);

		if (!pb_encode_tag_for_field(stream, field))
			return false;
		if (!pb_encode_submessage(stream, perfetto_protos_DebugAnnotation_fields, &ann_proto))
			return false;
	}

	return true;
}

bool enc_str_iid(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_str_iid *pair = *arg;
	InternedString pb = {
		PB_INIT(iid) = pair->iid,
		.str = PB_STRING(pair->s),
	};

	if (!pb_encode_tag_for_field(stream, field))
		return false;
	if (!pb_encode_submessage(stream, perfetto_protos_InternedString_fields, &pb))
		return false;

	return true;
}

bool enc_str_iid_range(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_str_iid_range *intern_set = *arg;

	for (int iid = intern_set->start_id; iid < intern_set->end_id; iid++) {
		InternedString pb = {
			PB_INIT(iid) = iid,
			.str = PB_STRING(pb_static_str(iid)),
		};

		if (!pb_encode_tag_for_field(stream, field))
			return false;
		if (!pb_encode_submessage(stream, perfetto_protos_InternedString_fields, &pb))
			return false;
	}

	return true;
}

bool enc_str_iids(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_str_iids *iids = *arg;

	for (int i = 0; i < iids->cnt; i++) {
		InternedString pb = {
			PB_INIT(iid) = iids->iids[i],
			.str = PB_STRING(iids->strs[i]),
		};

		if (!pb_encode_tag_for_field(stream, field))
			return false;
		if (!pb_encode_submessage(stream, perfetto_protos_InternedString_fields, &pb))
			return false;
	}

	return true;
}

bool enc_mappings(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_mapping_iids *iids = *arg;

	for (int i = 0; i < iids->cnt; i++) {
		perfetto_protos_Mapping pb = {
			PB_INIT(iid) = iids->mappings[i].iid,
			PB_INIT(start) = iids->mappings[i].start,
			PB_INIT(end) = iids->mappings[i].end,
			PB_INIT(start_offset) = iids->mappings[i].start_offset,
		};

		if (!pb_encode_tag_for_field(stream, field))
			return false;
		if (!pb_encode_submessage(stream, perfetto_protos_Mapping_fields, &pb))
			return false;
	}

	return true;
}

bool enc_frames(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_frame_iids *iids = *arg;

	for (int i = 0; i < iids->cnt; i++) {
		perfetto_protos_Frame pb = {
			PB_INIT(iid) = iids->frames[i].iid,
			PB_INIT(mapping_id) = iids->frames[i].mapping_id,
			PB_INIT(function_name_id) = iids->frames[i].function_name_id,
			PB_INIT(rel_pc) = iids->frames[i].rel_pc,
		};

		if (!pb_encode_tag_for_field(stream, field))
			return false;
		if (!pb_encode_submessage(stream, perfetto_protos_Frame_fields, &pb))
			return false;
	}

	return true;
}

bool enc_callstack_frame_ids(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_callstack *callstack = *arg;

	for (int i = 0; i < callstack->frame_cnt; i++) {
		if (!pb_encode_tag_for_field(stream, field))
			return false;
		if (!pb_encode_varint(stream, callstack->frame_ids[i]))
			return false;
	}

	return true;
}

bool enc_callstacks(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_callstack_iids *iids = *arg;

	for (int i = 0; i < iids->cnt; i++) {
		perfetto_protos_Callstack pb = {
			PB_INIT(iid) = iids->callstacks[i].iid,
			.frame_ids = PB_CALLSTACK_FRAME_IDS(&iids->callstacks[i]),
		};

		if (!pb_encode_tag_for_field(stream, field))
			return false;
		if (!pb_encode_submessage(stream, perfetto_protos_Callstack_fields, &pb))
			return false;
	}

	return true;
}

void reset_str_iids(struct pb_str_iids *iids)
{
	iids->cnt = 0;
}

void append_str_iid(struct pb_str_iids *iids, int iid, const char *s)
{
	if (iids->cnt == iids->cap) {
		int new_cap = iids->cnt < 1024 ? 1024 : iids->cnt * 4 / 3;
		iids->iids = realloc(iids->iids, new_cap * sizeof(*iids->iids));
		iids->strs = realloc(iids->strs, new_cap * sizeof(*iids->strs));
		iids->cap = new_cap;
	}
	iids->iids[iids->cnt] = iid;
	iids->strs[iids->cnt] = s;
	iids->cnt += 1;
}

void append_mapping_iid(struct pb_mapping_iids *iids, int iid, u64 start, u64 end, u64 offset)
{
	if (iids->cnt == iids->cap) {
		int new_cap = iids->cnt < 256 ? 256 : iids->cnt * 4 / 3;
		iids->mappings = realloc(iids->mappings, new_cap * sizeof(*iids->mappings));
		iids->cap = new_cap;
	}
	iids->mappings[iids->cnt].iid = iid;
	iids->mappings[iids->cnt].start = start;
	iids->mappings[iids->cnt].end = end;
	iids->mappings[iids->cnt].start_offset = offset;
	iids->cnt += 1;
}

void append_frame_iid(struct pb_frame_iids *iids, int iid, int mapping_iid, int fname_iid, u64 rel_pc)
{
	if (iids->cnt == iids->cap) {
		int new_cap = iids->cnt < 256 ? 256 : iids->cnt * 4 / 3;
		iids->frames = realloc(iids->frames, new_cap * sizeof(*iids->frames));
		iids->cap = new_cap;
	}
	iids->frames[iids->cnt].iid = iid;
	iids->frames[iids->cnt].mapping_id = mapping_iid;
	iids->frames[iids->cnt].function_name_id = fname_iid;
	iids->frames[iids->cnt].rel_pc = rel_pc;
	iids->cnt += 1;
}

void append_callstack_frame_iid(struct pb_callstack_iids *iids, int iid, int frame_iid)
{
	struct pb_callstack *cs = NULL;

	if (iids->cnt > 0 && iids->callstacks[iids->cnt - 1].iid == iid)
		cs = &iids->callstacks[iids->cnt - 1];

	if (!cs) {
		if (iids->cnt == iids->cap) {
			int new_cap = iids->cnt < 32 ? 32 : iids->cnt * 4 / 3;
			iids->callstacks = realloc(iids->callstacks, new_cap * sizeof(*iids->callstacks));
			iids->cap = new_cap;
		}
		iids->callstacks[iids->cnt].iid = iid;
		iids->callstacks[iids->cnt].frame_cnt = 0;
		iids->callstacks[iids->cnt].frame_ids = NULL;
		cs = &iids->callstacks[iids->cnt];

		iids->cnt += 1;
	}

	cs->frame_ids = realloc(cs->frame_ids, (cs->frame_cnt + 1) * sizeof(*cs->frame_ids));
	cs->frame_ids[cs->frame_cnt] = frame_iid;
	cs->frame_cnt++;
}

static pb_field_iter_t trace_pkt_it;

void enc_trace_packet(pb_ostream_t *stream, TracePacket *msg)
{
	if (!pb_encode_tag_for_field(stream, &trace_pkt_it)) {
		fprintf(stderr, "Failed to encode Trace.packet field tag!\n");
		exit(1);
	}
	if (!pb_encode_submessage(stream, perfetto_protos_TracePacket_fields, msg)) {
		fprintf(stderr, "Failed to encode TracePacket value!\n");
		exit(1);
	}
}

bool enc_clock(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	const struct pb_clock **clocks = *arg;

	while (*clocks) {
		const struct pb_clock *clock = *clocks;
		perfetto_protos_ClockSnapshot_Clock pb = {
			PB_INIT(clock_id) = clock->clock_id,
			PB_INIT(timestamp) = clock->timestamp,
		};

		if (!pb_encode_tag_for_field(stream, field))
			return false;
		if (!pb_encode_submessage(stream, perfetto_protos_ClockSnapshot_Clock_fields, &pb))
			return false;
		clocks++;
	}
	return true;
}

__unused static void emit_clock_snapshot(pb_ostream_t *stream)
{
	struct pb_clock boot_clock = {
		.clock_id = perfetto_protos_ClockSnapshot_Clock_BuiltinClocks_BOOTTIME,
		.timestamp = 0,
	};
	struct pb_clock mono_clock = {
		.clock_id = perfetto_protos_ClockSnapshot_Clock_BuiltinClocks_MONOTONIC,
		.timestamp = env.sess_start_ts,
	};
	struct pb_clock *clocks[] = { &boot_clock, &mono_clock, NULL };
	TracePacket pb = {
		PB_TRUST_SEQ_ID(),
		PB_ONEOF(data, TracePacket_clock_snapshot) = { .clock_snapshot = {
			PB_INIT(primary_trace_clock) = perfetto_protos_BuiltinClock_BUILTIN_CLOCK_MONOTONIC,
			.clocks = PB_CLOCK(clocks),
		}},
	};
	enc_trace_packet(stream, &pb);
}

int init_pb_trace(pb_ostream_t *stream)
{
	if (!pb_field_iter_begin(&trace_pkt_it, perfetto_protos_Trace_fields, NULL)) {
		fprintf(stderr, "Failed to start Trace fields iterator!\n");
		return -1;
	}
	if (!pb_field_iter_find(&trace_pkt_it, 1)) {
		fprintf(stderr, "Failed to find Trace field!\n");
		return -1;
	}

	//emit_clock_snapshot(stream);

	/* emit fake instant event to establish strict zero timestamp */
	TracePacket ev_pb = {
		PB_INIT(timestamp) = 0,
		PB_TRUST_SEQ_ID(),
		PB_INIT(sequence_flags) = perfetto_protos_TracePacket_SequenceFlags_SEQ_INCREMENTAL_STATE_CLEARED,
		PB_ONEOF(data, TracePacket_track_event) = { .track_event = {
			PB_INIT(type) = perfetto_protos_TrackEvent_Type_TYPE_INSTANT,
			PB_ONEOF(name_field, TrackEvent_name) = { .name = PB_STRING("START") },
		}},
		PB_INIT(interned_data) = {
			.event_categories = PB_STR_IID_RANGE(CAT_START_IID, CAT_END_IID),
			.event_names = PB_STR_IID_RANGE(NAME_START_IID, NAME_END_IID),
			.debug_annotation_names = PB_STR_IID_RANGE(ANNK_START_IID, ANNK_END_IID),
			.debug_annotation_string_values = PB_STR_IID_RANGE(ANNV_START_IID, ANNV_END_IID),
		},
	};
	enc_trace_packet(stream, &ev_pb);

	if (env.pb_debug_interns) {
		struct { const char *name; int start, end; } ranges[] = {
			{"category", CAT_START_IID, CAT_END_IID},
			{"event_name", NAME_START_IID, NAME_END_IID},
			{"ann_name", ANNK_START_IID, ANNK_END_IID},
			{"ann_value", ANNV_START_IID, ANNV_END_IID},
		};

		for (int k = 0; k < ARRAY_SIZE(ranges); k++)
			for (int i = ranges[k].start; i < ranges[k].end; i++)
				fprintf(stderr, "% 3d: %-20s [%s]\n", i, pb_static_strs[i] ?: "??????", ranges[k].name);
	}

	return 0;
}

pb_iid str_iid_for(struct str_iid_domain *d, const char *s, bool *new_iid, const char **out_str)
{
	long iid;
	char *sdup;
	struct hashmap_entry *entry;

	hashmap__for_each_key_entry(d->str_iids, entry, (long)s) {
		iid = entry->value;
		if (new_iid)
			*new_iid = false;
		if (out_str)
			*out_str = entry->pkey;
		return iid;
	}

	sdup = strdup(s);
	iid = d->next_str_iid++;

	hashmap__set(d->str_iids, sdup, iid, NULL, NULL);

	if (env.pb_debug_interns)
		fprintf(stderr, "%03ld: %-20s [%s]\n", iid, sdup, d->domain_desc);
	if (new_iid)
		*new_iid = true;
	if (out_str)
		*out_str = sdup;

	return iid;
}
