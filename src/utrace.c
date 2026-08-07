// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#include "bpf/libbpf.h"
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

#include <bpf/btf.h>

#include "utils.h"
#include "env.h"
#include "utrace.h"
#include "utrace_cfg.h"
#include "elf_utils.h"
#include "bpf_utils.h"
#include "proc.h"
#include "wprof.skel.h"

static enum utrace_arg_type usdt_arg_to_utrace_type(const struct usdt_arg_info *arg)
{
	switch (arg->size) {
	case 1: return arg->is_signed ? UTRACE_ARG_S8  : UTRACE_ARG_U8;
	case 2: return arg->is_signed ? UTRACE_ARG_S16 : UTRACE_ARG_U16;
	case 4: return arg->is_signed ? UTRACE_ARG_S32 : UTRACE_ARG_U32;
	case 8: return arg->is_signed ? UTRACE_ARG_S64 : UTRACE_ARG_U64;
	default: return UTRACE_ARG_U64;
	}
}

static int add_link(struct bpf_state *st, struct bpf_link *link)
{
	struct bpf_link **tmp;

	tmp = realloc(st->links, (st->link_cnt + 1) * sizeof(struct bpf_link *));
	if (!tmp)
		return -ENOMEM;
	st->links = tmp;
	st->links[st->link_cnt] = link;
	st->link_cnt++;
	return 0;
}

static int add_link_fd(struct bpf_state *st, int fd)
{
	int *tmp;

	tmp = realloc(st->link_fds, (st->link_fd_cnt + 1) * sizeof(int));
	if (!tmp)
		return -ENOMEM;
	st->link_fds = tmp;
	st->link_fds[st->link_fd_cnt] = fd;
	st->link_fd_cnt++;
	return 0;
}

static bool cfg_needs_uprobe(const struct utrace_cfg *cfg)
{
	switch (cfg->type) {
	case UTRACE_UPROBE:
	case UTRACE_UPROBE_SPAN:
		return true;
	default:
		return false;
	}
}

static bool cfg_needs_uretprobe(const struct utrace_cfg *cfg)
{
	switch (cfg->type) {
	case UTRACE_URETPROBE:
	case UTRACE_UPROBE_SPAN:
		return true;
	default:
		return false;
	}
}

static bool cfg_needs_kprobe(const struct utrace_cfg *cfg)
{
	switch (cfg->type) {
	case UTRACE_KPROBE:
	case UTRACE_KPROBE_SPAN:
		return true;
	default:
		return false;
	}
}

static bool cfg_needs_kretprobe(const struct utrace_cfg *cfg)
{
	switch (cfg->type) {
	case UTRACE_KRETPROBE:
	case UTRACE_KPROBE_SPAN:
		return true;
	default:
		return false;
	}
}

/* Fill a utrace_probe_cfg from utrace_cfg params, filtering args by is_exit */
static void fill_probe_cfg(struct utrace_probe_cfg *pcfg, const struct utrace_cfg *cfg,
			   int utrace_id, enum utrace_event_type event_type, bool is_exit)
{
	memset(pcfg, 0, sizeof(*pcfg));
	pcfg->utrace_id = utrace_id;
	pcfg->event_type = event_type;
	pcfg->probe_type = cfg->type;

	int arg_idx = 0;
	for (int i = 0; i < cfg->param_cnt && arg_idx < MAX_UTRACE_ARGS; i++) {
		const struct utrace_param *p = &cfg->params[i];

		if (p->type == UTRACE_PARAM_CAPTURE_STACK) {
			/* For kspan/uspan exits, skip: same function as entry, stack is redundant */
			if (is_exit && cfg_is_span(cfg))
				continue;
			pcfg->flags |= UTRACE_FL_CAPTURE_STACK;
			continue;
		}
		if (p->type != UTRACE_PARAM_ARG)
			continue;

		/*
		 * Native spans split one cfg's args across entry/exit by ret-ness;
		 * generic ~~ span legs (and plain probes) keep all their own args.
		 */
		if (cfg_is_span(cfg)) {
			if (event_type == UTRACE_ENTRY && p->arg.arg_idx == UTRACE_ARG_RET)
				continue;
			if (event_type == UTRACE_EXIT && p->arg.arg_idx != UTRACE_ARG_RET)
				continue;
		}

		memcpy(pcfg->arg_ops[arg_idx], p->arg.read_ops, p->arg.read_op_cnt * sizeof(**pcfg->arg_ops));
		pcfg->arg_op_cnt[arg_idx] = p->arg.read_op_cnt;
		arg_idx++;
	}
	pcfg->arg_cnt = arg_idx;
}

static void cfg_set_binary_path(struct utrace_cfg *cfg, char *path)
{
	cfg->params = realloc(cfg->params, (cfg->param_cnt + 1) * sizeof(*cfg->params));
	struct utrace_param *p = &cfg->params[cfg->param_cnt++];
	memset(p, 0, sizeof(*p));
	p->type = UTRACE_PARAM_BINARY_PATH;
	p->binary.path = path;
}

static const char *cfg_binary_path(const struct utrace_cfg *cfg)
{
	for (int i = 0; i < cfg->param_cnt; i++) {
		if (cfg->params[i].type == UTRACE_PARAM_BINARY_PATH)
			return cfg->params[i].binary.path;
	}
	return NULL;
}

static int cfg_pid(const struct utrace_cfg *cfg)
{
	if (cfg->type == UTRACE_SPAN) {
		int pid = cfg_pid(cfg->span.entry);
		return pid >= 0 ? pid : cfg_pid(cfg->span.exit);
	}
	for (int i = 0; i < cfg->param_cnt; i++) {
		if (cfg->params[i].type == UTRACE_PARAM_PID)
			return cfg->params[i].pid.pid;
	}
	return -1; /* system-wide */
}

static enum utrace_pid_discovery cfg_pid_discovery(const struct utrace_cfg *cfg)
{
	if (cfg->type == UTRACE_SPAN)
		return cfg_pid_discovery(cfg->span.entry) ?: cfg_pid_discovery(cfg->span.exit);

	for (int i = 0; i < cfg->param_cnt; i++) {
		if (cfg->params[i].type == UTRACE_PARAM_PID)
			return cfg->params[i].pid.discovery;
	}

	return UTRACE_PID_DISCOVER_NONE;
}

static bool cfg_is_kprobe_type(const struct utrace_cfg *cfg)
{
	switch (cfg->type) {
	case UTRACE_KPROBE:
	case UTRACE_KRETPROBE:
	case UTRACE_KPROBE_SPAN:
		return true;
	default:
		return false;
	}
}

static bool cfg_is_bpf_type(const struct utrace_cfg *cfg)
{
	switch (cfg->type) {
	case UTRACE_BPF_PROBE:
	case UTRACE_BPF_RETPROBE:
	case UTRACE_BPF_SPAN:
		return true;
	default:
		return false;
	}
}

/* Chase through typedefs/const/volatile/restrict/type_tag to the underlying type */
static const struct btf_type *btf_skip_modifiers(const struct btf *btf, __u32 id, __u32 *res_id)
{
	const struct btf_type *t;

	for (t = btf__type_by_id(btf, id); btf_is_mod(t) || btf_is_typedef(t); t = btf__type_by_id(btf, id))
		id = t->type;

	if (res_id)
		*res_id = id;
	return t;
}

static int resolve_btf_proto_arg_type(const struct btf *btf, const struct btf_type *proto,
				      int arg_idx, enum utrace_arg_type *out,
				      const char **name_out, __u32 *type_id_out)
{
	__u32 type_id;
	if (arg_idx == UTRACE_ARG_RET) {
		type_id = proto->type;
		if (!type_id)
			return -ENOENT;
	} else {
		if (arg_idx >= btf_vlen(proto))
			return -ENOENT;
		struct btf_param *params = btf_params(proto);
		type_id = params[arg_idx].type;
		if (name_out) {
			const char *pname = btf__name_by_offset(btf, params[arg_idx].name_off);
			if (*pname)
				*name_out = pname;
		}
	}
	if (type_id_out)
		*type_id_out = type_id;

	const struct btf_type *t = btf_skip_modifiers(btf, type_id, NULL);

	switch (btf_kind(t)) {
	case BTF_KIND_INT: {
		__u8 encoding = btf_int_encoding(t);
		bool is_signed = encoding & BTF_INT_SIGNED;
		int bits = btf_int_bits(t);

		if (encoding & BTF_INT_BOOL) {
			*out = UTRACE_ARG_U8;
			return 0;
		}

		switch (bits) {
		case 8:  *out = is_signed ? UTRACE_ARG_S8  : UTRACE_ARG_U8;  break;
		case 16: *out = is_signed ? UTRACE_ARG_S16 : UTRACE_ARG_U16; break;
		case 32: *out = is_signed ? UTRACE_ARG_S32 : UTRACE_ARG_U32; break;
		case 64: *out = is_signed ? UTRACE_ARG_S64 : UTRACE_ARG_U64; break;
		default: *out = UTRACE_ARG_U64; break;
		}
		return 0;
	}
	case BTF_KIND_ENUM:
		*out = UTRACE_ARG_S32;
		return 0;
	case BTF_KIND_ENUM64:
		*out = UTRACE_ARG_S64;
		return 0;
	case BTF_KIND_PTR: {
		const struct btf_type *pointee = btf_skip_modifiers(btf, t->type, NULL);
		const char *name = btf__name_by_offset(btf, pointee->name_off);
		if (btf_is_int(pointee) && strcmp(name, "char") == 0)
			*out = UTRACE_ARG_STR;
		else
			*out = UTRACE_ARG_PTR;
		return 0;
	}
	default:
		*out = UTRACE_ARG_U64;
		return 0;
	}
}

static const struct btf_type *btf_find_func_proto(const struct btf *btf, const char *func_name)
{
	__s32 func_id = btf__find_by_name_kind(btf, func_name, BTF_KIND_FUNC);
	if (func_id < 0)
		return NULL;

	const struct btf_type *func = btf__type_by_id(btf, func_id);
	const struct btf_type *proto = btf__type_by_id(btf, func->type);
	if (!proto || !btf_is_func_proto(proto))
		return NULL;
	return proto;
}

static int resolve_btf_arg_type(const struct btf *btf, const char *func_name,
				int arg_idx, enum utrace_arg_type *out, const char **name_out,
				__u32 *type_id_out)
{
	const struct btf_type *proto = btf_find_func_proto(btf, func_name);
	if (!proto)
		return -ENOENT;
	return resolve_btf_proto_arg_type(btf, proto, arg_idx, out, name_out, type_id_out);
}

struct utrace_type_ref {
	const struct btf *btf;
	__u32 id;		/* BTF type id; 0 means no/failed type resolution */
};

#define UTRACE_TYPE_REF(btf_, id_) ((struct utrace_type_ref){ .btf = (btf_), .id = (id_) })

/*
 * Where the value tracked during accessor compilation currently lives — the
 * value-vs-lvalue distinction that decides whether a step needs a memory read.
 *
 * UTRACE_LOC_VALUE: the raw arg/register value. If it is a pointer it is already
 *   the pointee's address, so the first field access is free (no deref) — e.g.
 *   arg:0.comm on a `struct task_struct *` is just reg + offsetof(comm).
 * UTRACE_LOC_ADDR: the value lives in memory at addr + offset; following a
 *   pointer from here needs a real load — e.g. arg:0.real_parent.comm must DEREF
 *   real_parent before reading comm.
 *
 * It also keeps casts position-correct (a cast preserves loc): the same
 * ::cast<struct sock *>.sk_state compiles to 0 derefs on a register value
 * (VALUE) but 1 deref when the pointer is a struct member (ADDR).
 */
enum utrace_value_loc {
	UTRACE_LOC_VALUE,
	UTRACE_LOC_ADDR,
};

struct utrace_arg_state {
	struct utrace_type_ref type;
	enum utrace_arg_type fallback_type;
	enum utrace_value_loc loc;
	long long offset;
};

struct utrace_member_info {
	struct utrace_type_ref type;
	__u32 byte_offset;
};

__printf(3, 4)
static int utrace_acc_err(const struct utrace_param *p,
			       const struct utrace_accessor *acc, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	eprintf("utrace: %s", vsfmt(fmt, ap));
	va_end(ap);

	if (p->arg.source) {
		struct sview source = acc ? acc->source : sv_new(p->arg.source);
		int off = source.s - p->arg.source;
		int len = source.len;

		eprintf("  %s\n", p->arg.source);
		if (sv_is_empty(source))
			len = 1;
		eprintf("  %*s%.*s\n", off, "", len,
			"^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
	}
	return -EINVAL;
}

static const struct btf_type *utrace_ref_type(struct utrace_type_ref ref, __u32 *id_out)
{
	if (!ref.id || !ref.btf)
		return NULL;
	return btf_skip_modifiers(ref.btf, ref.id, id_out);
}

static bool utrace_ref_ptr(struct utrace_type_ref ref, struct utrace_type_ref *pointee)
{
	if (!ref.id || !ref.btf)
		return false;
	const struct btf_type *t = btf_skip_modifiers(ref.btf, ref.id, NULL);
	if (!t || !btf_is_ptr(t))
		return false;
	if (pointee)
		*pointee = UTRACE_TYPE_REF(ref.btf, t->type);
	return true;
}

static bool utrace_ref_is_char(struct utrace_type_ref ref)
{
	const struct btf_type *t = utrace_ref_type(ref, NULL);
	const char *name;

	if (!t || !btf_is_int(t) || t->size != 1)
		return false;
	name = btf__name_by_offset(ref.btf, t->name_off);
	return name && strcmp(name, "char") == 0;
}

static bool utrace_refs_compatible(struct utrace_type_ref a, struct utrace_type_ref b, int depth)
{
	struct utrace_type_ref ap, bp;
	const struct btf_type *at, *bt;
	const char *aname, *bname;
	__u32 aid, bid;

	if (!a.id || !b.id || depth > 8)
		return false;
	bool a_ptr = utrace_ref_ptr(a, &ap);
	bool b_ptr = utrace_ref_ptr(b, &bp);
	if (a_ptr || b_ptr)
		return a_ptr && b_ptr && utrace_refs_compatible(ap, bp, depth + 1);
	at = utrace_ref_type(a, &aid);
	bt = utrace_ref_type(b, &bid);
	if (!at || !bt)
		return false;
	if (a.btf == b.btf)
		return aid == bid;
	if (btf_kind(at) != btf_kind(bt))
		return false;
	aname = btf__name_by_offset(a.btf, at->name_off);
	bname = btf__name_by_offset(b.btf, bt->name_off);
	return aname && bname && aname[0] && strcmp(aname, bname) == 0;
}

static int utrace_find_member(struct utrace_type_ref container, struct sview name,
			      __u32 base_bytes, int depth, struct utrace_member_info *out)
{
	const struct btf_type *t = utrace_ref_type(container, NULL);
	const struct btf *btf = container.btf;

	if (!t || !btf_is_composite(t))
		return -EINVAL;
	if (depth > 16)
		return -ELOOP;

	const struct btf_member *members = btf_members(t);
	for (int i = 0; i < btf_vlen(t); i++) {
		const struct btf_member *m = &members[i];
		const char *member_name = btf__name_by_offset(btf, m->name_off);
		__u32 bit_offset = btf_member_bit_offset(t, i);

		if (member_name && member_name[0] && sv_eq(name, member_name)) {
			if (btf_member_bitfield_size(t, i) || bit_offset % 8)
				return -ENOTSUP;
			*out = (struct utrace_member_info){
				.type = UTRACE_TYPE_REF(btf, m->type),
				.byte_offset = base_bytes + bit_offset / 8,
			};
			return 0;
		}
		if (member_name && member_name[0])
			continue;

		struct utrace_type_ref nested = UTRACE_TYPE_REF(btf, m->type);
		const struct btf_type *nested_t = utrace_ref_type(nested, NULL);
		if (!nested_t || !btf_is_composite(nested_t))
			continue;
		int err = utrace_find_member(nested, name, base_bytes + bit_offset / 8, depth + 1, out);
		if (!err)
			return 0;
		if (err != -ENOENT)
			return err;
	}
	return -ENOENT;
}

static int utrace_emit_read_op(struct utrace_param *p, const struct utrace_accessor *acc,
			       enum utrace_read_op_kind kind, long long val, unsigned short size,
			       unsigned char flags)
{
	if (p->arg.read_op_cnt == MAX_UTRACE_READ_OPS)
		return utrace_acc_err(p, acc, "too many compiled read operations (max %d)\n", MAX_UTRACE_READ_OPS);

	struct utrace_read_op *op = &p->arg.read_ops[p->arg.read_op_cnt++];

	*op = (struct utrace_read_op){
		.offset = val,
		.size = size,
		.kind = kind,
		.flags = flags,
	};
	if (kind == UTRACE_READ_ARG)
		op->arg_idx = val;
	return 0;
}

static int normalize_cast_type(struct sview input, struct sview *name_out, bool *is_ptr)
{
	struct sview v = sv_trim(input);
	*is_ptr = v.len > 0 && v.s[v.len - 1] == '*';
	if (*is_ptr)
		v = sv_trim(sv(v.s, v.len - 1));
	if (sv_is_empty(v))
		return -EINVAL;
	*name_out = v;
	return 0;
}

static __u32 utrace_canon_id(const struct btf *btf, __u32 id)
{
	__u32 res = id;
	if (id)
		btf_skip_modifiers(btf, id, &res);
	return res;
}

/*
 * Find a real BTF pointer type whose pointee resolves to target_id. A cast to
 * T * is only meaningful if some T * field exists in the kernel, so its pointer
 * type is present in BTF.
 */
static __s32 btf_find_ptr_to(const struct btf *btf, __u32 target_id)
{
	__u32 canon = utrace_canon_id(btf, target_id);
	__u32 n = btf__type_cnt(btf);

	for (__u32 i = 1; i < n; i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);
		if (t && btf_is_ptr(t) && utrace_canon_id(btf, t->type) == canon)
			return i;
	}
	return -ENOENT;
}

static int utrace_resolve_type(const struct btf *btf, const struct utrace_param *p,
			       const struct utrace_accessor *acc, struct utrace_type_ref *out)
{
	struct sview tname, lookup;
	bool is_ptr;
	int err = normalize_cast_type(acc->args[0], &tname, &is_ptr);
	if (err)
		return utrace_acc_err(p, acc, "invalid cast type\n");
	if (tname.len && tname.s[tname.len - 1] == '*')
		return utrace_acc_err(p, acc, "pointer-to-pointer casts are not supported\n");
	if (!is_ptr && sv_eq(tname, "void"))
		return utrace_acc_err(p, acc, "cannot cast to void\n");

	int kind = 0;
	char name[128];
	__s32 id;

	lookup = tname;
	if (sv_starts_with(tname, "struct ")) {
		lookup = sv_trim(sv_consume_left(tname, 7));
		kind = BTF_KIND_STRUCT;
	} else if (sv_starts_with(tname, "union ")) {
		lookup = sv_trim(sv_consume_left(tname, 6));
		kind = BTF_KIND_UNION;
	} else if (sv_starts_with(tname, "enum ")) {
		lookup = sv_trim(sv_consume_left(tname, 5));
		kind = BTF_KIND_ENUM;
	}
	snprintf(name, sizeof(name), "%.*s", lookup.len, lookup.s);

	if (kind == BTF_KIND_ENUM) {
		id = btf__find_by_name_kind(btf, name, BTF_KIND_ENUM);
		if (id < 0)
			id = btf__find_by_name_kind(btf, name, BTF_KIND_ENUM64);
	} else if (kind) {
		id = btf__find_by_name_kind(btf, name, kind);
	} else if (sv_eq(tname, "void")) {
		id = 0;
	} else {
		id = btf__find_by_name_kind(btf, name, BTF_KIND_TYPEDEF);
		if (id < 0)
			id = btf__find_by_name_kind(btf, name, BTF_KIND_INT);
		if (id < 0)
			id = btf__find_by_name_kind(btf, name, BTF_KIND_ENUM);
		if (id < 0)
			id = btf__find_by_name_kind(btf, name, BTF_KIND_ENUM64);
		if (id < 0)
			id = btf__find_by_name_kind(btf, name, BTF_KIND_STRUCT);
		if (id < 0)
			id = btf__find_by_name_kind(btf, name, BTF_KIND_UNION);
	}
	if (id < 0)
		return utrace_acc_err(p, acc, "type '%.*s' not found\n", tname.len, tname.s);

	if (is_ptr) {
		id = btf_find_ptr_to(btf, id);
		if (id < 0)
			return utrace_acc_err(p, acc, "no pointer-to-'%.*s' type in BTF\n", lookup.len, lookup.s);
	}
	*out = UTRACE_TYPE_REF(btf, id);
	return 0;
}

static int utrace_compile_field(struct utrace_arg_state *state, struct utrace_param *p,
				const struct utrace_accessor *acc)
{
	struct utrace_type_ref pointee;
	struct utrace_member_info member;

	if (!state->type.id)
		return utrace_acc_err(p, acc, "field access needs a value type or leading ::cast\n");
	if (state->loc == UTRACE_LOC_VALUE) {
		if (!utrace_ref_ptr(state->type, &pointee))
			return utrace_acc_err(p, acc, "cannot select field '%s' from a scalar value\n", acc->field);
		state->type = pointee;
		state->loc = UTRACE_LOC_ADDR;
	}
	if (utrace_ref_ptr(state->type, &pointee)) {
		int err = utrace_emit_read_op(p, acc, UTRACE_READ_VAL, state->offset, sizeof(void *), 0);
		if (err)
			return err;
		state->offset = 0;
		state->type = pointee;
		if (utrace_ref_ptr(state->type, NULL)) {
			return utrace_acc_err(p, acc, "field '%s' would require more than one implicit pointer dereference\n",
					      acc->field);
		}
	}

	const struct btf_type *t = utrace_ref_type(state->type, NULL);
	if (!t || !btf_is_composite(t))
		return utrace_acc_err(p, acc, "cannot select field '%s' from a non-struct type\n", acc->field);
	int err = utrace_find_member(state->type, sv_new(acc->field), 0, 0, &member);
	if (err == -ENOENT)
		return utrace_acc_err(p, acc, "field '%s' not found\n", acc->field);
	if (err == -ENOTSUP)
		return utrace_acc_err(p, acc, "field '%s' is a bitfield or not byte-aligned (unsupported)\n", acc->field);
	if (err)
		return utrace_acc_err(p, acc, "failed to resolve field '%s'\n", acc->field);
	state->offset += member.byte_offset;
	state->type = member.type;
	return 0;
}

static int utrace_compile_container_of(struct utrace_arg_state *state, const struct btf *btf,
				       struct utrace_param *p, const struct utrace_accessor *acc)
{
	struct utrace_type_ref container, current;
	struct utrace_member_info member;
	int err = utrace_resolve_type(btf, p, acc, &container);
	if (err)
		return err;

	const struct btf_type *container_t = utrace_ref_type(container, NULL);
	if (!container_t || !btf_is_composite(container_t))
		return utrace_acc_err(p, acc, "container_of type is not a struct or union\n");

	err = utrace_find_member(container, acc->args[1], 0, 0, &member);
	if (err == -ENOENT) {
		return utrace_acc_err(p, acc, "container member '%.*s' not found\n",
				      acc->args[1].len, acc->args[1].s);
	} else if (err == -ENOTSUP) {
		return utrace_acc_err(p, acc, "container member '%.*s' is a bitfield or not byte-aligned (unsupported)\n",
				      acc->args[1].len, acc->args[1].s);
	} else if (err) {
		return utrace_acc_err(p, acc, "failed to resolve container member '%.*s'\n",
				      acc->args[1].len, acc->args[1].s);
	}

	current = state->type;
	if (state->loc == UTRACE_LOC_VALUE) {
		if (!utrace_ref_ptr(current, &current))
			return utrace_acc_err(p, acc, "container_of needs a pointer value or addressed member\n");
		state->loc = UTRACE_LOC_ADDR;
	}
	if (!utrace_refs_compatible(current, member.type, 0)) {
		return utrace_acc_err(p, acc, "container_of current type does not match member '%.*s'\n",
				      acc->args[1].len, acc->args[1].s);
	}
	state->offset -= member.byte_offset;
	state->type = container;
	state->loc = UTRACE_LOC_ADDR;
	return 0;
}

static int utrace_int_arg_type(int size, bool is_signed, enum utrace_arg_type *out)
{
	switch (size) {
	case 1: *out = is_signed ? UTRACE_ARG_S8 : UTRACE_ARG_U8; return 0;
	case 2: *out = is_signed ? UTRACE_ARG_S16 : UTRACE_ARG_U16; return 0;
	case 4: *out = is_signed ? UTRACE_ARG_S32 : UTRACE_ARG_U32; return 0;
	case 8: *out = is_signed ? UTRACE_ARG_S64 : UTRACE_ARG_U64; return 0;
	default: return -EINVAL;
	}
}

static int utrace_compile_btf_terminal(struct utrace_arg_state *state, struct utrace_param *p,
				       const struct utrace_accessor *last)
{
	enum utrace_arg_type explicit_type = p->arg.arg_type;
	struct utrace_type_ref pointee;
	const struct btf_type *t;
	enum utrace_arg_type inferred;
	bool is_signed = false;
	int size;

	if (!state->type.id)
		return utrace_acc_err(p, last, "failed to determine value type\n");

	if (utrace_ref_ptr(state->type, &pointee)) {
		bool char_ptr = utrace_ref_is_char(pointee);
		int err;

		if (explicit_type == UTRACE_ARG_STR && !char_ptr)
			return utrace_acc_err(p, last, ":str requires a char pointer (use ::cast<char *> to reinterpret)\n");
		if (explicit_type != UTRACE_ARG_UNKNOWN && explicit_type != UTRACE_ARG_STR &&
		    explicit_type != UTRACE_ARG_PTR && !utrace_arg_is_int(explicit_type))
			return utrace_acc_err(p, last, "invalid pointer type override\n");
		p->arg.arg_type = explicit_type == UTRACE_ARG_UNKNOWN ?
			(char_ptr ? UTRACE_ARG_STR : UTRACE_ARG_PTR) : explicit_type;
		if (state->loc == UTRACE_LOC_ADDR) {
			err = utrace_emit_read_op(p, last, UTRACE_READ_VAL, state->offset, sizeof(void *), 0);
			if (err)
				return err;
			state->offset = 0;
		} else {
			p->arg.read_ops[0].size = sizeof(void *);
			p->arg.read_ops[0].flags = 0;
		}
		if (p->arg.arg_type == UTRACE_ARG_STR) {
			return utrace_emit_read_op(p, last, UTRACE_READ_STR, state->offset, MAX_UTRACE_STR_SZ,
						   state->loc == UTRACE_LOC_ADDR ? UTRACE_READ_F_KERNEL : 0);
		}
		return 0;
	}

	t = utrace_ref_type(state->type, NULL);
	if (!t)
		return utrace_acc_err(p, last, "failed to determine value type\n");
	if (btf_is_array(t)) {
		const struct btf_array *arr = btf_array(t);
		struct utrace_type_ref elem = UTRACE_TYPE_REF(state->type.btf, arr->type);
		if (!utrace_ref_is_char(elem))
			return utrace_acc_err(p, last, "only char arrays are supported\n");
		if (state->loc != UTRACE_LOC_ADDR || arr->nelems == 0)
			return utrace_acc_err(p, last, "char array has no fixed address to read from\n");
		if (explicit_type != UTRACE_ARG_UNKNOWN && explicit_type != UTRACE_ARG_STR)
			return utrace_acc_err(p, last, "char array only supports :str\n");
		p->arg.arg_type = UTRACE_ARG_STR;
		return utrace_emit_read_op(p, last, UTRACE_READ_STR, state->offset,
					   min(arr->nelems, (unsigned int)MAX_UTRACE_STR_SZ),
					   UTRACE_READ_F_KERNEL);
	}
	if (btf_is_composite(t))
		return utrace_acc_err(p, last, "capturing a whole struct/union is not supported yet; select a field\n");
	if (btf_is_int(t)) {
		size = t->size;
		is_signed = btf_int_encoding(t) & BTF_INT_SIGNED;
	} else if (btf_is_enum(t) || btf_is_enum64(t)) {
		size = t->size;
		is_signed = btf_kflag(t);
	} else {
		return utrace_acc_err(p, last, "unsupported value type\n");
	}
	if (utrace_int_arg_type(size, is_signed, &inferred))
		return utrace_acc_err(p, last, "value has unsupported size %d\n", size);
	if (explicit_type == UTRACE_ARG_STR)
		return utrace_acc_err(p, last, ":str requires char * or char[] (use ::cast<char *> to reinterpret)\n");
	if (explicit_type != UTRACE_ARG_UNKNOWN && explicit_type != UTRACE_ARG_PTR &&
	    !utrace_arg_is_int(explicit_type))
		return utrace_acc_err(p, last, "invalid scalar type override\n");
	p->arg.arg_type = explicit_type == UTRACE_ARG_UNKNOWN ? inferred : explicit_type;
	if (state->loc == UTRACE_LOC_VALUE) {
		p->arg.read_ops[0].size = size;
		p->arg.read_ops[0].flags = is_signed ? UTRACE_READ_F_SIGNED : 0;
		return 0;
	}
	return utrace_emit_read_op(p, last, UTRACE_READ_VAL, state->offset, size,
				   is_signed ? UTRACE_READ_F_SIGNED : 0);
}

static bool utrace_arg_is_signed_type(enum utrace_arg_type type)
{
	return type == UTRACE_ARG_S8 || type == UTRACE_ARG_S16 || type == UTRACE_ARG_S32 || type == UTRACE_ARG_S64;
}

static int utrace_compile_fallback_terminal(struct utrace_arg_state *state, struct utrace_param *p)
{
	enum utrace_arg_type type = p->arg.arg_type == UTRACE_ARG_UNKNOWN ? state->fallback_type : p->arg.arg_type;
	struct utrace_read_op *read_arg = &p->arg.read_ops[0];

	if (type == UTRACE_ARG_UNKNOWN)
		type = UTRACE_ARG_U64;
	p->arg.arg_type = type;
	if (type == UTRACE_ARG_STR) {
		read_arg->size = sizeof(void *);
		return utrace_emit_read_op(p, NULL, UTRACE_READ_STR, 0, MAX_UTRACE_STR_SZ, 0);
	}

	int size = utrace_arg_size(type);

	read_arg->size = size ?: sizeof(void *);
	read_arg->flags = utrace_arg_is_signed_type(type) ? UTRACE_READ_F_SIGNED : 0;
	return 0;
}

static int utrace_apply_accessors(struct utrace_arg_state *state, const struct btf *btf,
				  struct utrace_param *p)
{
	for (int i = 0; i < p->arg.accessor_cnt; i++) {
		const struct utrace_accessor *acc = &p->arg.accessors[i];
		int err;

		if (acc->kind == UTRACE_ACC_FIELD) {
			err = utrace_compile_field(state, p, acc);
		} else if (strcmp(acc->op, "cast") == 0) {
			if (acc->arg_cnt != 1)
				return utrace_acc_err(p, acc, "operator 'cast' expects 1 argument, got %d\n", acc->arg_cnt);
			err = utrace_resolve_type(btf, p, acc, &state->type);
		} else if (strcmp(acc->op, "container_of") == 0) {
			if (acc->arg_cnt != 2)
				return utrace_acc_err(p, acc, "operator 'container_of' expects 2 arguments, got %d\n", acc->arg_cnt);
			err = utrace_compile_container_of(state, btf, p, acc);
		} else {
			err = utrace_acc_err(p, acc, "unsupported accessor operator '%s'\n", acc->op);
		}
		if (err)
			return err;
	}
	return 0;
}

/*
 * Resolve BTF type info for a raw tracepoint. The first argument of any
 * raw tracepoint is always void *__data and should be skipped.
 *
 * We first try __bpf_trace_<name>, which is a real FUNC with both correct
 * types and parameter names. If found, it's the single source of truth.
 *
 * If not, we fall back to 'btf_trace_<name>' BTF TYPEDEF -> PTR -> FUNC_PROTO,
 * which has correct types but loses parameter names. E.g.:
 *
 *   typedef void (*btf_trace_module_get)(void *, struct module *, unsigned long);
 *
 * To recover names in that case, we look for __traceiter_<name> or
 * __tracepoint_iter_<name> (older naming) which are FUNCs that preserve
 * the original prototype with named params. __traceiter_ may be missing
 * from BTF for some tracepoints (e.g., sched_switch) due to missing DWARF
 * in their compilation units. Names are optional.
 */
static int resolve_raw_tp_btf(const struct btf *btf, struct utrace_cfg *cfg)
{
	char buf[256];
	const struct btf_type *t;

	/* try __bpf_trace_<name> first: has both types and names */
	snprintf(buf, sizeof(buf), "__bpf_trace_%s", cfg->raw_tp.name);
	t = btf_find_func_proto(btf, buf);
	if (t) {
		cfg->raw_tp.proto = t;
		cfg->raw_tp.arg_cnt = btf_vlen(t) - 1; /* skip void *__data */
		return 0;
	}

	/* fall back to btf_trace_<name> TYPEDEF -> PTR -> FUNC_PROTO for types */
	snprintf(buf, sizeof(buf), "btf_trace_%s", cfg->raw_tp.name);
	__s32 btf_id = btf__find_by_name_kind(btf, buf, BTF_KIND_TYPEDEF);
	if (btf_id < 0)
		return -ESRCH;

	t = btf__type_by_id(btf, btf_id);
	if (!t || !btf_is_typedef(t))
		return -ESRCH;
	t = btf_skip_modifiers(btf, t->type, NULL);
	if (!btf_is_ptr(t))
		return -ESRCH;
	t = btf__type_by_id(btf, t->type);
	if (!t || !btf_is_func_proto(t))
		return -ESRCH;

	cfg->raw_tp.proto = t;
	cfg->raw_tp.arg_cnt = btf_vlen(t) - 1; /* skip void *__data */

	/* try to recover parameter names from traceiter functions */
	const char *name_funcs[] = { "__traceiter_%s", "__tracepoint_iter_%s" };
	for (int i = 0; i < ARRAY_SIZE(name_funcs); i++) {
		snprintf(buf, sizeof(buf), name_funcs[i], cfg->raw_tp.name);
		t = btf_find_func_proto(btf, buf);
		if (t) {
			cfg->raw_tp.name_proto = t;
			break;
		}
	}

	return 0;
}

/*
 * Parse tracefs format file to get tracepoint field info. Works for both
 * TRACE_EVENT and DEFINE_EVENT tracepoints since the format file always
 * exists for the event name with the correct fields.
 */
static int resolve_tp_format(struct utrace_cfg *cfg)
{
	char path[256], line[512];

	snprintf(path, sizeof(path), "/sys/kernel/debug/tracing/events/%s/%s/format",
		 cfg->tp.cat, cfg->tp.name);

	FILE *f = fopen(path, "r");
	if (!f)
		return -errno;

	struct tp_field *fields = NULL;
	int cnt = 0;
	bool in_fields = false;

	while (fgets(line, sizeof(line), f)) {
		char type[128];
		int offset, size, is_signed;

		if (strncmp(line, "format:", 7) == 0) {
			in_fields = true;
			continue;
		}
		if (!in_fields)
			continue;
		if (strncmp(line, "print fmt:", 10) == 0)
			break;

		if (sscanf(line, " field:%127[^;]; offset:%d; size:%d; signed:%d;",
			   type, &offset, &size, &is_signed) != 4)
			continue;

		/* skip common_* fields (trace_entry header) */
		char *last_space = strrchr(type, ' ');
		if (!last_space)
			continue;
		char *fname = last_space + 1;

		/* strip trailing [] from array names like "prev_comm[16]" */
		char *bracket = strchr(fname, '[');

		if (strncmp(fname, "common_", 7) == 0)
			continue;

		if (bracket)
			*bracket = '\0';

		fields = realloc(fields, (cnt + 1) * sizeof(*fields));
		struct tp_field *field = &fields[cnt];
		memset(field, 0, sizeof(*field));

		bool is_data_loc = strncmp(type, "__data_loc", 10) == 0;
		bool is_char_arr = !is_data_loc && bracket && strstr(type, "char") != NULL;

		field->name = strdup(fname);
		field->offset = offset;
		field->size = size;
		field->is_signed = is_signed;
		field->is_data_loc = is_data_loc;
		field->is_string = is_data_loc || is_char_arr;
		cnt++;
	}

	fclose(f);

	cfg->tp.fields = fields;
	cfg->tp.field_cnt = cnt;
	return cnt > 0 ? 0 : -ENOENT;
}

static bool cfg_is_ret_probe(enum utrace_type t)
{
	return t == UTRACE_URETPROBE || t == UTRACE_KRETPROBE || t == UTRACE_BPF_RETPROBE;
}

static bool cfg_is_native_span(enum utrace_type t)
{
	return t == UTRACE_KPROBE_SPAN || t == UTRACE_UPROBE_SPAN || t == UTRACE_BPF_SPAN;
}

/* Determine the number of positional args for wildcard expansion */
static int btf_func_arg_cnt(const struct btf *btf, const char *func_name)
{
	__s32 func_id = btf__find_by_name_kind(btf, func_name, BTF_KIND_FUNC);
	if (func_id < 0)
		return -1;

	const struct btf_type *func = btf__type_by_id(btf, func_id);
	const struct btf_type *proto = btf__type_by_id(btf, func->type);
	if (!proto || !btf_is_func_proto(proto))
		return -1;

	return btf_vlen(proto);
}

/* Get arg count for a BPF program target using its pre-loaded BTF */
static int bpf_prog_func_arg_cnt(const struct utrace_cfg *cfg)
{
	if (!cfg->bpf_prog.btf)
		return -ENOENT;

	const struct btf_type *t = btf__type_by_id(cfg->bpf_prog.btf, cfg->bpf_prog.btf_func_id);
	if (!t || !btf_is_func(t))
		return -ESRCH;

	const struct btf_type *proto = btf__type_by_id(cfg->bpf_prog.btf, t->type);
	if (!proto || !btf_is_func_proto(proto))
		return -EINVAL;

	return btf_vlen(proto);
}

/* Expand wildcard_args into individual arg params */
static void expand_wildcard_args(struct utrace_cfg *cfg, const struct btf *btf)
{
	int arg_cnt;
	bool has_ret = cfg_is_ret_probe(cfg->type) || cfg_is_native_span(cfg->type);

	if (cfg_is_ret_probe(cfg->type)) {
		/* ret probes only get arg:ret, no positional args */
		arg_cnt = 0;
	} else if (cfg->type == UTRACE_USDT) {
		arg_cnt = cfg->usdt.info.arg_cnt;
	} else if (cfg->type == UTRACE_RAW_TRACEPOINT) {
		arg_cnt = cfg->raw_tp.arg_cnt;
	} else if (cfg->type == UTRACE_TRACEPOINT) {
		arg_cnt = cfg->tp.field_cnt;
	} else if (cfg_is_kprobe_type(cfg)) {
		arg_cnt = btf_func_arg_cnt(btf, cfg->kprobe.name);
		if (arg_cnt < 0)
			arg_cnt = 6;
	} else if (cfg_is_bpf_type(cfg)) {
		arg_cnt = bpf_prog_func_arg_cnt(cfg);
		if (arg_cnt < 0)
			arg_cnt = 6;
	} else {
		arg_cnt = 6;
	}

	/* figure out which arg indices are already explicitly defined */
	bool has_arg[MAX_UTRACE_ARGS] = {};
	bool has_arg_ret = false;
	for (int i = 0; i < cfg->param_cnt; i++) {
		if (cfg->params[i].type != UTRACE_PARAM_ARG)
			continue;
		if (cfg->params[i].arg.arg_idx == UTRACE_ARG_RET)
			has_arg_ret = true;
		else if (cfg->params[i].arg.arg_idx < MAX_UTRACE_ARGS)
			has_arg[cfg->params[i].arg.arg_idx] = true;
	}

	/* cap so total args fit in MAX_UTRACE_ARGS */
	int max_args = MAX_UTRACE_ARGS - (has_ret && !has_arg_ret ? 1 : 0);
	if (arg_cnt > max_args)
		arg_cnt = max_args;

	/* count how many new args we actually need to add */
	int add_cnt = 0;
	for (int i = 0; i < arg_cnt; i++)
		if (!has_arg[i])
			add_cnt++;
	if (has_ret && !has_arg_ret)
		add_cnt++;

	cfg->params = realloc(cfg->params, (cfg->param_cnt + add_cnt) * sizeof(*cfg->params));

	int idx = cfg->param_cnt;

	for (int i = 0; i < arg_cnt; i++) {
		if (has_arg[i])
			continue;
		struct utrace_param *p = &cfg->params[idx++];
		memset(p, 0, sizeof(*p));
		p->type = UTRACE_PARAM_ARG;
		p->arg.arg_idx = i;
		p->arg.arg_type = UTRACE_ARG_UNKNOWN;
	}

	if (has_ret && !has_arg_ret) {
		struct utrace_param *p = &cfg->params[idx++];
		memset(p, 0, sizeof(*p));
		p->type = UTRACE_PARAM_ARG;
		p->arg.arg_idx = UTRACE_ARG_RET;
		p->arg.arg_type = UTRACE_ARG_UNKNOWN;
	}

	cfg->param_cnt += add_cnt;
	cfg->wildcard_args = false;
}

/* Check if a cfg (or its inner span cfgs) needs BTF for wildcard expansion or type resolution */
static bool cfg_needs_btf(const struct utrace_cfg *cfg)
{
	if (cfg->type == UTRACE_SPAN)
		return cfg_needs_btf(cfg->span.entry) || cfg_needs_btf(cfg->span.exit);
	if (cfg->type == UTRACE_RAW_TRACEPOINT)
		return true;
	if (!cfg_is_kprobe_type(cfg))
		return false;
	if (cfg->wildcard_args)
		return true;
	for (int i = 0; i < cfg->param_cnt; i++) {
		if (cfg->params[i].type == UTRACE_PARAM_ARG)
			return true;
	}
	return false;
}

static int resolve_arg_name(const struct utrace_cfg *cfg, const struct btf *btf, const char *name)
{
	switch (cfg->type) {
	case UTRACE_TRACEPOINT:
		for (int i = 0; i < cfg->tp.field_cnt; i++) {
			if (strcmp(cfg->tp.fields[i].name, name) == 0)
				return i;
		}
		break;
	case UTRACE_RAW_TRACEPOINT: {
		const struct btf_type *proto = cfg->raw_tp.name_proto ?: cfg->raw_tp.proto;
		if (!proto)
			return -ENOENT;
		const struct btf_param *p = btf_params(proto) + 1; /* skip void *__data */
		for (int i = 1; i < btf_vlen(proto); i++, p++) {
			const char *pname = btf__name_by_offset(btf, p->name_off);
			if (pname && strcmp(pname, name) == 0)
				return i - 1;
		}
		break;
	}
	case UTRACE_KPROBE:
	case UTRACE_KRETPROBE:
	case UTRACE_KPROBE_SPAN:
	case UTRACE_BPF_PROBE:
	case UTRACE_BPF_RETPROBE:
	case UTRACE_BPF_SPAN: {
		const struct btf *resolve_btf = cfg_is_bpf_type(cfg) ? cfg->bpf_prog.btf : btf;
		const char *func_name = cfg_is_bpf_type(cfg) ? cfg->bpf_prog.name : cfg->kprobe.name;
		if (!resolve_btf)
			return -ENOENT;
		const struct btf_type *proto = btf_find_func_proto(resolve_btf, func_name);
		if (!proto)
			return -ENOENT;
		const struct btf_param *p = btf_params(proto);
		for (int i = 0; i < btf_vlen(proto); i++, p++) {
			const char *pname = btf__name_by_offset(resolve_btf, p->name_off);
			if (pname && strcmp(pname, name) == 0)
				return i;
		}
		break;
	}
	default:
		eprintf("utrace: name-based arg references not supported for probe type %d\n", cfg->type);
		return -EOPNOTSUPP;
	}
	return -ENOENT;
}

/*
 * Number of positional arguments a probe exposes, or -1 when it can't be
 * determined (missing BTF/format), in which case numeric indices are not
 * range-checked.
 */
static int utrace_probe_arg_count(const struct utrace_cfg *cfg, const struct btf *btf)
{
	switch (cfg->type) {
	case UTRACE_TRACEPOINT:
		return cfg->tp.field_cnt;
	case UTRACE_RAW_TRACEPOINT: {
		const struct btf_type *proto = cfg->raw_tp.proto ?: cfg->raw_tp.name_proto;

		return proto ? btf_vlen(proto) - 1 : -1; /* skip void *__data */
	}
	case UTRACE_USDT:
		return cfg->usdt.info.arg_cnt;
	case UTRACE_KPROBE:
	case UTRACE_KRETPROBE:
	case UTRACE_KPROBE_SPAN:
	case UTRACE_BPF_PROBE:
	case UTRACE_BPF_RETPROBE:
	case UTRACE_BPF_SPAN: {
		const struct btf *rbtf = cfg_is_bpf_type(cfg) ? cfg->bpf_prog.btf : btf;
		const char *func = cfg_is_bpf_type(cfg) ? cfg->bpf_prog.name : cfg->kprobe.name;
		const struct btf_type *proto = rbtf ? btf_find_func_proto(rbtf, func) : NULL;

		return proto ? btf_vlen(proto) : -1;
	}
	default:
		return -1;
	}
}

static int param_sort_key(const struct utrace_param *p)
{
	if (p->type == UTRACE_PARAM_ARG)
		return UTRACE_PARAM_ARG + (p->arg.arg_idx == UTRACE_ARG_RET ? 99 : p->arg.arg_idx);
	return p->type;
}

static int cmp_params(const void *a, const void *b)
{
	return param_sort_key(a) - param_sort_key(b);
}

static int utrace_resolve_base(struct utrace_arg_state *state, struct utrace_cfg *cfg,
			       const struct btf *btf, struct utrace_param *p)
{
	enum utrace_arg_type inferred_type = UTRACE_ARG_UNKNOWN;
	const char *base_name = NULL;
	__u32 btf_id = 0;
	int err = -ENOENT;

	switch (cfg->type) {
	case UTRACE_TRACEPOINT: {
		int idx = p->arg.arg_idx;

		if (idx >= 0 && idx < cfg->tp.field_cnt) {
			const struct tp_field *field = &cfg->tp.fields[idx];

			p->arg.tp_byte_off = field->offset;
			p->arg.tp_data_loc = field->is_data_loc;
			base_name = field->name;
			if (field->is_string) {
				inferred_type = UTRACE_ARG_STR;
			} else {
				switch (field->size) {
				case 1: inferred_type = field->is_signed ? UTRACE_ARG_S8 : UTRACE_ARG_U8; break;
				case 2: inferred_type = field->is_signed ? UTRACE_ARG_S16 : UTRACE_ARG_U16; break;
				case 4: inferred_type = field->is_signed ? UTRACE_ARG_S32 : UTRACE_ARG_U32; break;
				default: inferred_type = field->is_signed ? UTRACE_ARG_S64 : UTRACE_ARG_U64; break;
				}
			}
		}
		break;
	}
	case UTRACE_RAW_TRACEPOINT: {
		int btf_idx = p->arg.arg_idx + 1; /* skip void *__data */

		if (cfg->raw_tp.proto) {
			err = resolve_btf_proto_arg_type(btf, cfg->raw_tp.proto, btf_idx,
							 &inferred_type, &base_name, &btf_id);
		}
		/* if proto had no names, try name_proto */
		if (!base_name && cfg->raw_tp.name_proto) {
			resolve_btf_proto_arg_type(btf, cfg->raw_tp.name_proto, btf_idx,
						   &inferred_type, &base_name, NULL);
		}
		break;
	}
	case UTRACE_USDT: {
		int idx = p->arg.arg_idx;

		if (idx >= 0 && idx < cfg->usdt.info.arg_cnt)
			inferred_type = usdt_arg_to_utrace_type(&cfg->usdt.info.args[idx]);
		break;
	}
	case UTRACE_KPROBE:
	case UTRACE_KRETPROBE:
	case UTRACE_KPROBE_SPAN:
	case UTRACE_BPF_PROBE:
	case UTRACE_BPF_RETPROBE:
	case UTRACE_BPF_SPAN: {
		const char *func_name = cfg_is_bpf_type(cfg) ? cfg->bpf_prog.name : cfg->kprobe.name;

		if (cfg_is_bpf_type(cfg) && !btf) {
			if (p->arg.accessor_cnt) {
				return utrace_acc_err(p, &p->arg.accessors[0],
							  "typed argument access requires BPF program BTF\n");
			}
		} else {
			err = resolve_btf_arg_type(btf, func_name, p->arg.arg_idx, &inferred_type, &base_name, &btf_id);
		}
		if (err && p->arg.arg_type == UTRACE_ARG_UNKNOWN) {
			wprintf("utrace: failed to determine type for %s arg %d, defaulting to u64\n",
				func_name, p->arg.arg_idx == UTRACE_ARG_RET ? -1 : p->arg.arg_idx);
		}
		break;
	}
	default:
		break;
	}

	if (!err)
		state->type = UTRACE_TYPE_REF(btf, btf_id);
	if (!base_name && p->arg.ref_name)
		base_name = p->arg.ref_name;
	if (!p->arg.name && base_name)
		p->arg.name = strdup(base_name);

	state->fallback_type = inferred_type;
	enum utrace_arg_type type = p->arg.arg_type == UTRACE_ARG_UNKNOWN ? state->fallback_type : p->arg.arg_type;
	unsigned char flags = 0;
	int arg_idx = p->arg.arg_idx;

	if (cfg->type == UTRACE_TRACEPOINT) {
		arg_idx = p->arg.tp_byte_off;
		if (type == UTRACE_ARG_STR)
			flags = p->arg.tp_data_loc ? UTRACE_READ_F_TP_DATA_LOC : UTRACE_READ_F_TP_INLINE;
	}
	p->arg.read_op_cnt = 0;
	return utrace_emit_read_op(p, NULL, UTRACE_READ_ARG, arg_idx, sizeof(void *), flags);
}

/* Expand wildcards and resolve arg types/names for a single cfg */
static int augment_cfg_args(struct utrace_cfg *cfg, const struct btf *vmlinux_btf)
{
	if (cfg->type == UTRACE_SPAN) {
		int err;

		err = augment_cfg_args(cfg->span.entry, vmlinux_btf);
		err = err ?: augment_cfg_args(cfg->span.exit, vmlinux_btf);
		return err;
	}
	const struct btf *btf = cfg_is_bpf_type(cfg) ? cfg->bpf_prog.btf : vmlinux_btf;

	if (cfg->type == UTRACE_RAW_TRACEPOINT) {
		if (resolve_raw_tp_btf(btf, cfg)) {
			bool has_args = cfg->wildcard_args;

			for (int j = 0; !has_args && j < cfg->param_cnt; j++)
				has_args = cfg->params[j].type == UTRACE_PARAM_ARG;
			if (has_args) {
				eprintf("utrace: no BTF for raw tracepoint '%s'; argument capture is not supported\n",
					cfg->raw_tp.name);
				return -ESRCH;
			}
			eprintf("utrace: no BTF for raw tracepoint '%s'; capturing event without arguments\n",
				cfg->raw_tp.name);
		}
	}
	if (cfg->type == UTRACE_TRACEPOINT) {
		if (resolve_tp_format(cfg))
			eprintf("utrace: failed to parse format for tracepoint '%s:%s'\n", cfg->tp.cat, cfg->tp.name);
	}

	if (cfg->wildcard_args)
		expand_wildcard_args(cfg, btf);

	int nonret_args = 0, ret_args = 0;
	for (int j = 0; j < cfg->param_cnt; j++) {
		if (cfg->params[j].type != UTRACE_PARAM_ARG)
			continue;
		if (cfg->params[j].arg.arg_idx == UTRACE_ARG_RET)
			ret_args++;
		else
			nonret_args++;
	}
	if (nonret_args > MAX_UTRACE_ARGS || ret_args > MAX_UTRACE_ARGS) {
		eprintf("utrace: too many arguments (max %d per probe entry/exit side)\n", MAX_UTRACE_ARGS);
		return -E2BIG;
	}

	/* resolve name-based arg references (arg:prev_pid) to indices */
	for (int j = 0; j < cfg->param_cnt; j++) {
		struct utrace_param *p = &cfg->params[j];
		if (p->type != UTRACE_PARAM_ARG || !p->arg.ref_name)
			continue;

		int resolved = resolve_arg_name(cfg, btf, p->arg.ref_name);
		if (resolved < 0) {
			eprintf("utrace: failed to resolve argument '%s'\n", p->arg.ref_name);
			return -ESRCH;
		} else {
			p->arg.arg_idx = resolved;
		}
	}

	/* range-check numeric arg indices against the probe's argument count */
	int arg_count = utrace_probe_arg_count(cfg, btf);
	if (arg_count >= 0) {
		for (int j = 0; j < cfg->param_cnt; j++) {
			struct utrace_param *p = &cfg->params[j];

			if (p->type != UTRACE_PARAM_ARG || p->arg.arg_idx == UTRACE_ARG_RET)
				continue;
			if (p->arg.arg_idx >= arg_count)
				return utrace_acc_err(p, NULL,
						      "argument index %d out of range (probe has %d argument%s)\n",
						      p->arg.arg_idx, arg_count, arg_count == 1 ? "" : "s");
		}
	}

	for (int j = 0; j < cfg->param_cnt; j++) {
		struct utrace_param *p = &cfg->params[j];

		if (p->type != UTRACE_PARAM_ARG)
			continue;

		struct utrace_arg_state state = { .loc = UTRACE_LOC_VALUE };
		const struct utrace_accessor *last = NULL;

		int err = utrace_resolve_base(&state, cfg, btf, p);
		if (err)
			return err;
		err = utrace_apply_accessors(&state, btf, p);
		if (err)
			return err;
		if (p->arg.accessor_cnt)
			last = &p->arg.accessors[p->arg.accessor_cnt - 1];
		if (!state.type.id)
			err = utrace_compile_fallback_terminal(&state, p);
		else
			err = utrace_compile_btf_terminal(&state, p, last);
		if (err)
			return err;

		if (p->arg.hex && !utrace_arg_is_int(p->arg.arg_type) && p->arg.arg_type != UTRACE_ARG_PTR) {
			eprintf("utrace: /x supports integer (u8..s64) and ptr args, but '%s' is neither\n",
				p->arg.name ?: "(unnamed)");
			return -EINVAL;
		}
		if (p->arg.map_cnt && !utrace_arg_is_int(p->arg.arg_type)) {
			eprintf("utrace: /map supports integer (u8..s64) args, but '%s' is not\n",
				p->arg.name ?: "(unnamed)");
			return -EINVAL;
		}
	}

	qsort(cfg->params, cfg->param_cnt, sizeof(*cfg->params), cmp_params);
	return 0;
}

static int utrace_augment_args(void)
{
	bool need_btf = false;

	for (int i = 0; i < env.utrace_cfg_cnt; i++) {
		if (cfg_needs_btf(&env.utrace_cfgs[i])) {
			need_btf = true;
			break;
		}
	}

	struct btf *vmlinux_btf = need_btf ? load_vmlinux_btf() : NULL;

	for (int i = 0; i < env.utrace_cfg_cnt; i++) {
		int err = augment_cfg_args(&env.utrace_cfgs[i], vmlinux_btf);
		if (err)
			return err;
	}

	/* compile name format templates after all arg types/names are resolved */
	for (int i = 0; i < env.utrace_cfg_cnt; i++) {
		struct utrace_cfg *cfg = &env.utrace_cfgs[i];

		if (cfg->settings.name_fmt)
			utrace_cfg_compile_name(cfg);
	}
	return 0;
}

/*
 * Resolve uprobe binary path by scanning /proc/<pid>/maps for executable VMAs.
 * Returns the /proc/<pid>/map_files/ path in attach_path_out (for ELF lookup and
 * uprobe attach) and the human-readable VMA name in display_path_out (for logging
 * and replay).
 */
static int resolve_uprobe_binary(int pid, const char *sym_name,
				 char **attach_path_out, char **display_path_out,
				 unsigned long *offset_out)
{
	__u32 last_dev_major = 0, last_dev_minor = 0;
	__u64 last_inode = 0;
	struct vma_info *vma;

	wprof_for_each(vma, vma, pid, VMA_QUERY_FILE_BACKED_VMA | VMA_QUERY_VMA_EXECUTABLE) {
		if (vma->vma_name[0] != '/')
			continue;
		/* skip duplicate segments of the same binary */
		if (vma->dev_major == last_dev_major && vma->dev_minor == last_dev_minor && vma->inode == last_inode)
			continue;
		last_dev_major = vma->dev_major;
		last_dev_minor = vma->dev_minor;
		last_inode = vma->inode;

		/* Use /proc/<pid>/map_files/ to access binary through the process's mount namespace */
		char map_file[128];
		snprintf(map_file, sizeof(map_file), "/proc/%d/map_files/%llx-%llx",
			 pid, (unsigned long long)vma->vma_start, (unsigned long long)vma->vma_end);

		unsigned long offset = 0;
		if (elf_find_syms(map_file, STT_FUNC, &sym_name, 1, &offset))
			continue;

		*attach_path_out = strdup(map_file);
		const char *name = vma->vma_name;
		if (str_has_suffix(name, " (deleted)"))
			*display_path_out = strndup(name, strlen(name) - 10);
		else
			*display_path_out = strdup(name);
		*offset_out = offset;
		return 0;
	}

	return -ENOENT;
}

/*
 * Resolve a uprobe cfg's attach target: either use its explicit path: to find
 * the symbol, or discover the binary via the process's /proc/<pid>/maps. Fills
 * cfg->uprobe.attach_path (malloc'd) and cfg->uprobe.attach_off with the final
 * path and total offset so attach time is a straight lookup.
 */
static int resolve_uprobe_cfg(struct utrace_cfg *cfg, bool mandatory)
{
	int lvl = mandatory ? -1 : 1;
	const char *binary_path = cfg_binary_path(cfg);
	int pid = cfg_pid(cfg);
	unsigned long sym_offset = 0;

	if (binary_path) {
		const char *sym_name = cfg->uprobe.name;
		int err = elf_find_syms(binary_path, STT_FUNC, &sym_name, 1, &sym_offset);
		if (err < 0) {
			log_printf(lvl, "utrace: failed to resolve symbol '%s' in '%s': %d\n",
				   cfg->uprobe.name, binary_path, err);
			return err;
		}
		cfg->uprobe.attach_path = binary_path;
		cfg->uprobe.display_path = binary_path;
	} else if (pid >= 0) {
		char *attach_path = NULL, *display_path = NULL;
		int err = resolve_uprobe_binary(pid, cfg->uprobe.name,
						&attach_path, &display_path, &sym_offset);
		if (err) {
			log_printf(lvl, "utrace: failed to find symbol '%s' in any binary of PID %d: %d\n",
				   cfg->uprobe.name, pid, err);
			return err;
		}
		cfg->uprobe.attach_path = attach_path;
		cfg->uprobe.display_path = display_path;
		cfg_set_binary_path(cfg, display_path);
	} else {
		eprintf("utrace: uprobe '%s' requires a binary path (path:) or process (pid:)\n", cfg->uprobe.name);
		return -EINVAL;
	}

	cfg->uprobe.attach_off = sym_offset + cfg->uprobe.off;
	return 0;
}

/*
 * Scan /proc/<pid>/maps for a binary containing a USDT matching provider:name.
 * Returns the /proc/<pid>/map_files/ path in attach_path_out and the
 * human-readable VMA name in display_path_out.
 */
static int resolve_usdt_binary(int pid, const char *provider, const char *name,
			       char **attach_path_out, char **display_path_out,
			       struct usdt_info *info)
{
	__u32 last_dev_major = 0, last_dev_minor = 0;
	__u64 last_inode = 0;
	struct vma_info *vma;

	wprof_for_each(vma, vma, pid, VMA_QUERY_FILE_BACKED_VMA | VMA_QUERY_VMA_EXECUTABLE) {
		if (vma->vma_name[0] != '/')
			continue;
		if (vma->dev_major == last_dev_major && vma->dev_minor == last_dev_minor && vma->inode == last_inode)
			continue;
		last_dev_major = vma->dev_major;
		last_dev_minor = vma->dev_minor;
		last_inode = vma->inode;

		char map_file[128];
		snprintf(map_file, sizeof(map_file), "/proc/%d/map_files/%llx-%llx",
			 pid, (unsigned long long)vma->vma_start, (unsigned long long)vma->vma_end);

		if (elf_find_usdt(map_file, provider, name, info))
			continue;

		*attach_path_out = strdup(map_file);
		const char *vma_name = vma->vma_name;
		if (str_has_suffix(vma_name, " (deleted)"))
			*display_path_out = strndup(vma_name, strlen(vma_name) - 10);
		else
			*display_path_out = strdup(vma_name);
		return 0;
	}

	return -ENOENT;
}

static int resolve_usdt_cfg(struct utrace_cfg *cfg, bool mandatory)
{
	int lvl = mandatory ? -1 : 1;
	const char *binary_path = cfg_binary_path(cfg);
	int pid = cfg_pid(cfg);

	if (binary_path) {
		int err = elf_find_usdt(binary_path, cfg->usdt.provider, cfg->usdt.name,
					&cfg->usdt.info);
		if (err) {
			log_printf(lvl, "utrace: USDT '%s:%s' not found in '%s': %d\n",
				   cfg->usdt.provider, cfg->usdt.name, binary_path, err);
			return err;
		}
		cfg->usdt.attach_path = binary_path;
		cfg->usdt.display_path = binary_path;
	} else if (pid >= 0) {
		char *attach_path = NULL, *display_path = NULL;
		int err = resolve_usdt_binary(pid, cfg->usdt.provider, cfg->usdt.name,
					      &attach_path, &display_path, &cfg->usdt.info);
		if (err) {
			log_printf(lvl, "utrace: USDT '%s:%s' not found in any binary of PID %d: %d\n",
				   cfg->usdt.provider, cfg->usdt.name, pid, err);
			return err;
		}
		cfg->usdt.attach_path = attach_path;
		cfg->usdt.display_path = display_path;
		cfg_set_binary_path(cfg, display_path);
	} else {
		eprintf("utrace: USDT '%s:%s' requires a binary path (path:) or process (pid:)\n",
			cfg->usdt.provider, cfg->usdt.name);
		return -EINVAL;
	}

	return 0;
}

static int find_bpf_prog_by_name(const char *name, int *prog_fd_out,
				 __u32 *btf_func_id_out, struct btf **btf_out)
{
	__u32 id = 0;
	int err = -ENOENT, prog_fd = -1;
	int match_prog_fd = -1, match_btf_func_id = 0;
	struct btf *match_btf = NULL;
	void *func_info_buf = NULL;
	struct btf *btf = NULL;
	bool found = false;

	while (!bpf_prog_get_next_id(id, &id)) {
		struct bpf_prog_info info;
		__u32 info_len = sizeof(info);

		func_info_buf = NULL;
		btf = NULL;
		found = false;

		memset(&info, 0, sizeof(info));

		prog_fd = bpf_prog_get_fd_by_id(id);
		if (prog_fd < 0)
			continue;

		/* first call to get func_info_cnt */
		err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
		if (err || info.btf_id == 0 || info.nr_func_info == 0)
			goto next;

		/* allocate and fetch func_info */
		__u32 func_info_cnt = info.nr_func_info;
		__u32 func_info_rec_size = info.func_info_rec_size;
		func_info_buf = calloc(func_info_cnt, func_info_rec_size);

		memset(&info, 0, sizeof(info));
		info_len = sizeof(info);
		info.func_info = (unsigned long long)(uintptr_t)func_info_buf;
		info.nr_func_info = func_info_cnt;
		info.func_info_rec_size = func_info_rec_size;

		err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
		if (err)
			goto next;

		btf = btf__load_from_kernel_by_id(info.btf_id);
		if (!btf)
			goto next;

		for (__u32 i = 0; i < info.nr_func_info; i++) {
			struct bpf_func_info *fi = func_info_buf + i * func_info_rec_size;
			const struct btf_type *t = btf__type_by_id(btf, fi->type_id);
			if (!t)
				continue;
			const char *func_name = btf__name_by_offset(btf, t->name_off);
			if (!func_name)
				continue;

			if (strcmp(func_name, name) != 0)
				continue;

			if (match_prog_fd >= 0) {
				eprintf("utrace: BPF function '%s' is ambiguous, can't proceed!\n", name);
				err = -EEXIST;
				goto out;
			}

			match_prog_fd = prog_fd;
			match_btf_func_id = fi->type_id;
			match_btf = btf;
			found = true;
			break;
		}
next:
		free(func_info_buf);
		if (!found) {
			btf__free(btf);
			close(prog_fd);
		}
	}

	if (match_prog_fd >= 0) {
		*prog_fd_out = match_prog_fd;
		*btf_func_id_out = match_btf_func_id;
		*btf_out = match_btf;
		return 0;
	}

	return -ENOENT;

out:
	free(func_info_buf);
	btf__free(btf);
	if (prog_fd >= 0)
		close(prog_fd);
	btf__free(match_btf);
	if (match_prog_fd >= 0)
		close(match_prog_fd);
	return err;
}

static bool is_uprobe_family(enum utrace_type type)
{
	switch (type) {
	case UTRACE_UPROBE:
	case UTRACE_URETPROBE:
	case UTRACE_UPROBE_SPAN:
	case UTRACE_USDT:
		return true;
	default:
		return false;
	}
}

static struct utrace_param *clone_params(const struct utrace_param *src, int cnt)
{
	if (!cnt)
		return NULL;
	struct utrace_param *dst = malloc(cnt * sizeof(*dst));
	memcpy(dst, src, cnt * sizeof(*dst));
	return dst;
}

static void params_set_pid(struct utrace_param *params, int cnt, int pid)
{
	for (int i = 0; i < cnt; i++) {
		if (params[i].type == UTRACE_PARAM_PID && params[i].pid.discovery != UTRACE_PID_DISCOVER_NONE) {
			params[i].pid.pid = pid;
			return;
		}
	}
}

static void clone_leg_with_pid(const struct utrace_cfg *src, struct utrace_cfg *dst,
			       int pid, enum utrace_pid_discovery discovery)
{
	*dst = *src;
	dst->params = clone_params(src->params, src->param_cnt);
	params_set_pid(dst->params, dst->param_cnt, pid);
	if (is_uprobe_family(dst->type))
		utrace_cfg_add_pid(dst, pid, discovery);
}

static void clone_cfg_with_pid(const struct utrace_cfg *src,
			       struct utrace_cfg *dst, int pid)
{
	*dst = *src;
	dst->settings.name_segs = NULL;
	dst->settings.name_seg_cnt = 0;

	if (src->type == UTRACE_SPAN) {
		enum utrace_pid_discovery d = cfg_pid_discovery(src);
		dst->span.entry = malloc(sizeof(*dst->span.entry));
		clone_leg_with_pid(src->span.entry, dst->span.entry, pid, d);
		dst->span.exit = malloc(sizeof(*dst->span.exit));
		clone_leg_with_pid(src->span.exit, dst->span.exit, pid, d);
	} else {
		dst->params = clone_params(src->params, src->param_cnt);
		params_set_pid(dst->params, dst->param_cnt, pid);
	}
}

/*
 * Expand pid:nv-smi probes into concrete per-PID cfgs.  Discovers GPU PIDs
 * lazily (cached in env), then clones each discovery cfg once per PID.
 * Resolution and filtering happen later in the normal utrace_setup loop.
 */
static int utrace_discover_pids(void)
{
	bool has_discovery = false;
	for (int i = 0; i < env.utrace_cfg_cnt; i++) {
		if (cfg_pid_discovery(&env.utrace_cfgs[i])) {
			has_discovery = true;
			break;
		}
	}
	if (!has_discovery)
		return 0;

	ensure_nv_smi_pids();

	struct utrace_cfg *new_cfgs = NULL;
	int new_cnt = 0;

	for (int i = 0; i < env.utrace_cfg_cnt; i++) {
		struct utrace_cfg *src = &env.utrace_cfgs[i];

		if (!cfg_pid_discovery(src)) {
			new_cfgs = realloc(new_cfgs, (new_cnt + 1) * sizeof(*new_cfgs));
			new_cfgs[new_cnt++] = *src;
			continue;
		}

		for (int j = 0; j < env.nv_smi_pid_cnt; j++) {
			struct utrace_cfg clone;
			clone_cfg_with_pid(src, &clone, env.nv_smi_pids[j]);

			new_cfgs = realloc(new_cfgs, (new_cnt + 1) * sizeof(*new_cfgs));
			new_cfgs[new_cnt++] = clone;
		}
	}

	free(env.utrace_cfgs);
	env.utrace_cfgs = new_cfgs;
	env.utrace_cfg_cnt = new_cnt;

	return 0;
}

int utrace_setup(struct wprof_bpf *skel)
{
	int err = utrace_discover_pids();
	if (err) {
		eprintf("Failed to expand utrace PID discovery: %d\n", err);
		return err;
	}

	if (env.utrace_cfg_cnt == 0) {
		env.capture_utrace = FALSE;
		env.requested_stack_traces &= ~ST_UTRACE;
		bpf_map__set_autocreate(skel->maps.utrace_probe_cfgs, false);
		bpf_map__set_autocreate(skel->maps.utrace_scratch, false);
		return 0;
	}

	env.capture_utrace = TRUE;

	if (!(env.requested_stack_traces & ST_UTRACE)) {
		for (int i = 0; i < env.utrace_cfg_cnt; i++) {
			const struct utrace_cfg *cfg = &env.utrace_cfgs[i];
			for (int j = 0; j < cfg->param_cnt; j++) {
				if (cfg->params[j].type == UTRACE_PARAM_CAPTURE_STACK) {
					eprintf("utrace config #%d requests 'stack' capture, but -Sutrace is not enabled\n", i + 1);
					return -EINVAL;
				}
			}
		}
	}

	bool need_fentry = false, need_fexit = false;
	int first_prog_fd = -1;
	const char *first_func_name = NULL;
	int map_cnt = 0;
	bool had_discovery = false;

	for (int i = 0; i < env.utrace_cfg_cnt; i++) {
		struct utrace_cfg *cfg = &env.utrace_cfgs[i];
		bool discovered = cfg_pid_discovery(cfg);
		int err = 0;

		if (discovered)
			had_discovery = true;

		utrace_for_each_leg(leg, cfg) {
			bool mandatory = cfg_pid_discovery(leg) == UTRACE_PID_DISCOVER_NONE;

			switch (leg->type) {
			case UTRACE_UPROBE:
			case UTRACE_URETPROBE:
			case UTRACE_UPROBE_SPAN:
				if (cfg_needs_uprobe(leg))
					bpf_program__set_autoload(skel->progs.wprof_ut_uprobe, true);
				if (cfg_needs_uretprobe(leg))
					bpf_program__set_autoload(skel->progs.wprof_ut_uret, true);
				err = resolve_uprobe_cfg(leg, mandatory);
				break;
			case UTRACE_KPROBE:
			case UTRACE_KRETPROBE:
			case UTRACE_KPROBE_SPAN: {
				struct btf *vmlinux_btf = load_vmlinux_btf();
				bool has_multi = btf__find_by_name_kind(vmlinux_btf, "bpf_kprobe_multi_link", BTF_KIND_STRUCT) > 0;
				if (cfg_needs_kprobe(leg)) {
					bpf_program__set_autoload(skel->progs.wprof_ut_kprobe, true);
					bpf_program__set_autoload(skel->progs.wprof_ut_kmulti, has_multi);
				}
				if (cfg_needs_kretprobe(leg)) {
					bpf_program__set_autoload(skel->progs.wprof_ut_kret, true);
					bpf_program__set_autoload(skel->progs.wprof_ut_kretmulti, has_multi);
				}
				break;
			}
			case UTRACE_USDT:
				bpf_program__set_autoload(skel->progs.wprof_ut_usdt, true);
				bpf_program__set_autoattach(skel->progs.wprof_ut_usdt, false);
				err = resolve_usdt_cfg(leg, mandatory);
				break;
			case UTRACE_RAW_TRACEPOINT:
				bpf_program__set_autoload(skel->progs.wprof_ut_raw_tp, true);
				break;
			case UTRACE_TRACEPOINT:
				bpf_program__set_autoload(skel->progs.wprof_ut_tp, true);
				break;
			case UTRACE_BPF_PROBE:
			case UTRACE_BPF_RETPROBE:
			case UTRACE_BPF_SPAN:
				err = find_bpf_prog_by_name(leg->bpf_prog.name,
								    &leg->bpf_prog.prog_fd,
								    &leg->bpf_prog.btf_func_id,
								    &leg->bpf_prog.btf);
				if (err) {
					eprintf("utrace: failed to find BPF program '%s': %d\n",
						leg->bpf_prog.name, err);
					return err;
				}
				if (first_prog_fd < 0) {
					first_prog_fd = leg->bpf_prog.prog_fd;
					first_func_name = leg->bpf_prog.name;
				}
				if (leg->type == UTRACE_BPF_PROBE || leg->type == UTRACE_BPF_SPAN)
					need_fentry = true;
				if (leg->type == UTRACE_BPF_RETPROBE || leg->type == UTRACE_BPF_SPAN)
					need_fexit = true;
				break;
			default:
				break;
			}

			if (err) {
				if (mandatory)
					return err;
				break;
			}
		}

		if (err) {
			int pid = cfg_pid(cfg);
			wprintf("utrace: discovered PID %d (%s) doesn't contain matching probe, skipping...\n",
				pid, proc_name(pid));
			cfg->type = UTRACE_INVALID;
			continue;
		}

		map_cnt += cfg_is_span(cfg) ? 2 : 1;
	}

	/* Remove failed discovery cfgs and check if any survived */
	if (had_discovery) {
		int nv_smi_ok = 0, j = 0;

		for (int i = 0; i < env.utrace_cfg_cnt; i++) {
			if (env.utrace_cfgs[i].type == UTRACE_INVALID)
				continue;

			if (cfg_pid_discovery(&env.utrace_cfgs[i]))
				nv_smi_ok += 1;

			env.utrace_cfgs[j] = env.utrace_cfgs[i];
			j += 1;
		}
		env.utrace_cfg_cnt = j;

		if (nv_smi_ok == 0) {
			eprintf("utrace: no discovered PIDs contain matching probe(s)!\n");
			return -ESRCH;
		}
	}

	bpf_map__set_autocreate(skel->maps.utrace_probe_cfgs, true);
	bpf_map__set_max_entries(skel->maps.utrace_probe_cfgs, map_cnt);

	if (first_prog_fd >= 0) {
		/*
		 * Set attach target on template programs so they get prepared properly.
		 * The actual target is overridden per-clone, so any valid target works here.
		 * Autoload is enabled so bpf_object__prepare() processes them, but must be
		 * disabled again before bpf_object__load() to prevent loading into kernel
		 * (templates are only used as clone sources).
		 */
		if (need_fentry) {
			err = bpf_program__set_attach_target(skel->progs.wprof_ut_bpf_entry,
							     first_prog_fd, first_func_name);
			if (err) {
				eprintf("utrace: failed to set fentry attach target: %d\n", err);
				return err;
			}
			bpf_program__set_autoload(skel->progs.wprof_ut_bpf_entry, true);
		}
		if (need_fexit) {
			err = bpf_program__set_attach_target(skel->progs.wprof_ut_bpf_exit,
							     first_prog_fd, first_func_name);
			if (err) {
				eprintf("utrace: failed to set fexit attach target: %d\n", err);
				return err;
			}
			bpf_program__set_autoload(skel->progs.wprof_ut_bpf_exit, true);
		}
	}

	err = utrace_augment_args();
	if (err)
		return err;

	/* Free BPF program BTFs — only needed for arg resolution above */
	for (int i = 0; i < env.utrace_cfg_cnt; i++) {
		utrace_for_each_leg(leg, &env.utrace_cfgs[i]) {
			if (cfg_is_bpf_type(leg)) {
				btf__free(leg->bpf_prog.btf);
				leg->bpf_prog.btf = NULL;
			}
		}
	}

	return 0;
}

/*
 * Attach one probe instance for the given cfg (which may be a simple type or a
 * native span). Callers of native spans (UPROBE_SPAN/KPROBE_SPAN/BPF_SPAN) invoke
 * this twice with is_retprobe false/true for entry/exit sides. For simple ret
 * types (URETPROBE/KRETPROBE/BPF_RETPROBE) callers pass is_retprobe=true.
 */
static int attach_utrace_probe(struct bpf_state *st, struct wprof_bpf *skel,
			       struct utrace_cfg *cfg, int utrace_id,
			       enum utrace_event_type event_type, bool is_exit,
			       bool is_retprobe, int map_fd, u32 *map_idx)
{
	struct utrace_probe_cfg pcfg;
	int err;

	fill_probe_cfg(&pcfg, cfg, utrace_id, event_type, is_exit);
	err = bpf_map_update_elem(map_fd, map_idx, &pcfg, BPF_ANY);
	if (err)
		return err;

	switch (cfg->type) {
	case UTRACE_UPROBE:
	case UTRACE_URETPROBE:
	case UTRACE_UPROBE_SPAN: {
		struct bpf_program *prog = is_retprobe ? skel->progs.wprof_ut_uret
						       : skel->progs.wprof_ut_uprobe;
		LIBBPF_OPTS(bpf_uprobe_opts, opts, .bpf_cookie = *map_idx, .retprobe = is_retprobe);
		struct bpf_link *link = bpf_program__attach_uprobe_opts(prog, cfg_pid(cfg),
									cfg->uprobe.attach_path,
									cfg->uprobe.attach_off, &opts);
		if (!link) {
			err = -errno;
			eprintf("utrace: failed to attach %s to '%s' in '%s': %d\n",
				is_retprobe ? "uretprobe" : "uprobe",
				cfg->uprobe.name, cfg->uprobe.display_path, err);
			return err;
		}
		err = add_link(st, link);
		if (err)
			return err;
		break;
	}
	case UTRACE_KPROBE:
	case UTRACE_KRETPROBE:
	case UTRACE_KPROBE_SPAN: {
		const char *kind = is_retprobe ? "kretprobe" : "kprobe";
		struct bpf_link *link = NULL;
		struct btf *vmlinux_btf = load_vmlinux_btf();
		bool has_multi = btf__find_by_name_kind(vmlinux_btf, "bpf_kprobe_multi_link", BTF_KIND_STRUCT) > 0;

		/*
		 * Multi-kprobe is generally faster than legacy breakpoint-based kprobes, but can
		 * only attach at function entry. Use it when the offset is zero (always true for
		 * kretprobe and span legs), and fall back to the legacy program for non-zero
		 * offsets or functions that aren't ftrace-attachable.
		 */
		if (has_multi && cfg->kprobe.off == 0) {
			struct bpf_program *prog = is_retprobe ? skel->progs.wprof_ut_kretmulti : skel->progs.wprof_ut_kmulti;
			const char *sym = cfg->kprobe.name;
			__u64 cookie = *map_idx;
			LIBBPF_OPTS(bpf_kprobe_multi_opts, mopts,
				.syms = &sym,
				.cookies = &cookie,
				.cnt = 1,
				.retprobe = is_retprobe,
			);
			link = bpf_program__attach_kprobe_multi_opts(prog, NULL, &mopts);
			if (!link) {
				err = -errno;
				vprintf("utrace: multi-%s attach to '%s' failed: %s. Falling back to legacy %s.\n",
					kind, cfg->kprobe.name, errstr(err), kind);
			}
		}

		if (!link) {
			struct bpf_program *prog = is_retprobe ? skel->progs.wprof_ut_kret : skel->progs.wprof_ut_kprobe;
			LIBBPF_OPTS(bpf_kprobe_opts, opts,
				.bpf_cookie = *map_idx,
				.retprobe = is_retprobe,
				.offset = cfg->kprobe.off,
			);
			link = bpf_program__attach_kprobe_opts(prog, cfg->kprobe.name, &opts);
		}

		if (!link) {
			err = -errno;
			eprintf("utrace: failed to attach %s to '%s': %s\n", kind, cfg->kprobe.name, errstr(err));
			return err;
		}
		err = add_link(st, link);
		if (err)
			return err;
		break;
	}
	case UTRACE_BPF_PROBE:
	case UTRACE_BPF_RETPROBE:
	case UTRACE_BPF_SPAN: {
		struct bpf_program *tmpl = is_retprobe ? skel->progs.wprof_ut_bpf_exit
						       : skel->progs.wprof_ut_bpf_entry;
		enum bpf_attach_type atype = is_retprobe ? BPF_TRACE_FEXIT : BPF_TRACE_FENTRY;

		LIBBPF_OPTS(bpf_prog_load_opts, clone_opts,
			    .attach_prog_fd = cfg->bpf_prog.prog_fd,
			    .attach_btf_id = cfg->bpf_prog.btf_func_id);
		int clone_fd = bpf_program__clone(tmpl, &clone_opts);
		if (clone_fd < 0) {
			eprintf("utrace: failed to clone %s for BPF prog '%s': %d\n",
				is_retprobe ? "fexit" : "fentry", cfg->bpf_prog.name, clone_fd);
			return clone_fd;
		}

		LIBBPF_OPTS(bpf_link_create_opts, link_opts, .tracing.cookie = *map_idx);
		int link_fd = bpf_link_create(clone_fd, 0, atype, &link_opts);
		close(clone_fd);
		if (link_fd < 0) {
			err = -errno;
			eprintf("utrace: failed to attach %s to BPF prog '%s': %d\n",
				is_retprobe ? "fexit" : "fentry", cfg->bpf_prog.name, err);
			return err;
		}
		err = add_link_fd(st, link_fd);
		if (err)
			return err;
		break;
	}
	case UTRACE_TRACEPOINT: {
		LIBBPF_OPTS(bpf_tracepoint_opts, opts, .bpf_cookie = *map_idx);
		struct bpf_link *link = bpf_program__attach_tracepoint_opts(skel->progs.wprof_ut_tp,
									    cfg->tp.cat, cfg->tp.name, &opts);
		if (!link) {
			err = -errno;
			eprintf("utrace: failed to attach tracepoint '%s:%s': %d\n", cfg->tp.cat, cfg->tp.name, err);
			return err;
		}
		err = add_link(st, link);
		if (err)
			return err;
		break;
	}
	case UTRACE_RAW_TRACEPOINT: {
		LIBBPF_OPTS(bpf_raw_tracepoint_opts, opts, .cookie = *map_idx);
		struct bpf_link *link = bpf_program__attach_raw_tracepoint_opts(
						skel->progs.wprof_ut_raw_tp,
						cfg->raw_tp.name, &opts);
		if (!link) {
			err = -errno;
			eprintf("utrace: failed to attach raw tracepoint '%s': %d\n", cfg->raw_tp.name, err);
			return err;
		}
		err = add_link(st, link);
		if (err)
			return err;
		break;
	}
	case UTRACE_USDT: {
		LIBBPF_OPTS(bpf_usdt_opts, opts, .usdt_cookie = *map_idx);
		struct bpf_link *link = bpf_program__attach_usdt(skel->progs.wprof_ut_usdt,
								 cfg_pid(cfg),
								 cfg->usdt.attach_path,
								 cfg->usdt.provider,
								 cfg->usdt.name, &opts);
		if (!link) {
			err = -errno;
			eprintf("utrace: failed to attach USDT '%s:%s' in '%s': %d\n",
				cfg->usdt.provider, cfg->usdt.name, cfg->usdt.display_path, err);
			return err;
		}
		err = add_link(st, link);
		if (err)
			return err;
		break;
	}
	default:
		eprintf("utrace: probe type %d not yet supported\n", cfg->type);
		return -EOPNOTSUPP;
	}

	(*map_idx)++;
	return 0;
}

int utrace_attach(struct bpf_state *st, struct wprof_bpf *skel)
{
	int err;
	int map_fd = bpf_map__fd(skel->maps.utrace_probe_cfgs);
	u32 map_idx = 0;

	for (int i = 0; i < env.utrace_cfg_cnt; i++) {
		struct utrace_cfg *cfg = &env.utrace_cfgs[i];

		switch (cfg->type) {
		case UTRACE_UPROBE:
		case UTRACE_URETPROBE:
		case UTRACE_KPROBE:
		case UTRACE_KRETPROBE:
		case UTRACE_BPF_PROBE:
		case UTRACE_BPF_RETPROBE:
		case UTRACE_USDT:
		case UTRACE_RAW_TRACEPOINT:
		case UTRACE_TRACEPOINT:
			err = attach_utrace_probe(st, skel, cfg, i, UTRACE_INSTANT, false,
						  cfg_is_ret_probe(cfg->type), map_fd, &map_idx);
			if (err)
				return err;
			break;
		case UTRACE_UPROBE_SPAN:
		case UTRACE_KPROBE_SPAN:
		case UTRACE_BPF_SPAN:
			err = attach_utrace_probe(st, skel, cfg, i, UTRACE_ENTRY, false,
						  false, map_fd, &map_idx);
			if (err)
				return err;
			err = attach_utrace_probe(st, skel, cfg, i, UTRACE_EXIT, true,
						  true, map_fd, &map_idx);
			if (err)
				return err;
			break;
		case UTRACE_SPAN: {
			struct utrace_cfg *entry = cfg->span.entry;
			struct utrace_cfg *exit = cfg->span.exit;

			err = attach_utrace_probe(st, skel, entry, i, UTRACE_ENTRY, false,
						  cfg_is_ret_probe(entry->type), map_fd, &map_idx);
			if (err)
				return err;
			err = attach_utrace_probe(st, skel, exit, i, UTRACE_EXIT, true,
						  cfg_is_ret_probe(exit->type), map_fd, &map_idx);
			if (err)
				return err;
			break;
		}
		default:
			eprintf("utrace: probe type %d not yet supported\n", cfg->type);
			return -EOPNOTSUPP;
		}
	}

	return 0;
}
