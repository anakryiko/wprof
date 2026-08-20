// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Meta Platforms, Inc. */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "utils.h"
#include "ksyms.h"
#include "wprof_query.h"
#include "wprof_query.skel.h"

static struct wprof_query_bpf *skel;
static struct bpf_link *iter_link;
static int init_err;

static int query_init(void)
{
	if (iter_link || init_err)
		return init_err;

	skel = wprof_query_bpf__open_and_load();
	if (!skel) {
		init_err = -errno;
		return init_err;
	}
	iter_link = bpf_program__attach_iter(skel->progs.wprof_query_prog_info, NULL);
	if (!iter_link) {
		init_err = -errno;
		wprof_query_bpf__destroy(skel);
		skel = NULL;
		return init_err;
	}
	return 0;
}

/*
 * Run the bpf_prog iterator over every loaded program. The program matches
 * targ_prog_id and writes its answer into globals, never into the seq file, so
 * a single read() walks the whole set and reports end of iteration.
 */
static int query_prog(unsigned int prog_id)
{
	char buf[8];
	int iter_fd, err;

	err = query_init();
	if (err)
		return err;

	skel->bss->targ_prog_id = prog_id;
	skel->bss->prog_type = 0;
	skel->bss->expected_attach_type = 0;
	skel->bss->attach_btf_id = 0;
	skel->bss->attach_btf_obj_id = 0;
	skel->bss->st_ops_stub_addr = 0;

	iter_fd = bpf_iter_create(bpf_link__fd(iter_link));
	if (iter_fd < 0)
		return -errno;

	err = read(iter_fd, buf, sizeof(buf)) < 0 ? -errno : 0;
	close(iter_fd);
	return err;
}

static struct {
	__u32 id;
	struct btf *btf;
} *mod_btfs;
static int mod_btf_cnt;

static const struct btf *fetch_kernel_btf(__u32 obj_id)
{
	struct btf *vmlinux_btf = load_vmlinux_btf();

	if (obj_id <= 1)
		return vmlinux_btf;

	for (int i = 0; i < mod_btf_cnt; i++) {
		if (mod_btfs[i].id == obj_id)
			return mod_btfs[i].btf;
	}

	struct btf *btf = btf__load_from_kernel_by_id_split(obj_id, vmlinux_btf);
	if (!btf)
		return NULL;

	mod_btfs = realloc(mod_btfs, (mod_btf_cnt + 1) * sizeof(*mod_btfs));
	mod_btfs[mod_btf_cnt].id = obj_id;
	mod_btfs[mod_btf_cnt].btf = btf;
	mod_btf_cnt++;
	return btf;
}

static const struct btf_type *btf_skip_mods(const struct btf *btf, __u32 id)
{
	const struct btf_type *t;

	for (t = btf__type_by_id(btf, id); btf_is_mod(t) || btf_is_typedef(t); t = btf__type_by_id(btf, id))
		id = t->type;
	return t;
}

static const struct btf_type *btf_resolve_func_ptr(const struct btf *btf, __u32 id)
{
	const struct btf_type *t = btf_skip_mods(btf, id);

	if (!btf_is_ptr(t))
		return NULL;
	t = btf_skip_mods(btf, t->type);
	if (!btf_is_func_proto(t))
		return NULL;
	return t;
}

/*
 * The ops struct only declares a member's arguments, so they have no names. The
 * stub function the kernel keeps in cfi_stubs for that member is a real
 * function, and its BTF does name them, so prefer its prototype when the two
 * agree on arity and argument types, as prepare_arg_info() requires them to.
 */
static const struct btf_type *st_ops_stub_proto(const struct btf *btf, const struct btf_type *proto,
					       __u64 addr)
{
	const struct btf_type *sproto;
	const struct btf_param *p, *sp;
	const struct ksyms *ksyms;
	const struct ksym *ksym;
	__s32 id;

	if (!addr)
		return NULL;
	ksyms = load_ksyms();
	if (!ksyms)
		return NULL;
	ksym = ksyms__map_addr(ksyms, addr, KSYM_FUNC);
	if (!ksym || ksym->addr != addr)
		return NULL;

	id = btf__find_by_name_kind(btf, ksym->name, BTF_KIND_FUNC);
	if (id < 0)
		return NULL;
	sproto = btf__type_by_id(btf, btf__type_by_id(btf, id)->type);
	if (!btf_is_func_proto(sproto) || btf_vlen(sproto) != btf_vlen(proto))
		return NULL;

	p = btf_params(proto);
	sp = btf_params(sproto);
	for (int i = 0; i < btf_vlen(proto); i++) {
		if (p[i].type != sp[i].type)
			return NULL;
	}
	return sproto;
}

static int st_ops_info(struct wprof_prog_info *info)
{
	const struct btf_type *t, *proto;
	const struct btf_member *m;
	const struct btf *btf;
	__u32 member_idx;

	if (!skel->bss->attach_btf_id)
		return -ENOENT;

	btf = fetch_kernel_btf(skel->bss->attach_btf_obj_id);
	if (!btf)
		return -ESRCH;

	/* for struct_ops programs expected_attach_type is the ops member index */
	member_idx = skel->bss->expected_attach_type;

	t = btf__type_by_id(btf, skel->bss->attach_btf_id);
	if (!btf_is_struct(t) || member_idx >= btf_vlen(t))
		return -EINVAL;

	m = btf_members(t) + member_idx;
	proto = btf_resolve_func_ptr(btf, m->type);
	if (!proto)
		return -EINVAL;

	info->proto_btf = btf;
	info->proto = st_ops_stub_proto(btf, proto, skel->bss->st_ops_stub_addr) ?: proto;
	info->args_in_ctx = true;
	return 0;
}

/*
 * fentry, fexit and LSM programs are called with the arguments of the function
 * they attach to, which attach_btf_id names.
 */
static int attach_func_info(struct wprof_prog_info *info)
{
	const struct btf_type *t, *proto;
	const struct btf *btf;

	/*
	 * Without an attach_btf the target is another BPF program, and
	 * attach_btf_id indexes that program's BTF rather than the kernel's.
	 * Leave the arguments to the program's own prototype.
	 */
	if (!skel->bss->attach_btf_id || !skel->bss->attach_btf_obj_id)
		return 0;

	btf = fetch_kernel_btf(skel->bss->attach_btf_obj_id);
	if (!btf)
		return -ESRCH;

	t = btf__type_by_id(btf, skel->bss->attach_btf_id);
	if (!btf_is_func(t))
		return -EINVAL;
	proto = btf__type_by_id(btf, t->type);
	if (!btf_is_func_proto(proto))
		return -EINVAL;

	info->proto_btf = btf;
	info->proto = proto;
	info->args_in_ctx = true;
	return 0;
}

/*
 * A tp_btf program attaches to a tracepoint through its btf_trace_<name>
 * typedef, whose prototype leads with the void *__data the tracepoint passes
 * ahead of its own arguments. It is returned as it is, for the tracepoint side
 * of utrace to skip like it does for raw tracepoints.
 */
static int tp_btf_info(struct wprof_prog_info *info)
{
	const char prefix[] = "btf_trace_";
	const struct btf_type *t, *proto;
	const struct btf *btf;
	const char *name;
	char buf[256];
	__s32 id;

	if (!skel->bss->attach_btf_id || !skel->bss->attach_btf_obj_id)
		return 0;

	btf = fetch_kernel_btf(skel->bss->attach_btf_obj_id);
	if (!btf)
		return -ESRCH;

	proto = btf_resolve_func_ptr(btf, skel->bss->attach_btf_id);
	if (!proto || btf_vlen(proto) < 1)
		return -EINVAL;

	/* the typedef leaves its arguments unnamed, the trace functions name them */
	static const char *name_funcs[] = { "__bpf_trace_%s", "__traceiter_%s", "__tracepoint_iter_%s" };

	t = btf__type_by_id(btf, skel->bss->attach_btf_id);
	name = btf__name_by_offset(btf, t->name_off);
	if (strncmp(name, prefix, sizeof(prefix) - 1) != 0)
		goto out;
	name += sizeof(prefix) - 1;

	for (int i = 0; i < ARRAY_SIZE(name_funcs); i++) {
		snprintf(buf, sizeof(buf), name_funcs[i], name);
		id = btf__find_by_name_kind(btf, buf, BTF_KIND_FUNC);
		if (id < 0)
			continue;
		t = btf__type_by_id(btf, btf__type_by_id(btf, id)->type);
		if (btf_is_func_proto(t) && btf_vlen(t) == btf_vlen(proto)) {
			proto = t;
			break;
		}
	}
out:
	info->proto_btf = btf;
	info->proto = proto;
	info->arg_idx_off = 1;
	info->args_in_ctx = true;
	return 0;
}

int wprof_query_prog_info(unsigned int prog_id, struct wprof_prog_info *info)
{
	int err;

	err = query_prog(prog_id);
	if (err)
		return err;

	info->expected_attach_type = skel->bss->expected_attach_type;

	/*
	 * The attach type only means anything within a program type: struct_ops
	 * reuses the field as an ops member index, which aliases the values the
	 * tracing and LSM types use.
	 */
	switch (skel->bss->prog_type) {
	case BPF_PROG_TYPE_STRUCT_OPS:
		return st_ops_info(info);
	case BPF_PROG_TYPE_TRACING:
		switch (info->expected_attach_type) {
		case BPF_TRACE_FENTRY:
		case BPF_TRACE_FEXIT:
		case BPF_MODIFY_RETURN:
			return attach_func_info(info);
		case BPF_TRACE_RAW_TP:
			return tp_btf_info(info);
		default:
			return 0;
		}
	case BPF_PROG_TYPE_LSM:
		switch (info->expected_attach_type) {
		case BPF_LSM_MAC:
		case BPF_LSM_CGROUP:
			return attach_func_info(info);
		default:
			return 0;
		}
	default:
		return 0;
	}
}

/*
 * Members of struct bpf_ctx_convert come in prog/kern pairs, one per program
 * type. The kernel indexes them through a private table that BTF doesn't carry,
 * so match on the member name instead.
 */
int wprof_query_ctx_kern_type(enum bpf_prog_type prog_type)
{
	struct btf *vmlinux_btf = load_vmlinux_btf();
	const char *name = libbpf_bpf_prog_type_str(prog_type);
	const struct btf_member *m;
	const struct btf_type *t;
	char member[256];
	__s32 id;
	int i, n;

	if (!name)
		return 0;

	n = snprintf(member, sizeof(member), "BPF_PROG_TYPE_%s", name);
	for (i = 0; i < n; i++)
		member[i] = toupper(member[i]);
	strcpy(member + n, "_kern");

	id = btf__find_by_name_kind(vmlinux_btf, "bpf_ctx_convert", BTF_KIND_STRUCT);
	if (id < 0)
		return id;

	t = btf__type_by_id(vmlinux_btf, id);
	m = btf_members(t);
	for (i = 0; i < btf_vlen(t); i++, m++) {
		if (strcmp(btf__name_by_offset(vmlinux_btf, m->name_off), member) != 0)
			continue;
		/* types that have no real context, like void * or u64, are of no use */
		if (!btf_is_struct(btf_skip_mods(vmlinux_btf, m->type)))
			return 0;
		return m->type;
	}
	return 0;
}
