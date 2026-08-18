// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Meta Platforms, Inc. */
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "utils.h"
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

int wprof_query_struct_ops_proto(unsigned int prog_id, const struct btf **btf_out,
				 const struct btf_type **proto_out)
{
	const struct btf_type *t, *proto;
	const struct btf_member *m;
	const struct btf *btf;
	int err;

	err = query_prog(prog_id);
	if (err)
		return err;
	if (!skel->bss->attach_btf_id)
		return -ENOENT;

	btf = fetch_kernel_btf(skel->bss->attach_btf_obj_id);
	if (!btf)
		return -ESRCH;

	/* for struct_ops programs expected_attach_type is the ops member index */
	__u32 member_idx = skel->bss->expected_attach_type;

	t = btf__type_by_id(btf, skel->bss->attach_btf_id);
	if (!btf_is_struct(t) || member_idx >= btf_vlen(t))
		return -EINVAL;

	m = btf_members(t) + member_idx;
	proto = btf_resolve_func_ptr(btf, m->type);
	if (!proto)
		return -EINVAL;

	*btf_out = btf;
	*proto_out = proto;
	return 0;
}
