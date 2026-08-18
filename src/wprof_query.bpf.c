// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2026 Meta Platforms, Inc. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* program to look up; outputs below are valid only if attach_btf_id != 0 */
u32 targ_prog_id;

u32 prog_type;
u32 expected_attach_type;
u32 attach_btf_id;
u32 attach_btf_obj_id;
/* struct_ops: address of the member's stub function, 0 if not resolved */
u64 st_ops_stub_addr;

/* byte offset of member idx, mirroring __btf_member_bit_offset() */
static u32 member_off(const struct btf_type *t, u32 idx)
{
	const struct btf_member *m;
	u32 off;

	t = bpf_core_cast(t, struct btf_type);
	m = bpf_core_cast((const struct btf_member *)(t + 1) + idx, struct btf_member);
	/* BTF_INFO_KFLAG means offsets carry bitfield sizes in their top bits */
	off = (t->info >> 31) ? (m->offset & 0xffffff) : m->offset;
	return off / 8;
}

/*
 * Kernels since 6.15 record the implemented member on the program itself, older
 * ones need the lookup bpf_struct_ops_find() does. The descriptor is consumed
 * inside the loop so that no pointer escapes it, which would make the verifier
 * demand a NULL check on the exhausted path.
 */
static u64 find_st_ops_stub_addr(struct bpf_prog *prog, struct bpf_prog_aux *aux)
{
	u64 stride = bpf_core_type_size(struct bpf_struct_ops_desc);
	struct btf_struct_ops_tab *tab;
	u32 st_ops_btf_id;
	u64 addr = 0;
	int i;

	if (bpf_core_field_exists(aux->st_ops)) {
		void *cfi_stubs_addr = aux->st_ops->cfi_stubs;

		bpf_probe_read_kernel(&addr, sizeof(addr),
				      cfi_stubs_addr + aux->attach_st_ops_member_off);
		return addr;
	}

	tab = aux->attach_btf->struct_ops_tab;
	st_ops_btf_id = aux->attach_btf_id;

	bpf_for(i, 0, tab->cnt) {
		const struct bpf_struct_ops_desc *desc;
		void *cfi_stubs_addr;

		desc = bpf_core_cast((void *)tab->ops + i * stride, struct bpf_struct_ops_desc);
		if (desc->type_id != st_ops_btf_id)
			continue;
		cfi_stubs_addr = desc->st_ops->cfi_stubs;
		/* for struct_ops programs expected_attach_type is the ops member index */
		bpf_probe_read_kernel(&addr, sizeof(addr),
				      cfi_stubs_addr + member_off(desc->type, prog->expected_attach_type));
		break;
	}
	return addr;
}

SEC("iter/bpf_prog")
int wprof_query_prog_info(struct bpf_iter__bpf_prog *ctx)
{
	struct bpf_prog *prog = ctx->prog;
	struct bpf_prog_aux *aux;

	if (!prog)
		return 0;

	aux = prog->aux;
	if (aux->id != targ_prog_id)
		return 0;

	prog_type = prog->type;
	expected_attach_type = prog->expected_attach_type;
	attach_btf_id = aux->attach_btf_id;
	if (aux->attach_btf)
		attach_btf_obj_id = aux->attach_btf->id;
	else
		attach_btf_obj_id = 0;

	switch (prog->type) {
	case BPF_PROG_TYPE_STRUCT_OPS:
		st_ops_stub_addr = find_st_ops_stub_addr(prog, aux);
		break;
	default:
		break;
	}

	return 0;
}
