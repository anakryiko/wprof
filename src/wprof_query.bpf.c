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

	return 0;
}
