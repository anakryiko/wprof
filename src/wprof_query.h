/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __WPROF_QUERY_H_
#define __WPROF_QUERY_H_

#include <bpf/btf.h>

struct wprof_prog_info {
	enum bpf_attach_type expected_attach_type;
	/*
	 * Prototype describing the program's logical arguments, taken from
	 * whatever its program type attaches to, and the BTF holding it. Left
	 * NULL for program types whose attach target says nothing about them.
	 */
	const struct btf_type *proto;
	const struct btf *proto_btf;
};

/*
 * What a loaded program's own bpf_prog says about it, which bpf_prog_info
 * doesn't carry, read through a bpf_prog iterator. Beyond the attach type this
 * is program-type specific, so fields not described above are left alone.
 */
int wprof_query_prog_info(unsigned int prog_id, struct wprof_prog_info *info);

/*
 * Kernel-side type of a program type's context. A program is written against
 * the prog_ctx_type half of struct bpf_ctx_convert, but is called with the
 * kern_ctx_type one, which is what a probe on the program itself observes.
 * Returns a vmlinux BTF type ID, or zero if there is no usable one.
 */
int wprof_query_ctx_kern_type(enum bpf_prog_type prog_type);

#endif /* __WPROF_QUERY_H_ */
