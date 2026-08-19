/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __WPROF_QUERY_H_
#define __WPROF_QUERY_H_

#include <bpf/btf.h>

/*
 * Prototype of the struct_ops member a program implements, recovered from facts
 * that bpf_prog_info doesn't carry by reading struct bpf_prog through a bpf_prog
 * iterator.
 */
int wprof_query_st_ops_proto(unsigned int prog_id, const struct btf **btf_out,
			    const struct btf_type **proto_out);

/*
 * Kernel-side type of a program type's context. A program is written against
 * the prog_ctx_type half of struct bpf_ctx_convert, but is called with the
 * kern_ctx_type one, which is what a probe on the program itself observes.
 * Returns a vmlinux BTF type ID, or zero if there is no usable one.
 */
int wprof_query_ctx_kern_type(enum bpf_prog_type prog_type);

#endif /* __WPROF_QUERY_H_ */
