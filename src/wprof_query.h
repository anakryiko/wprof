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

#endif /* __WPROF_QUERY_H_ */
