/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __REQUESTS_H_
#define __REQUESTS_H_

#include <stdint.h>

#include "utils.h"

struct uprobe_binary {
	/* unique binary identifier */
	u64 dev;
	u64 inode;

	/* informational info */
	char *path;
	char *attach_path;
};

static inline size_t uprobe_binary_hash_fn(long key, void *ctx)
{
	struct uprobe_binary *b = (void *)key;

	return hash_combine(b->dev, b->inode);
}

static inline bool uprobe_binary_equal_fn(long a, long b, void *ctx)
{
	struct uprobe_binary *x = (void *)a;
	struct uprobe_binary *y = (void *)b;

	return x->dev == y->dev && x->inode == y->inode;
}

int setup_req_tracking_discovery(void);

struct bpf_state;
int attach_req_tracking_usdts(struct bpf_state *st);

#endif /* __REQUESTS_H_ */
