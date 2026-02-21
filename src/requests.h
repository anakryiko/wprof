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

/* request listing */
enum req_field {
	REQ_FIELD_INVALID,
	REQ_FIELD_ID,
	REQ_FIELD_NAME,
	REQ_FIELD_COMM,
	REQ_FIELD_PID,
	REQ_FIELD_START,
	REQ_FIELD_END,
	REQ_FIELD_LATENCY,
};

enum req_sort_order {
	REQ_ORDER_INVALID,
	REQ_ORDER_DEFAULT,
	REQ_ORDER_ASC,
	REQ_ORDER_DESC,
};

enum req_filter_op {
	REQ_OP_INVALID,
	REQ_OP_EQ,
	REQ_OP_NE,
	REQ_OP_LT,
	REQ_OP_GT,
	REQ_OP_LE,
	REQ_OP_GE,
	REQ_OP_GLOB_MATCH,
	REQ_OP_GLOB_MISMATCH,
};

struct req_sort_spec {
	enum req_field field;
	enum req_sort_order order;
};

struct req_filter_spec {
	enum req_field field;
	enum req_filter_op op;
	union {
		const char *str_val;
		long num_val;
	};
};

struct req_list_cfg {
	struct req_sort_spec *sorts;
	int sort_cnt;
	struct req_filter_spec *filters;
	int filter_cnt;
	int top_n;
	int bottom_n;
};

struct worker_state;
int req_list_output(struct worker_state *w);

/* parsing helpers called from env.c */
int req_list_parse_sort(const char *field_name, enum req_sort_order order);
int req_list_parse_filter(const char *expr);

#endif /* __REQUESTS_H_ */
