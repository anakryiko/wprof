/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __WRUST_H_
#define __WRUST_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * libwrust: C interface to Rust standard-library data structures and helpers
 * (implemented in src/wrust/). Each data structure gets its own section below;
 * add new ones here as more Rust-backed interfaces are introduced.
 */

/* ==================== PRIORITY QUEUE ====================
 * Min priority queue over (key, value) pairs, backed by std BinaryHeap.
 * Ordered ascending and lexicographically on (key, value), so value breaks
 * ties on key.
 */
struct wpq;

struct wpq *wpq_new(size_t cap);
void wpq_free(struct wpq *pq);
void wpq_push(struct wpq *pq, uint64_t key, uint32_t val);
bool wpq_empty(const struct wpq *pq);
void wpq_peek(const struct wpq *pq, uint64_t *key, uint32_t *val);
void wpq_replace_min(struct wpq *pq, uint64_t key, uint32_t val);
void wpq_pop(struct wpq *pq);

#endif /* __WRUST_H_ */
