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

/* ==================== SORT ====================
 * In-place stable sort of (timestamp, event pointer) pairs, ascending by ts. The
 * timestamp is kept inline so the sort never dereferences ptr.
 */
struct wrust_ts_ptr {
	uint64_t ts;
	const void *ptr;
};
void wrust_sort_events_by_ts(struct wrust_ts_ptr *items, size_t cnt);

/*
 * ==================== POINTER PRIORITY QUEUE ====================
 * Min priority queue over (key, pointer) pairs, backed by std BinaryHeap.
 * Sibling of wpq whose value is a pointer rather than a uint32_t; the pointer
 * is stored as usize internally. Ordered ascending on key, with the pointer
 * bits breaking ties deterministically. The queue does not own the pointed-to
 * memory: wppq_free() releases only the queue itself, so drain via wppq_pop()
 * first if the values need freeing.
 */
struct wppq;

struct wppq *wppq_new(size_t cap);
void wppq_free(struct wppq *pq);
void wppq_push(struct wppq *pq, uint64_t key, void *val);
bool wppq_empty(const struct wppq *pq);
size_t wppq_len(const struct wppq *pq);
uint64_t wppq_peek_key(const struct wppq *pq);  /* min key; requires non-empty */
void *wppq_pop(struct wppq *pq);                 /* min value, or NULL if empty */

/* ======================== DWARF parsing ========================= */

struct dwarf_info;

/*
 * Parses DWARF from a vmlinux ELF and creates a dwarf_info instance with information
 * about functions listed in @func_names. Looks for vmlinux in the following locations:
 * - /boot/vmlinux-$(uname -r)
 * - /usr/lib/modules/$(uname -r)/vmlinux-$(uname -r)
 *
 * Returns NULL if no vmlinux was found or if there was an error while reading DWARF.
 * DWARF parsing errors are logged.
 */
struct dwarf_info *dwarf_info_init_vmlinux(const char *const *func_names, size_t func_name_cnt);
/* Returns the path to the ELF file from which @info was derived. */
const char *dwarf_info_elf_path(const struct dwarf_info *info);
void dwarf_info_free(struct dwarf_info *info);

struct dwarf_func_addr {
	uint64_t addr; /* ELF virtual address. */
	const char *file_name; /* Cleaned declaration file path, or NULL if unavailable. */
	bool is_inline; /* True for DW_TAG_inlined_subroutine. */
};

/*
 * Look up DW_TAG_inlined_subroutine and DW_TAG_subprogram entries by function name.
 * Returns NULL and sets *cnt to zero if absent.
 */
const struct dwarf_func_addr *dwarf_info_find_func(const struct dwarf_info *info,
                                                   const char *name,
                                                   size_t *cnt);

#endif /* __WRUST_H_ */
