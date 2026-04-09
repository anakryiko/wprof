// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "hashmap.h"
#include "blobset.h"

/*
 * Pack blob offset, size, and alignment into a single long for use as
 * hashmap key.  Layout (64 bits):
 *   bits  0..25  -- offset into data buffer  (up to 64 MB)
 *   bits 26..31  -- alignment                (6 bits, up to 63)
 *   bits 32..63  -- blob size                (up to 4 GB)
 *
 * Alignment is part of the key so blobs with different alignment
 * requirements are never considered duplicates.
 */
static __always_inline long blob_key(size_t off, size_t sz, size_t align)
{
	return (long)(((unsigned long)sz << 32) |
		      ((unsigned long)align << 26) |
		      (unsigned long)off);
}

static __always_inline size_t blob_key_off(long key)
{
	return (size_t)((unsigned long)key & 0x3FFFFFF);
}

static __always_inline size_t blob_key_sz(long key)
{
	return (size_t)((unsigned long)key >> 32);
}

static __always_inline size_t align_up(size_t v, size_t align)
{
	return (v + align - 1) & ~(align - 1);
}

struct blobset {
	void *data;
	size_t data_len;
	size_t data_cap;

	struct hashmap *hash;
};

static size_t blob_hash_fn(long key, void *ctx)
{
	const struct blobset *set = ctx;
	const unsigned char *p = set->data + blob_key_off(key);
	size_t sz = blob_key_sz(key);
	/* seed with size and alignment so different-shaped blobs spread */
	size_t h = (size_t)((unsigned long)key >> 26);

	for (size_t i = 0; i < sz; i++)
		h = h * 31 + p[i];
	return h;
}

static bool blob_equal_fn(long key1, long key2, void *ctx)
{
	const struct blobset *set = ctx;

	/* upper 38 bits encode size + alignment -- must match exactly */
	if ((key1 ^ key2) >> 26)
		return false;
	return memcmp(set->data + blob_key_off(key1),
		      set->data + blob_key_off(key2),
		      blob_key_sz(key1)) == 0;
}

struct blobset *blobset__new(void)
{
	struct blobset *set = calloc(1, sizeof(*set));

	if (!set)
		return NULL;

	set->hash = hashmap__new(blob_hash_fn, blob_equal_fn, set);
	if (!set->hash) {
		free(set);
		return NULL;
	}

	set->data = calloc(1, 256);
	if (!set->data) {
		hashmap__free(set->hash);
		free(set);
		return NULL;
	}
	set->data_cap = 256;
	/* reserve byte at offset 0 so that offset 0 is never a valid blob */
	set->data_len = 1;

	return set;
}

void blobset__free(struct blobset *set)
{
	if (!set)
		return;
	hashmap__free(set->hash);
	free(set->data);
	free(set);
}

const void *blobset__data(const struct blobset *set)
{
	return set->data;
}

size_t blobset__data_size(const struct blobset *set)
{
	return set->data_len;
}

static void *blobset_ensure(struct blobset *set, size_t add_sz)
{
	size_t need = set->data_len + add_sz;

	if (need > set->data_cap) {
		size_t new_cap = set->data_cap * 2;

		if (new_cap < need)
			new_cap = need;
		if (new_cap < 256)
			new_cap = 256;

		void *new_data = realloc(set->data, new_cap);
		if (!new_data)
			return NULL;

		set->data = new_data;
		set->data_cap = new_cap;
	}
	return set->data + set->data_len;
}

/*
 * Add a blob to the set, deduplicating by content and alignment.
 * @align must be a power of 2 (minimum 1).
 * Returns the offset into the data buffer on success, or -errno on error.
 */
int blobset__add_blob(struct blobset *set, const void *blob, size_t len, size_t align)
{
	long old_key, new_key;
	int err;

	if (len == 0 || len > 0xFFFFFFFF || align == 0 || align > 63 || (align & (align - 1)))
		return -EINVAL;

	/* pad data_len up to desired alignment */
	size_t aligned_off = align_up(set->data_len, align);
	size_t pad = aligned_off - set->data_len;

	if (!blobset_ensure(set, pad + len))
		return -ENOMEM;

	if (pad) {
		memset(set->data + set->data_len, 0, pad);
		set->data_len = aligned_off;
	}

	new_key = blob_key(set->data_len, len, align);
	memcpy(set->data + set->data_len, blob, len);

	err = hashmap__insert(set->hash, new_key, new_key, HASHMAP_ADD, &old_key, NULL);
	if (err == -EEXIST)
		return blob_key_off(old_key);
	if (err)
		return err;

	set->data_len += len;
	return blob_key_off(new_key);
}
