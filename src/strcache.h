/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __STRCACHE_H_
#define __STRCACHE_H_

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "wprof_types.h"
#include "strset.h"

/*
 * strcache: a lock-free read cache in front of a strset.
 *
 * Interning a string through a strset needs a lock -- strset is not thread-safe,
 * and even strset__find_str() mutates its buffer. For a read-mostly, write-once
 * set of strings interned from many threads (e.g. PyTorch RecordFunction op
 * names, observed on every autograd/interop thread) that lock serializes every
 * event. strcache fronts the strset with a fixed, append-only, open-addressing
 * table whose reads are lock-free: hash the string, probe a bounded number of
 * slots with acquire loads, compare. A previously-seen string (the common case)
 * returns its offset with no lock; only a string's first sighting falls to the
 * slow path, which interns it under the caller's lock and publishes the entry
 * with a release store.
 *
 * Sized for the *hot* set, not the whole vocabulary. Real workloads show a small
 * set of frequent names plus a high-cardinality tail of near-unique names (op
 * names with embedded shapes/ids), so probe length and load are bounded: the
 * tail simply stays on the locked path -- caching a seen-once name buys nothing
 * -- while the hot set is served lock-free, and the table never degrades into a
 * long scan or grows past its slot count.
 *
 * No deletes and no resize, so a lock-free reader never observes a moved or
 * freed slot; entries are freed once, via strcache_reset().
 */

#define STRCACHE_CAP       8192			/* slots; power of two */
#define STRCACHE_MAX_LOAD  (STRCACHE_CAP / 2)	/* cap inserts here to keep probe chains short */
#define STRCACHE_MAX_PROBE 16			/* beyond this a name stays on the locked path */

struct strcache_entry {
	u64 hash;	/* full name hash; the primary quick-reject within a probe chain */
	u32 off;	/* offset within set */
	u32 len;	/* strlen(str); fills the tail padding and keeps the verify a safe memcmp */
	char str[];	/* NUL-terminated copy (the interned source may be transient) */
};

struct strcache {
	struct strset *set;		/* backing store; offsets are into this */
	pthread_mutex_t *lock;		/* serializes cold inserts into set */
	int count;			/* cached entries (touched only under lock) */
	struct strcache_entry *slots[STRCACHE_CAP]; /* published/read atomically */
};

/* Initialize an empty cache fronting `set`, serializing cold inserts with `lock`. */
static inline void strcache_init(struct strcache *cache, struct strset *set, pthread_mutex_t *lock)
{
	memset(cache, 0, sizeof(*cache));
	cache->set = set;
	cache->lock = lock;
}

/* h*31 + c (like libbpf str_hash); a single pass also yields the length. */
static inline u64 strcache_hash(const char *s, u32 *len_out)
{
	const char *p;
	u64 h = 0;

	for (p = s; *p; p++)
		h = h * 31 + (unsigned char)*p;
	*len_out = (u32)(p - s);
	return h;
}

/* Publish str->off into the table. Caller must hold cache->lock. */
static inline void strcache_insert(struct strcache *cache, const char *str, u32 len, u64 h, u32 off)
{
	u32 idx = h & (STRCACHE_CAP - 1);

	if (cache->count >= STRCACHE_MAX_LOAD)
		return;

	for (u32 probe = 0; probe < STRCACHE_MAX_PROBE; probe++) {
		struct strcache_entry *cur = __atomic_load_n(&cache->slots[idx], __ATOMIC_RELAXED);
		if (cur) {
			/* same string already cached (e.g. a racing reader interned it)? done */
			if (cur->hash == h && cur->len == len && memcmp(cur->str, str, len) == 0)
				return;
			/* a different name occupies this slot: collision, probe the next one */
			idx = (idx + 1) & (STRCACHE_CAP - 1);
			continue;
		}

		/* empty slot: publish a fresh entry here */
		struct strcache_entry *e = malloc(sizeof(*e) + len + 1);
		if (!e)
			return; /* best-effort cache */
		e->hash = h;
		e->off = off;
		e->len = len;
		memcpy(e->str, str, len + 1);
		__atomic_store_n(&cache->slots[idx], e, __ATOMIC_RELEASE);
		cache->count++;
		return;
	}
	/* probe window full: leave uncached (still correct, just stays on the lock) */
}

/* Intern str into cache->set, returning its offset; lock-free on the warm path. */
static inline u32 strcache_intern(struct strcache *cache, const char *str)
{
	u32 len;
	u64 h = strcache_hash(str, &len);
	u32 idx = h & (STRCACHE_CAP - 1);

	for (u32 probe = 0; probe < STRCACHE_MAX_PROBE; probe++) {
		struct strcache_entry *e = __atomic_load_n(&cache->slots[idx], __ATOMIC_ACQUIRE);
		if (!e)
			break; /* first empty slot in the chain => not cached */
		if (e->hash == h && e->len == len && memcmp(e->str, str, len) == 0)
			return e->off;
		idx = (idx + 1) & (STRCACHE_CAP - 1);
	}

	/*
	 * cold: intern under the lock. strset__add_str returns < 0 only when the
	 * strset is full -- record offset 0 (the "" sentinel), not a garbage offset.
	 */
	pthread_mutex_lock(cache->lock);
	int off = strset__add_str(cache->set, str);
	strcache_insert(cache, str, len, h, off < 0 ? 0 : off);
	pthread_mutex_unlock(cache->lock);
	return off < 0 ? 0 : off;
}

/* Free all entries. Caller must ensure no concurrent intern (e.g. callbacks drained). */
static inline void strcache_reset(struct strcache *cache)
{
	for (u32 i = 0; i < STRCACHE_CAP; i++) {
		free(cache->slots[i]);
		cache->slots[i] = NULL;
	}
	cache->count = 0;
}

#endif /* __STRCACHE_H_ */
