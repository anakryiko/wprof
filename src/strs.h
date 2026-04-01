/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __STRS_H_
#define __STRS_H_

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* ======================== STRING VIEW (sview) ======================== */

struct sview {
	const char *s;
	int len;
};

static inline struct sview sv(const char *s, int len)
{
	return (struct sview){ .s = s, .len = len };
}

static inline struct sview sv_new(const char *s)
{
	return sv(s, strlen(s));
}

static inline struct sview sv_empty(void)
{
	return sv("", 0);
}

static inline bool sv_is_empty(struct sview v)
{
	return v.len == 0;
}

static inline struct sview sv_trim(struct sview v)
{
	while (v.len > 0 && isspace(v.s[0])) { v.s++; v.len--; }
	while (v.len > 0 && isspace(v.s[v.len - 1])) { v.len--; }
	return v;
}

static inline bool sv_eq(struct sview a, const char *b)
{
	return strncmp(a.s, b, a.len) == 0 && b[a.len] == '\0';
}

static inline bool sv_starts_with(struct sview v, const char *pfx)
{
	int plen = strlen(pfx);

	return v.len >= plen && strncmp(v.s, pfx, plen) == 0;
}

static inline char *sv_strdup(struct sview v)
{
	if (v.len < 0)
		return NULL;
	return strndup(v.s, v.len);
}

/* find substring in view, return -1 if not found */
static inline int sv_find(struct sview v, const char *needle)
{
	int nlen = strlen(needle);

	if (nlen > v.len)
		return -1;
	for (int i = 0; i <= v.len - nlen; i++)
		if (strncmp(v.s + i, needle, nlen) == 0)
			return i;
	return -1;
}

static inline struct sview sv_split(struct sview v, const char *delim, struct sview *right)
{
	int pos = sv_find(v, delim);

	if (pos < 0) {
		*right = sv_empty();
		return v;
	}

	*right = sv(v.s + pos, v.len - pos);
	return sv(v.s, pos);
}

static inline struct sview sv_consume_left(struct sview v, int n)
{
	if (n > v.len)
		n = v.len;
	return sv(v.s + n, v.len - n);
}

/* strip matching left/right delimiters from v; returns true on success, false if either is missing */
static inline bool sv_unwrap(struct sview *v, const char *left, const char *right)
{
	int llen = strlen(left);
	int rlen = strlen(right);

	if (v->len < llen + rlen)
		return false;
	if (strncmp(v->s, left, llen) != 0)
		return false;
	if (strncmp(v->s + v->len - rlen, right, rlen) != 0)
		return false;

	v->s += llen;
	v->len -= llen + rlen;
	return true;
}

static inline bool sv_as_long(struct sview v, long *val)
{
	int n = 0;

	return sscanf(v.s, "%li%n", val, &n) == 1 && n == v.len;
}

/* ======================== STRING BUFFER (sbuf) ======================== */

struct sbuf {
	char *buf;
	int len;
	int cap;
};

static inline struct sbuf sbuf_new(void)
{
	return (struct sbuf){ .buf = NULL, .len = 0, .cap = 0 };
}

static inline void sbuf_reset(struct sbuf *sb)
{
	sb->len = 0;
}

static inline void sbuf_free(struct sbuf *sb)
{
	free(sb->buf);
	sb->buf = NULL;
	sb->len = 0;
	sb->cap = 0;
}

static inline void sbuf_ensure(struct sbuf *sb, int need)
{
	int total = sb->len + need + 1; /* +1 for null terminator */

	if (total <= sb->cap)
		return;

	int new_cap = sb->cap * 5 / 4;
	if (new_cap < total)
		new_cap = total;

	sb->buf = realloc(sb->buf, new_cap);
	sb->cap = new_cap;
}

__attribute__((format(printf, 2, 3)))
static inline void sbuf_appendf(struct sbuf *sb, const char *fmt, ...)
{
	va_list ap;
	int need;

	va_start(ap, fmt);
	need = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	sbuf_ensure(sb, need);

	va_start(ap, fmt);
	vsnprintf(sb->buf + sb->len, need + 1, fmt, ap);
	va_end(ap);

	sb->len += need;
}

static inline const char *sbuf_str(struct sbuf *sb)
{
	if (!sb->buf) {
		sbuf_ensure(sb, 0);
		sb->buf[0] = '\0';
	}
	return sb->buf;
}

#endif /* __STRS_H_ */
