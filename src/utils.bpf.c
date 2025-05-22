// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2025 Meta Platforms, Inc. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "wprof.h"
#include "wprof.bpf.h"

#define GLOB_MAX_ITERS 1000

long ZERO = 0, ONE = 1, MINUS_ONE = -1;

static __always_inline unsigned char glob_str_char(size_t idx, const char *s, size_t sz)
{
	barrier_var(idx);
	if (idx >= sz)
		return '\0';
	barrier_var(idx);
	return s[idx] + ZERO;
}

/* Non-recursive glob matching logic, adapted from:
 *
 * https://github.com/torvalds/linux/blob/master/lib/glob.c
 */
struct glob_state {
	const char *pat, *str;
	size_t pat_sz, str_sz;

	ssize_t backtrack_pi;
	ssize_t backtrack_si;

	size_t pi;
	size_t si;

	int match; /* -1 - unknown, 0 - definitely not, 1 - definitely yes */
};

#define ITER_BREAK 1
#define ITER_CONT 0

static int glob_match_step(u32 iter, struct glob_state *st)
{
	unsigned char p = glob_str_char(st->pi, st->pat, st->pat_sz);
	unsigned char s = glob_str_char(st->si, st->str, st->str_sz);

	st->pi += ONE;
	st->si += ONE;

	switch (p) {
	case '?':
		/* single char wildcard matches anything but zero terminator */
		if (s == '\0') {
			st->match = 0; /* no match */
			return ITER_BREAK;
		}
		return ITER_CONT;
	case '*':
		/* any-length widlcard, matched lazily (the least amount
		 * of characters that is enough to satisfy the
		 * pattern), which permits never needing to backtrack
		 * more than one level (though it's not that obvious)
		 */
		if (glob_str_char(st->pi, st->pat, st->pat_sz) == '\0') {
			st->match = 1; /* match: trailing '*' matches anything */
			return ITER_BREAK;
		}
		st->backtrack_pi = st->pi;
		st->backtrack_si = st->si - ONE; /* allow zero-length match */
		st->si -= ONE; /* "unconsume" last string character */
		return ITER_CONT;
	default:
		if (p == '\\') {
			p = glob_str_char(st->pi, st->pat, st->pat_sz);
			st->pi += ONE;
		}
		/* literal character match */
		if (p == s) {
			if (p == '\0') {
				st->match = 1; /* full match */
				return ITER_BREAK;
			}
			return ITER_CONT;
		}

		if (s == '\0' || st->backtrack_pi < 0) {
			st->match = 0; /* no match and no backtracking left */
			return ITER_BREAK;
		}

		/* backtrack to last * wildcard and consume one character */
		st->backtrack_si += ONE;
		st->pi = st->backtrack_pi;
		st->si = st->backtrack_si;
		return ITER_CONT;
	}
}

int glob_match(const char *pat, size_t pat_sz, const char *str, size_t str_sz)
{
	struct glob_state state = {
		/* inputs */
		.pat = pat, .pat_sz = pat_sz,
		.str = str, .str_sz = str_sz,

		/* state */
		.backtrack_pi = MINUS_ONE,
		.backtrack_si = MINUS_ONE,
		.pi = ZERO,
		.si = ZERO,

		/* output */
		.match = -E2BIG,
	};

	bpf_loop(1000000, glob_match_step, &state, 0);

	return state.match;
}

#define GLOB_BPF_TEST 0

#if GLOB_BPF_TEST == 1
/* Glob matching tests. Adapted from:
 *
 * https://github.com/torvalds/linux/blob/master/lib/globtest.c
 */
SEC("tp_btf/sched_switch")
int BPF_PROG(wprof_test_glob, struct task_struct *p) {
	const bool MATCH = true, MISMATCH = false;
	static unsigned long cur_test = 0;
	static const struct glob_test {
		bool match;
		char pat[20];
		char str[24];
	} tests[] = {
		/* Some basic tests */
		{MATCH, "a", "a"},
		{MISMATCH, "a", "b"},
		{MISMATCH, "a", "aa"},
		{MISMATCH, "a", ""},
		{MATCH, "", ""},
		{MISMATCH, "", "a"},
		/* Simple character class tests */
		//{MATCH, "[a]", "a"},
		//{MISMATCH, "[a]", "b"},
		//{MISMATCH, "[!a]", "a"},
		//{MATCH, "[!a]", "b"},
		//{MATCH, "[ab]", "a"},
		//{MATCH, "[ab]", "b"},
		//{MISMATCH, "[ab]", "c"},
		//{MATCH, "[!ab]", "c"},
		//{MATCH, "[a-c]", "b"},
		//{MISMATCH, "[a-c]", "d"},
		/* Corner cases in character class parsing */
		//{MATCH, "[a-c-e-g]", "-"},
		//{MISMATCH, "[a-c-e-g]", "d"},
		//{MATCH, "[a-c-e-g]", "f"},
		//{MATCH, "[]a-ceg-ik[]", "a"},
		//{MATCH, "[]a-ceg-ik[]", "]"},
		//{MATCH, "[]a-ceg-ik[]", "["},
		//{MATCH, "[]a-ceg-ik[]", "h"},
		//{MISMATCH, "[]a-ceg-ik[]", "f"},
		//{MISMATCH, "[!]a-ceg-ik[]", "h"},
		//{MISMATCH, "[!]a-ceg-ik[]", "]"},
		//{MATCH, "[!]a-ceg-ik[]", "f"},
		/* Simple wild cards */
		{MATCH, "?", "a"},
		{MISMATCH, "?", "aa"},
		{MISMATCH, "??", "a"},
		{MATCH, "?x?", "axb"},
		{MISMATCH, "?x?", "abx"},
		{MISMATCH, "?x?", "xab"},
		/* Asterisk wild cards (backtracking) */
		{MISMATCH, "*??", "a"},
		{MATCH, "*??", "ab"},
		{MATCH, "*??", "abc"},
		{MATCH, "*??", "abcd"},
		{MISMATCH, "??*", "a"},
		{MATCH, "??*", "ab"},
		{MATCH, "??*", "abc"},
		{MATCH, "??*", "abcd"},
		{MISMATCH, "?*?", "a"},
		{MATCH, "?*?", "ab"},
		{MATCH, "?*?", "abc"},
		{MATCH, "?*?", "abcd"},
		{MATCH, "*b", "b"},
		{MATCH, "*b", "ab"},
		{MISMATCH, "*b", "ba"},
		{MATCH, "*b", "bb"},
		{MATCH, "*b", "abb"},
		{MATCH, "*b", "bab"},
		{MATCH, "*bc", "abbc"},
		{MATCH, "*bc", "bc"},
		{MATCH, "*bc", "bbc"},
		{MATCH, "*bc", "bcbc"},
		/* Multiple asterisks (complex backtracking) */
		{MATCH, "*ac*", "abacadaeafag"},
		{MATCH, "*ac*ae*ag*", "abacadaeafag"},
		//{MATCH, "*a*b*[bc]*[ef]*g*", "abacadaeafag"},
		//{MISMATCH, "*a*b*[ef]*[cd]*g*", "abacadaeafag"},
		{MATCH, "*abcd*", "abcabcabcabcdefg"},
		{MATCH, "*ab*cd*", "abcabcabcabcdefg"},
		{MATCH, "*abcd*abcdef*", "abcabcdabcdeabcdefg"},
		{MISMATCH, "*abcd*", "abcabcabcabcefg"},
		{MISMATCH, "*ab*cd*", "abcabcabcabcefg"},
	};

	unsigned long idx = __sync_fetch_and_add(&cur_test, 1);
	if (idx >= ARRAY_SIZE(tests))
		return 0;
	barrier_var(idx);

	const struct glob_test *test = &tests[idx];
	int res = glob_match(test->pat, sizeof(test->pat), test->str, sizeof(test->str));
	if (res < 0 || res != test->match) {
		bpf_printk("TEST #%lu: MISMATCH!!! RESULT %d != %d PAT '%s' STR '%s'",
			   cur_test - 1, res, test->match, test->pat, test->str);
	} else {
		bpf_printk("TEST #%lu: MATCH RESULT %d == %d PAT '%s' STR '%s'",
			   cur_test - 1, res, test->match, test->pat, test->str);
	}

	return 0;
}
#endif
