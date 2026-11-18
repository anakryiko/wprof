/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __UTRACE_TRIGGER_H_
#define __UTRACE_TRIGGER_H_

#include <linux/types.h>

/* first hit of a utrace trigger, keep in sync with the copy in utrace_trigger.bpf.c */
struct utrace_trigger_hit {
	__u32 pid;
	__u32 tid;
	__u32 cpu;
	char comm[16];	/* TASK_COMM_LEN */
};

struct utrace_cfg;
struct utrace_trigger;

/*
 * Attach a utrace trigger for a probe parsed by ucfg_parse_trigger(). The
 * trigger takes over the heap-allocated cfg, which can be expanded into
 * several attach targets by PID discovery. desc names the trigger in messages.
 */
int utrace_trigger_start(struct utrace_cfg *cfg, const char *desc, struct utrace_trigger **out);
/* epoll-able fd, ready once the utrace trigger got hit */
int utrace_trigger_fd(const struct utrace_trigger *t);
/* number of utrace trigger hits so far, including ones not polled yet */
__u64 utrace_trigger_hit_cnt(const struct utrace_trigger *t);
/* 1 and the first hit in *hit, if the utrace trigger got hit, 0 if not yet, <0 on error */
int utrace_trigger_poll(struct utrace_trigger *t, struct utrace_trigger_hit *hit);
/* Detach the utrace trigger and free everything, t may be NULL */
void utrace_trigger_stop(struct utrace_trigger *t);

#endif /* __UTRACE_TRIGGER_H_ */
