/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __PYTRACE_H_
#define __PYTRACE_H_

#include <stdbool.h>
#include <stdint.h>
#include "cuda.h"
#include "inj_common.h"

#define DEFAULT_CAPTURE_PYTRACE FALSE

struct tracee_state;
struct inj_run_ctx;

struct pytrace_tracee {
	int pid;
	int ns_pid;
	const char *proc_name;
	int uds_fd;

	enum cuda_tracee_state state; /* reuse same state machine as CUDA */

	int log_fd;
	char *log_path;

	int dump_fd;
	char *dump_path;

	int torch_dump_fd;
	char *torch_dump_path;

	int py_version_minor;	/* detected Python 3.x version */
	unsigned long sym_addrs[PYTRACE_SYM_CNT];
	unsigned long torch_sym_addrs[TORCH_SYM_CNT];

	struct tracee_state *tracee;
	struct inj_run_ctx *ctx;
};

const char *pytrace_str(const struct pytrace_tracee *t);

int pytrace_trace_setup(int workdir_fd);
void pytrace_trace_teardown(void);
int pytrace_trace_prepare(int workdir_fd, long sess_timeout_ms);
int pytrace_trace_activate(long sess_start_ts, long sess_end_ts);
void pytrace_trace_deactivate(void);
void pytrace_trace_retract(void);

#endif /* __PYTRACE_H_ */
