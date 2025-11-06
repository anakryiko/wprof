/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __CUDA_H_
#define __CUDA_H_

#include <stdbool.h>
#include <stdint.h>

struct tracee_state;
struct inj_run_ctx;

struct cuda_tracee {
	int pid;
	const char *proc_name;
	int uds_fd;

	int log_fd;
	char *log_path;

	int dump_fd;
	char *dump_path;
	bool dump_ok;

	struct tracee_state *tracee;
	struct inj_run_ctx *ctx;
};

int cuda_trace_setup(int workdir_fd);
void cuda_trace_teardown(void);
int cuda_trace_prepare(int workdir_fd, long sess_timeout_ms);
int cuda_trace_activate(long sess_start_ts, long sess_end_ts);
void cuda_trace_deactivate(void);

#endif /* __CUDA_H_ */
