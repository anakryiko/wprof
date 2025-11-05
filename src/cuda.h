/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __CUDA_H_
#define __CUDA_H_

#include <stdint.h>

struct tracee_state;

struct cuda_tracee {
	int pid;
	const char *proc_name;
	int uds_fd;

	int log_fd;
	char *log_path;

	int dump_fd;
	char *dump_path;

	struct tracee_state *tracee;
};

int cuda_trace_setup(int workdir_fd);
void cuda_trace_teardown(void);
int cuda_trace_activate(int workdir_fd, uint64_t sess_start_ts, uint64_t sess_end_ts);
void cuda_trace_deactivate(void);

#endif /* __CUDA_H_ */
