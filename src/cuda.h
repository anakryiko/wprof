/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __CUDA_H_
#define __CUDA_H_

#include <stdbool.h>
#include <stdint.h>

struct tracee_state;
struct inj_run_ctx;

enum cuda_tracee_state {
	TRACEE_UNINIT,
	TRACEE_INJECTED,
	TRACEE_PENDING,
	TRACEE_ACTIVE,
	TRACEE_INACTIVE,
	TRACEE_SETUP_TIMEOUT,
	TRACEE_SETUP_FAILED,
	TRACEE_IGNORED,
	TRACEE_SHUTDOWN_TIMEOUT,
	TRACEE_SHUTDOWN_FAILED,
};

static inline const char *cuda_tracee_state_str(enum cuda_tracee_state state)
{
	switch (state) {
	case TRACEE_UNINIT: return "UNINIT";
	case TRACEE_INJECTED: return "INJECTED";
	case TRACEE_PENDING: return "PENDING";
	case TRACEE_ACTIVE: return "ACTIVE";
	case TRACEE_INACTIVE: return "INACTIVE";
	case TRACEE_SETUP_TIMEOUT: return "SETUP_TIMEOUT";
	case TRACEE_SETUP_FAILED: return "SETUP_FAILED";
	case TRACEE_IGNORED: return "IGNORED";
	case TRACEE_SHUTDOWN_TIMEOUT: return "SHUTDOWN_TIMEOUT";
	case TRACEE_SHUTDOWN_FAILED: return "SHUTDOWN_FAILED";
	default: return "???";
	}
}

struct cuda_tracee {
	int pid;
	const char *proc_name;
	int uds_fd;

	enum cuda_tracee_state state;

	int log_fd;
	char *log_path;

	int dump_fd;
	char *dump_path;

	struct tracee_state *tracee;
	struct inj_run_ctx *ctx;
};

int cuda_trace_setup(int workdir_fd);
void cuda_trace_teardown(void);
int cuda_trace_prepare(int workdir_fd, long sess_timeout_ms);
int cuda_trace_activate(long sess_start_ts, long sess_end_ts);
void cuda_trace_deactivate(void);

#endif /* __CUDA_H_ */
