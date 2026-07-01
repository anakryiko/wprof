/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __INJMGR_H_
#define __INJMGR_H_

#include <stdbool.h>
#include "inj_common.h"		/* enum inj_feature, PYTRACE_SYM_CNT, PYTORCH_SYM_CNT */

#define LIBWPROFINJ_SESSION_TIMEOUT_MS 15000
#define LIBWPROFINJ_SETUP_TIMEOUT_MS 10000
#define LIBWPROFINJ_TEARDOWN_TIMEOUT_MS 10000

struct tracee_state;
struct inj_run_ctx;
struct bpf_state;
struct bpf_program;

/* Injectee lifecycle states, shared across features and persisted as stat values. */
enum injectee_state {
	INJECTEE_UNINIT,
	INJECTEE_INJECTED,
	INJECTEE_PENDING,
	INJECTEE_ACTIVE,
	INJECTEE_INACTIVE,
	INJECTEE_SETUP_TIMEOUT,
	INJECTEE_SETUP_FAILED,
	INJECTEE_IGNORED,
	INJECTEE_SHUTDOWN_TIMEOUT,
	INJECTEE_SHUTDOWN_FAILED,
};

static inline const char *injectee_state_str(enum injectee_state state)
{
	switch (state) {
	case INJECTEE_UNINIT: return "UNINIT";
	case INJECTEE_INJECTED: return "INJECTED";
	case INJECTEE_PENDING: return "PENDING";
	case INJECTEE_ACTIVE: return "ACTIVE";
	case INJECTEE_INACTIVE: return "INACTIVE";
	case INJECTEE_SETUP_TIMEOUT: return "SETUP_TIMEOUT";
	case INJECTEE_SETUP_FAILED: return "SETUP_FAILED";
	case INJECTEE_IGNORED: return "IGNORED";
	case INJECTEE_SHUTDOWN_TIMEOUT: return "SHUTDOWN_TIMEOUT";
	case INJECTEE_SHUTDOWN_FAILED: return "SHUTDOWN_FAILED";
	default: return "???";
	}
}

/*
 * One injectee: a process we inject libwprofinj.so into exactly once, even when
 * several features (CUDA, PyTrace, PyTorch) are captured from it. Each feature
 * multiplexes its own session over the one shared UDS / run_ctx. The low-level
 * ptrace injection state lives behind the opaque struct tracee_state.
 */
struct injectee {
	int pid;
	int ns_pid;
	const char *proc_name;

	struct tracee_state *tracee;
	int uds_fd;
	struct inj_run_ctx *ctx;
	int lib_fd;			/* libwprofinj.so memfd, for USDT attach */
	int log_fd;
	char *log_path;

	enum injectee_state state;
	enum inj_feature detect_feats;	/* detected on the process */
	enum inj_feature avail_feats;	/* reached FEAT_READY */
	bool force_cuda;		/* nvidia-smi/explicit: skip the CUPTI-present check */

	int cuda_events_fd;		/* headerless event dump */
	char *cuda_events_path;
	int cuda_respool_fd;		/* resource pool (header + strs) */
	char *cuda_respool_path;

	int py_version_minor;
	unsigned long py_sym_addrs[PYTRACE_SYM_CNT];
	int pytrace_dump_fd;
	char *pytrace_dump_path;

	unsigned long pytorch_sym_addrs[PYTORCH_SYM_CNT];
	int pytorch_dump_fd;
	char *pytorch_dump_path;
};

const char *inj_proc_str(int pid, int ns_pid, const char *name);
const char *injectee_str(const struct injectee *inj);

int injmgr_setup(int workdir_fd);	/* enumerate, detect, inject once per PID */
int injmgr_prepare(int workdir_fd, long sess_timeout_ms);
int injmgr_activate(long sess_start_ts, long sess_end_ts);
int injmgr_attach_usdts(struct bpf_state *st, struct bpf_program *prog);
void injmgr_deactivate(void);
void injmgr_retract(void);
void injmgr_teardown(void);

/*
 * Per-feature detection (cuda.c / pytrace.c): inspect a candidate PID and report
 * whether the feature applies, resolving any host-side symbols the lib needs.
 * pytrace_detect doubles as the "is Python" gate that pytorch_detect depends on.
 */
bool cuda_detect(int pid, bool force);
bool pytrace_detect(int pid, int *out_py_minor, unsigned long *out_py_sym_addrs);
bool pytorch_detect(int pid, unsigned long *out_pytorch_sym_addrs);

#endif /* __INJMGR_H_ */
