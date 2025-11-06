/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __INJ_COMMON_H_
#define __INJ_COMMON_H_

#include "wprof_types.h"
#include "cuda_data.h"

#ifndef MAX_UDS_FD_CNT
#define MAX_UDS_FD_CNT 16
#endif

#define LIBWPROFINJ_SETUP_SYM __libwprof_inj_setup
#define LIBWPROFINJ_VERSION 1

struct inj_setup_ctx {
	/* Should be set to LIBWPROFINJ_VERSION */
	int version;
	/* The size of data+exec mmap injected for injection trampolining */
	int mmap_sz;
	/* handle returned by dlopen() for libwprofinj.so library */
	long lib_handle;
	/* PID of the original wprof injecting this libwprofinj.so */
	int parent_pid;
	/* Real (non-namespaces) PID of tracee process */
	int tracee_pid;

	int stderr_verbosity;
	int filelog_verbosity;

	int uds_fd;
	int uds_parent_fd;
};

struct inj_run_ctx {
	long cupti_dlhandle;
	bool cupti_ready;
	long sess_start_ts;
	long sess_end_ts;
};

enum inj_msg_kind {
	__INJ_INVALID = 0,
	INJ_MSG_SETUP = 1,
	INJ_MSG_CUDA_SESSION = 2,
};

static inline const char *inj_msg_str(enum inj_msg_kind kind)
{
	switch (kind) {
	case INJ_MSG_SETUP: return "SETUP";
	case INJ_MSG_CUDA_SESSION: return "CUDA_SESSION";
	default: return "???";
	}
}

struct inj_msg {
	enum inj_msg_kind kind;

	union {
		struct inj_msg_setup {
		} setup;
		struct inj_msg_cuda_session {
			long session_timeout_ms;
		} cuda_session;
	};
};

#endif /* __INJ_COMMON_H_ */
