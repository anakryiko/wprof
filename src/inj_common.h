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

enum inj_exit_hint {
	HINT_UNSET = 0,
	HINT_CUPTI_BUSY = 1,
	HINT_ERROR,
};

enum inj_setup_state {
	INJ_SETUP_PENDING = 0,
	INJ_SETUP_READY = 1,
	INJ_SETUP_FAILED = 2,
};

struct inj_run_ctx {
	bool worker_thread_done;
	bool use_usdts;
	long sess_start_ts;
	long sess_end_ts;

	enum inj_setup_state setup_state;
	enum inj_exit_hint exit_hint;
	char exit_hint_msg[1024];

	long cupti_rec_cnt;		/* captured records */
	long cupti_drop_cnt;		/* dropped records */
	long cupti_err_cnt;		/* errored records */
	long cupti_ignore_cnt;		/* ignored records */
	long cupti_data_sz;		/* total data size, bytes */
	long cupti_buf_cnt;		/* buffers passed to recording callback */
};

enum inj_msg_kind {
	__INJ_INVALID = 0,
	INJ_MSG_SETUP = 1,
	INJ_MSG_CUDA_SESSION = 2,
	INJ_MSG_SHUTDOWN = 3,
};

static inline const char *inj_msg_str(enum inj_msg_kind kind)
{
	switch (kind) {
	case INJ_MSG_SETUP: return "SETUP";
	case INJ_MSG_CUDA_SESSION: return "CUDA_SESSION";
	case INJ_MSG_SHUTDOWN: return "SHUTDOWN";
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
		struct inj_msg_shutdown {
		} shutdown;
	};
};

#endif /* __INJ_COMMON_H_ */
