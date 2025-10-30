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

#define LIBWPROFINJ_LOG_PATH_FMT "wprofinj-log.%d.%d.log"
#define LIBWPROFINJ_DUMP_PATH_FMT "wprofinj-cuda.%d.%d.data"

struct inj_setup_ctx {
	/* Should be set to LIBWPROFINJ_VERSION */
	int version;
	/* The size of data+exec mmap injected for injection trampolining */
	int mmap_sz;
	/* handle returned by dlopen() for libwprofinj.so library */
	long lib_handle;
	/* PID of the original wprof injecting this libwprofinj.so */
	int parent_pid;

	int stderr_verbosity;
	int filelog_verbosity;

	int uds_fd;
	int uds_parent_fd;
};

struct inj_run_ctx {
	char dummy;
};

enum inj_msg_kind {
	__INJ_INVALID = 0,
	INJ_MSG_SETUP = 1,
	INJ_MSG_CUDA_SESSION = 2,
};

struct inj_msg {
	enum inj_msg_kind kind;

	union {
		struct inj_msg_setup {
			int fd_cnt;
		} setup;
		struct inj_msg_cuda_session {
			long long session_start_ns;
			long long session_end_ns;
		} cuda_session;
	};
};

#endif /* __INJ_COMMON_H_ */
