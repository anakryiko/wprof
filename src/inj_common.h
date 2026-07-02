/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __INJ_COMMON_H_
#define __INJ_COMMON_H_

#include <stdio.h>

#include "wprof_types.h"
#include "cuda_data.h"
#include "pytrace_data.h"

#ifndef MAX_UDS_FD_CNT
#define MAX_UDS_FD_CNT 16
#endif

#define PYTRACE_SYM_CNT 15		/* must match ARRAY_SIZE(pytrace_resolve_syms) in inj_pytrace.c */

__attribute__((unused))
static const char *pytrace_sym_names[PYTRACE_SYM_CNT] = {
	"PyEval_SetProfile",
	"PyGILState_Ensure",
	"PyGILState_Release",
	"PyFrame_GetCode",
	"PyFrame_GetLineNumber",
	"PyUnicode_AsUTF8",
	"PyInterpreterState_Head",
	"PyInterpreterState_ThreadHead",
	"PyThreadState_Next",
	"PyThreadState_Swap",
	"Py_DecRef",
	"Py_IsInitialized",
	"PyObject_GetAttrString",
	"PyLong_AsLong",
	/* optional: 3.12+ only */
	"PyEval_SetProfileAllThreads",
};

#define PYTORCH_SYM_CNT 3		/* must match ARRAY_SIZE(torch_resolve_syms) in inj_torch_profiler.c */

__attribute__((unused))
static const char *pytorch_sym_names[PYTORCH_SYM_CNT] = {
	"_ZN2at17addGlobalCallbackENS_22RecordFunctionCallbackE",	/* at::addGlobalCallback */
	"_ZN2at14removeCallbackEm",					/* at::removeCallback */
	"_ZNK2at14RecordFunction4nameEv",				/* at::RecordFunction::name */
};

#define LIBWPROFINJ_SETUP_SYM __libwprof_inj_setup
#define LIBWPROFINJ_VERSION 2

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

enum inj_setup_state {
	INJ_SETUP_PENDING = 0,
	INJ_SETUP_READY = 1,
	INJ_SETUP_FAILED = 2,
};

/* Per-feature setup outcome, reported independently in inj_run_ctx. */
enum inj_feat_state {
	FEAT_NONE = 0,		/* feature not requested for this tracee */
	FEAT_PENDING,		/* setup message sent, not yet processed */
	FEAT_READY,		/* set up and capturing */
	FEAT_FAILED,		/* setup failed */
	FEAT_IGNORED,		/* e.g. CUDA: CUPTI busy / no GPU usage */
};

/* Bitmask of features multiplexed onto a single injection. */
enum inj_feature {
	INJ_FEAT_CUDA = 1,
	INJ_FEAT_PYTRACE = 2,
	INJ_FEAT_PYTORCH = 4,
};

struct inj_run_ctx {
	bool worker_thread_done;
	bool use_usdts;
	long sess_start_ts;
	long sess_end_ts;
	u64 fr_chunk_size;	/* flight recorder: rotate data chunks every N bytes (0 = off) */

	enum inj_setup_state setup_state;	/* overall; set by START_SESSION */
	enum inj_feat_state cuda_feat_state;	/* set by CUDA_SETUP */
	enum inj_feat_state pytrace_feat_state;	/* set by PYTRACE_SETUP */
	enum inj_feat_state pytorch_feat_state;	/* set by PYTORCH_SETUP */
	/* human-readable reason a feature failed or was ignored (set by its *_SETUP) */
	char cuda_feat_hint[512];
	char pytrace_feat_hint[512];
	char pytorch_feat_hint[512];

	long cupti_rec_cnt;		/* captured records */
	long cupti_drop_cnt;		/* dropped records */
	long cupti_err_cnt;		/* errored records */
	long cupti_ignore_cnt;		/* ignored records */
	long cupti_data_sz;		/* total data size, bytes */
	long cupti_buf_cnt;		/* buffers passed to recording callback */

	/* pytrace stats */
	long pytrace_event_cnt;		/* captured events */
	long pytrace_code_cache_cnt;	/* unique code objects cached */

	/* pytorch (RecordFunction) stats */
	long pytorch_event_cnt;		/* captured events */
};

/*
 * Per-feature setup messages (CUDA/PYTRACE/PYTORCH_SETUP) configure one feature
 * each and carry that feature's dump fd as ancillary data; START_SESSION then
 * arms the session timer and flips the overall setup_state to READY. They are
 * pipelined over one UDS, so the socket is SOCK_SEQPACKET to preserve message
 * boundaries (one recvmsg == one inj_msg).
 */
enum inj_msg_kind {
	__INJ_INVALID = 0,
	INJ_MSG_SETUP = 1,
	INJ_MSG_CUDA_SETUP = 2,
	INJ_MSG_PYTRACE_SETUP = 3,
	INJ_MSG_PYTORCH_SETUP = 4,
	INJ_MSG_START_SESSION = 5,
	INJ_MSG_SHUTDOWN = 6,
	INJ_MSG_CHUNK_DONE = 7,		/* injectee -> wprof: a rotated data chunk is complete */
	INJ_MSG_CHUNK_FD = 8,		/* wprof -> injectee: a fresh data chunk fd (spare) */
};

static inline const char *inj_msg_str(enum inj_msg_kind kind)
{
	switch (kind) {
	case INJ_MSG_SETUP: return "SETUP";
	case INJ_MSG_CUDA_SETUP: return "CUDA_SETUP";
	case INJ_MSG_PYTRACE_SETUP: return "PYTRACE_SETUP";
	case INJ_MSG_PYTORCH_SETUP: return "PYTORCH_SETUP";
	case INJ_MSG_START_SESSION: return "START_SESSION";
	case INJ_MSG_SHUTDOWN: return "SHUTDOWN";
	case INJ_MSG_CHUNK_DONE: return "CHUNK_DONE";
	case INJ_MSG_CHUNK_FD: return "CHUNK_FD";
	default: {
		static __thread char buf[24];
		snprintf(buf, sizeof(buf), "UNKNOWN(%d)", kind);
		return buf;
	}
	}
}

struct inj_msg {
	enum inj_msg_kind kind;

	union {
		struct inj_msg_setup {
		} setup;
		struct inj_msg_cuda_setup {
			/* cuda dump fd passed as ancillary data */
		} cuda_setup;
		struct inj_msg_pytrace_setup {
			int py_version_minor; /* Python 3.x minor version */
			unsigned long sym_addrs[PYTRACE_SYM_CNT];
			/* pytrace dump fd passed as ancillary data */
		} pytrace_setup;
		struct inj_msg_pytorch_setup {
			unsigned long pytorch_sym_addrs[PYTORCH_SYM_CNT];
			/* pytorch dump fd passed as ancillary data */
		} pytorch_setup;
		struct inj_msg_start_session {
			long session_timeout_ms;
		} start_session;
		struct inj_msg_shutdown {
		} shutdown;
		struct inj_msg_chunk_done {
			enum inj_feature feature;	/* which feature's data chunk completed */
			u64 end_ts;			/* max event ts in the chunk */
			u64 byte_sz;			/* bytes written to the chunk */
			u64 event_cnt;			/* events written to the chunk */
		} chunk_done;
		struct inj_msg_chunk_fd {
			enum inj_feature feature;	/* feature the new chunk fd (ancillary data) is for */
		} chunk_fd;
	};
};

#endif /* __INJ_COMMON_H_ */
