/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __INJ_COMMON_H_
#define __INJ_COMMON_H_

#ifndef MAX_UDS_FD_CNT
#define MAX_UDS_FD_CNT 16
#endif

#define LIBWPROFINJ_SETUP_SYM __libwprof_inj_setup
#define LIBWPROFINJ_VERSION 1

struct inj_setup_ctx {
	int version; /* should be set to LIBWPROFINJ_VERSION */
	int mmap_sz;
	int uds_fd;
	int uds_parent_fd;
	int lib_mem_fd;
};

struct inj_run_ctx {
	int parent_pid;
};

#endif /* __INJ_COMMON_H_ */
