/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __INJECT_H_
#define __INJECT_H_

#include "inj_common.h"
struct tracee_info {
	int pid;
	int ns_pid;
	const char *name;
	int uds_fd;
	int lib_fd;
	struct inj_run_ctx *run_ctx;
};

struct tracee_state;

struct tracee_state *tracee_inject(int pid);
int tracee_handshake(struct tracee_state *tracee, int log_fd, bool use_usdts);
int tracee_retract(struct tracee_state *tracee);
void tracee_free(struct tracee_state *tracee);

const struct tracee_info *tracee_info(const struct tracee_state *tracee);

/* GNU build-id (lowercase hex) of the embedded libwprofinj.so, or "unknown". Cached. */
const char *wprof_injectee_build_id(void);

#endif /* __INJECT_H_ */
