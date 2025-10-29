/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __INJECT_H_
#define __INJECT_H_

struct tracee_info {
	int pid;
	const char *name;
	int uds_fd;
};

struct tracee_state;

struct tracee_state *tracee_inject(int pid);
int tracee_handshake(struct tracee_state *tracee, int workdir_fd);
int tracee_retract(struct tracee_state *tracee);
void tracee_free(struct tracee_state *tracee);

const struct tracee_info *tracee_info(const struct tracee_state *tracee);

#endif /* __INJECT_H_ */
