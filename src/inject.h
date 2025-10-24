/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __INJECT_H_
#define __INJECT_H_

struct tracee_state {
	int pid;
	int pid_fd;
	char *proc_name;
};

int ptrace_inject(int pid, struct tracee_state *tracee);

#endif /* __INJECT_H_ */
