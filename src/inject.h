/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __INJECT_H_
#define __INJECT_H_

struct tracee_state;

struct tracee_state *ptrace_inject(int pid);

#endif /* __INJECT_H_ */
