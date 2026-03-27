/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __PYDISC_H_
#define __PYDISC_H_

#include <linux/limits.h>

struct py_binary_info {
	char host_path[PATH_MAX];
	unsigned long base_addr;
	int py_major;
	int py_minor;
};

int py_find_binary(int pid, struct py_binary_info *bi);
int pydisc_py_minor(int pid);

struct wprof_bpf;
int pydisc_discover(struct wprof_bpf *skel);

#endif /* __PYDISC_H_ */
