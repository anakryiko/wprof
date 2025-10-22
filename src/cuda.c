// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <linux/fs.h>

#include "cuda.h"
#include "proc.h"
#include "env.h"

static int discover_pid_cuda_binaries(int pid)
{
	struct vma_info *vma;
	int err = 0;
	bool has_cuda = false, has_cupti = false;

	wprof_for_each(vma, vma, pid,
		       PROCMAP_QUERY_VMA_EXECUTABLE | PROCMAP_QUERY_FILE_BACKED_VMA) {
		if (vma->vma_name[0] != '/')
			continue; /* special file, ignore */

		if (strstr(vma->vma_name, "/libcuda.so"))
			has_cuda = true;
		else if (strstr(vma->vma_name, "/libcupti.so"))
			has_cupti = true;

		errno = 0;
		if (has_cuda && has_cupti)
			break;
	}
	if (errno && (errno != ENOENT && errno != ESRCH)) {
		err = -errno;
		eprintf("VMA iteration failed for PID %d: %d\n", pid, err);
		return err;
	}

	if (!has_cuda && !has_cupti)
		return 0;

	if (has_cuda && !has_cupti) {
		eprintf("PID %d (%s) has CUDA, but no CUPTI, skipping...\n", pid, proc_name(pid));
		return 0;
	}

	if (env.verbose)
		printf("PID %d (%s) has CUPTI!\n", pid, proc_name(pid));

	return 0;
}

int setup_cuda_tracking_discovery(void)
{
	int err = 0;

	if (env.cuda_global_discovery) {
		int *pidp, pid;

		wprof_for_each(proc, pidp) {
			pid = *pidp;
			err = discover_pid_cuda_binaries(pid);
			if (err) {
				eprintf("Failed to check if PID %d uses CUDA+CUPTI: %d (skipping...)\n", pid, err);
				continue;
			}
		}
	}

	for (int i = 0; i < env.req_pid_cnt; i++) {
		int pid = env.req_pids[i];

		err = discover_pid_cuda_binaries(pid);
		if (err) {
			eprintf("Failed to check if PID %d uses CUDA+CUPTI: %d (skipping...)\n", pid, err);
			continue;
		}
	}

	return 0;
}
