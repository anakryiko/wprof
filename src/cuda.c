// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#include <string.h>
#include <errno.h>

#include "utils.h"
#include "injmgr.h"
#include "proc.h"

bool cuda_detect(int pid, bool force)
{
	struct vma_info *vma;
	bool has_cuda = false, has_cupti = false;

	wprof_for_each(vma, vma, pid, VMA_QUERY_VMA_EXECUTABLE | VMA_QUERY_FILE_BACKED_VMA) {
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
		eprintf("VMA iteration failed for PID %d: %d\n", pid, -errno);
		return false;
	}

	if (!has_cuda && !has_cupti) {
		if (force) {
			vprintf("PID %d (%s) has no CUDA or CUPTI, but continuing nevertheless...\n", pid, proc_name(pid));
			return true;
		}
		return false;
	}

	if (has_cuda && !has_cupti) {
		if (force) {
			vprintf("PID %d (%s) has CUDA, but no CUPTI, but continuing nevertheless...\n", pid, proc_name(pid));
			return true;
		}
		vprintf("PID %d (%s) has CUDA, but no CUPTI, skipping...\n", pid, proc_name(pid));
		return false;
	}

	vprintf("%s has CUPTI.\n", inj_proc_str(pid, ns_tid_by_host_tid(pid, pid), proc_name(pid)));
	return true;
}
