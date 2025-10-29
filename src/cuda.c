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
#include "inject.h"

static void add_tracee(int tracee_pid, struct tracee_state *tracee)
{
	env.tracees = realloc(env.tracees, (env.tracee_cnt + 1) * sizeof(*env.tracees));
	env.tracee_pids = realloc(env.tracee_pids, (env.tracee_cnt + 1) * sizeof(*env.tracee_pids));

	env.tracees[env.tracee_cnt] = tracee;
	env.tracee_pids[env.tracee_cnt] = tracee_pid;

	env.tracee_cnt++;
}

static int discover_pid_cuda_binaries(int pid, int workdir_fd)
{
	struct vma_info *vma;
	bool has_cuda = false, has_cupti = false;
	int err = 0;

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
		return -errno;
	}

	if (!has_cuda && !has_cupti)
		return 0;

	if (has_cuda && !has_cupti) {
		eprintf("PID %d (%s) has CUDA, but no CUPTI, skipping...\n", pid, proc_name(pid));
		return 0;
	}

	if (env.verbose)
		printf("PID %d (%s) has CUPTI!\n", pid, proc_name(pid));

	struct tracee_state *tracee = tracee_inject(pid);
	if (!tracee) {
		err = -errno;
		eprintf("PTRACE injection failed for PID %d (%s): %d\n", pid, proc_name(pid), err);
		return -errno;
	}

	err = tracee_handshake(tracee, workdir_fd);
	if (err) {
		eprintf("Injection handshake failed with PID %d (%s): %d\n", pid, proc_name(pid), err);
		goto err_retract;
	}

	add_tracee(pid, tracee);
	return 0;

err_retract:
	int rerr = tracee_retract(tracee);
	if (rerr) {
		eprintf("PTRACE retraction failed for PID %d (%s): %d\n", pid, proc_name(pid), rerr);
		return err;
	}
	tracee_free(tracee);
	return err;
}

int setup_cuda_tracking_discovery(int workdir_fd)
{
	int err = 0;

	if (env.cuda_global_discovery) {
		int *pidp, pid;

		wprof_for_each(proc, pidp) {
			pid = *pidp;
			err = discover_pid_cuda_binaries(pid, workdir_fd);
			if (err) {
				eprintf("Failed to check if PID %d uses CUDA+CUPTI: %d (skipping...)\n", pid, err);
				continue;
			}
		}

		/* no point in doing per-PID discovery, we just found all applicable processes */
		return 0;
	}

	for (int i = 0; i < env.req_pid_cnt; i++) {
		int pid = env.req_pids[i];

		err = discover_pid_cuda_binaries(pid, workdir_fd);
		if (err) {
			eprintf("Failed to check if PID %d uses CUDA+CUPTI: %d (skipping...)\n", pid, err);
			continue;
		}
	}

	return 0;
}

void teardown_cuda_tracking(void)
{
	for (int i = 0; i < env.tracee_cnt; i++) {
		struct tracee_state *tracee = env.tracees[i];

		int err = 0; //tracee_retract(tracee);
		if (err) {
			eprintf("Ptrace retraction for PID %d (%s) returned error: %d\n",
				env.tracee_pids[i], proc_name(env.tracee_pids[i]), err);
		}
		tracee_free(tracee);
	}
	free(env.tracees);
	free(env.tracee_pids);
	env.tracees = NULL;
}

