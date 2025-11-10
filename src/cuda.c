// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <linux/fs.h>
#include <fcntl.h>

#include "cuda.h"
#include "proc.h"
#include "env.h"
#include "sys.h"
#include "inj_common.h"
#include "inject.h"

#define LIBWPROFINJ_LOG_PATH_FMT "wprofinj-log.%d.%d.log"
#define LIBWPROFINJ_DUMP_PATH_FMT "wprofinj-cuda.%d.%d.data"

#define LIBWPROFINJ_SETUP_TIMEOUT_MS 5000
#define LIBWPROFINJ_TEARDOWN_TIMEOUT_MS 5000

static struct cuda_tracee *add_cuda_tracee(struct tracee_state *tracee)
{
	const struct tracee_info *info = tracee_info(tracee);
	struct cuda_tracee *cuda;

	env.cudas = realloc(env.cudas, (env.cuda_cnt + 1) * sizeof(*env.cudas));

	cuda = &env.cudas[env.cuda_cnt];
	memset(cuda, 0, sizeof(*cuda));

	cuda->pid = info->pid;
	cuda->proc_name = info->name;
	cuda->uds_fd = info->uds_fd;
	cuda->tracee = tracee;
	cuda->ctx = info->run_ctx;

	cuda->log_fd = -1;
	cuda->dump_fd = -1;

	env.cuda_cnt++;

	return cuda;
}

static int discover_pid_cuda_binaries(int pid, int workdir_fd, bool force)
{
	char log_path[128];
	struct vma_info *vma;
	bool has_cuda = false, has_cupti = false;
	int err = 0, log_fd = -1;

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

	if (!has_cuda && !has_cupti) {
		if (force) {
			vprintf("PID %d (%s) has no CUDA or CUPTI, but continuing nevertheless...\n", pid, proc_name(pid));
			goto force_continue;
		}
		return 0;
	}

	if (has_cuda && !has_cupti) {
		if (force) {
			vprintf("PID %d (%s) has CUDA, but no CUPTI, but continuing nevertheless...\n", pid, proc_name(pid));
			goto force_continue;
		} else {
			eprintf("PID %d (%s) has CUDA, but no CUPTI, skipping...\n", pid, proc_name(pid));
		}
		return 0;
	}

	if (env.verbose)
		printf("PID %d (%s) has CUPTI!\n", pid, proc_name(pid));

force_continue:
	snprintf(log_path, sizeof(log_path), LIBWPROFINJ_LOG_PATH_FMT, getpid(), pid);

	log_fd = openat(workdir_fd, log_path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
	if (log_fd < 0) {
		err = -errno;
		eprintf("Failed to create CUDA tracee %d (%s) log file at '%s': %d\n",
			pid, proc_name(pid), log_path, err);
		return -errno;
	}

	struct tracee_state *tracee = tracee_inject(pid);
	if (!tracee) {
		err = -errno;
		close(log_fd);
		eprintf("PTRACE injection failed for PID %d (%s): %d\n", pid, proc_name(pid), err);
		return -errno;
	}

	err = tracee_handshake(tracee, log_fd);
	if (err) {
		eprintf("Injection handshake failed with PID %d (%s): %d\n", pid, proc_name(pid), err);
		goto err_retract;
	}

	struct cuda_tracee *cuda = add_cuda_tracee(tracee);

	cuda->log_fd = log_fd;
	cuda->log_path = strdup(log_path);
	cuda->state = TRACEE_INJECTED;

	return 0;

err_retract:
	close(log_fd);
	int rerr = tracee_retract(tracee);
	if (rerr) {
		eprintf("PTRACE retraction failed for PID %d (%s): %d\n", pid, proc_name(pid), rerr);
		return err;
	}
	tracee_free(tracee);
	return err;
}

int cuda_trace_setup(int workdir_fd)
{
	int err = 0;

	if (env.cuda_global_discovery) {
		int *pidp, pid;

		wprof_for_each(proc, pidp) {
			pid = *pidp;
			err = discover_pid_cuda_binaries(pid, workdir_fd, false);
			if (err) {
				eprintf("Failed to check if PID %d uses CUDA+CUPTI: %d (skipping...)\n", pid, err);
				continue;
			}
		}

		/* no point in doing per-PID discovery, we just found all applicable processes */
		return 0;
	}

	for (int i = 0; i < env.cuda_pid_cnt; i++) {
		int pid = env.cuda_pids[i];

		err = discover_pid_cuda_binaries(pid, workdir_fd, true);
		if (err) {
			eprintf("Failed to check if PID %d uses CUDA+CUPTI: %d (skipping...)\n", pid, err);
			continue;
		}
	}

	return 0;
}

int cuda_trace_prepare(int workdir_fd, long sess_timeout_ms)
{
	for (int i = 0; i < env.cuda_cnt; i++) {
		struct cuda_tracee *cuda = &env.cudas[i];

		char dump_path[128];
		snprintf(dump_path, sizeof(dump_path), LIBWPROFINJ_DUMP_PATH_FMT, getpid(), cuda->pid);

		int dump_fd = openat(workdir_fd, dump_path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
		if (dump_fd < 0) {
			int err = -errno;
			eprintf("Failed to create CUDA tracee %d (%s) dump file at '%s': %d\n",
				cuda->pid, cuda->proc_name, dump_path, err);
			return -errno;
		}

		struct inj_msg msg = {
			.kind = INJ_MSG_CUDA_SESSION,
			.cuda_session = {
				.session_timeout_ms = sess_timeout_ms,
			},
		};
		int err = uds_send_data(cuda->uds_fd, &msg, sizeof(msg), &dump_fd, 1);
		if (err < 0) {
			eprintf("Failed to start CUDA trace session for tracee (%d, %s): %d\n",
				cuda->pid, cuda->proc_name, err);
			close(dump_fd);
			cuda->state = TRACEE_SETUP_FAILED;
			continue;
		}

		cuda->dump_fd = dump_fd;
		cuda->dump_path = strdup(dump_path);
		cuda->state = TRACEE_PENDING;
	}

	for (int i = 0; i < env.cuda_cnt; i++) {
		struct cuda_tracee *cuda = &env.cudas[i];

		vprintf("Tracee #%d (PID %d, %s, %s): LOG %s DUMP %s\n",
			i, cuda->pid, cuda->proc_name,
			cuda_tracee_state_str(cuda->state),
			cuda->log_path, cuda->dump_path);
	}

	vprintf("Waiting for CUDA tracees to be ready...\n");
	u64 start_ts = ktime_now_ns();
	for (int i = 0; i < env.cuda_cnt; i++) {
		struct cuda_tracee *cuda = &env.cudas[i];

		if (cuda->state != TRACEE_PENDING)
			continue;

		while (!cuda->ctx->cupti_ready &&
		       (ktime_now_ns() - start_ts < LIBWPROFINJ_SETUP_TIMEOUT_MS * 1000000ULL)) {
			usleep(10000);
		}

		if (!cuda->ctx->cupti_ready) {
			vprintf("Tracee #%d (PID %d, %s) TIMED OUT! Ignoring it...\n",
				i, cuda->pid, cuda->proc_name);
			cuda->state = TRACEE_SETUP_TIMEOUT;
		} else {
			vprintf("Tracee #%d (PID %d NAME %s) is READY!\n", i, cuda->pid, cuda->proc_name);
			cuda->state = TRACEE_ACTIVE;
		}
	}

	return 0;
}

int cuda_trace_activate(long sess_start_ts, long sess_end_ts)
{
	for (int i = 0; i < env.cuda_cnt; i++) {
		struct cuda_tracee *cuda = &env.cudas[i];

		if (cuda->state != TRACEE_ACTIVE)
			continue;

		cuda->ctx->sess_end_ts = sess_end_ts;
		cuda->ctx->sess_start_ts = sess_start_ts;
	}

	return 0;
}

static void dump_tracee_log(struct cuda_tracee *cuda)
{
	vprintf("Tracee PID %d (%s) LOG (%s) DUMP (LAST STATE %s):\n"
		"=======================================================================================================\n",
		cuda->pid, cuda->proc_name, cuda->log_path, cuda_tracee_state_str(cuda->state));

	lseek(cuda->log_fd, 0, SEEK_SET); /* just in case */

	FILE *f = fdopen(cuda->log_fd, "r");
	if (!f) {
		int err = -errno;
		eprintf("Failed to create FILE wrapper around tracee log FD: %d\n", err);
		return;
	}

	char buf[4096];
	while (fgets(buf, sizeof(buf), f)) {
		vprintf("    %s", buf);
	}

	vprintf("=======================================================================================================\n");

	fclose(f);
	cuda->log_fd = -1;
}

void cuda_trace_deactivate(void)
{
	if (env.cudas_deactivated)
		return;

	vprintf("Signaling CUDA tracees to shut down...\n");
	for (int i = 0; i < env.cuda_cnt; i++) {
		struct cuda_tracee *cuda = &env.cudas[i];

		vprintf("Signaling tracee #%d PID %d (%s) to exit...\n", i, cuda->pid, cuda->proc_name);

		struct inj_msg msg = {
			.kind = INJ_MSG_SHUTDOWN,
			.shutdown = { },
		};
		int err = uds_send_data(cuda->uds_fd, &msg, sizeof(msg), NULL, 0);

		/* regardless of outcome, close UDS fd */
		zclose(cuda->uds_fd);

		if (err < 0) {
			eprintf("Failed to send SHUTDOWN command cleanly to tracee #%d (PID %d, %s): %d\n",
				i, cuda->pid, cuda->proc_name, err);
			if (cuda->state == TRACEE_ACTIVE)
				cuda->state = TRACEE_SHUTDOWN_FAILED;

			if (env_log_set & LOG_TRACEE)
				dump_tracee_log(cuda);

			continue;
		}
	}

	vprintf("Waiting for CUDA tracees to shut down...\n");
	u64 start_ts = ktime_now_ns();
	for (int i = 0; i < env.cuda_cnt; i++) {
		struct cuda_tracee *cuda = &env.cudas[i];

		if (cuda->state != TRACEE_ACTIVE) {
			vprintf("NOT WAITING for tracee #%d (PID %d, %s, %s) as it was not successfully set up!\n",
				i, cuda->pid, cuda->proc_name, cuda_tracee_state_str(cuda->state));
			continue;
		}

		vprintf("Waiting for tracee #%d (PID %d, %s) to be done...\n", i, cuda->pid, cuda->proc_name);

		while (!cuda->ctx->worker_thread_done &&
		       (ktime_now_ns() - start_ts < LIBWPROFINJ_TEARDOWN_TIMEOUT_MS * 1000000ULL)) {
			usleep(10000);
		}

		if (!cuda->ctx->worker_thread_done) {
			vprintf("Tracee #%d (PID %d, %s) TIMED OUT DURING TEARDOWN! SKIPPING PTRACE RETRACTION!\n",
				i, cuda->pid, cuda->proc_name);
			cuda->state = TRACEE_SHUTDOWN_TIMEOUT;
		} else {
			vprintf("Tracee #%d (PID %d, %s) has shut down cleanly.\n",
				i, cuda->pid, cuda->proc_name);
			cuda->state = TRACEE_INACTIVE;

			int err = tracee_retract(cuda->tracee);
			if (err) {
				eprintf("Injection retraction for tracee #%d (PID %d, %s) FAILED: %d!\n",
					i, cuda->pid, cuda->proc_name, err);
			}
		}

		if (env.log_set & LOG_TRACEE)
			dump_tracee_log(cuda);
	}

	env.cudas_deactivated = true;
}

void cuda_trace_teardown(void)
{
	cuda_trace_deactivate();

	for (int i = 0; i < env.cuda_cnt; i++) {
		struct cuda_tracee *cuda = &env.cudas[i];

		zclose(cuda->uds_fd);
		zclose(cuda->dump_fd);
		zclose(cuda->log_fd);
	}
}
