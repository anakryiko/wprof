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

static const char *proc_str(int pid, int ns_pid, const char *proc_name)
{
	static char buf[128];

	if (pid == ns_pid)
		snprintf(buf, sizeof(buf), "%d, %s", pid, proc_name);
	else
		snprintf(buf, sizeof(buf), "%d=%d, %s", pid, ns_pid, proc_name);

	return buf;
}

const char *cuda_str(const struct cuda_tracee *t)
{
	return proc_str(t->pid, t->ns_pid, t->proc_name);
}

static struct cuda_tracee *add_cuda_tracee(struct tracee_state *tracee)
{
	const struct tracee_info *info = tracee_info(tracee);
	struct cuda_tracee *cuda;

	env.cudas = realloc(env.cudas, (env.cuda_cnt + 1) * sizeof(*env.cudas));

	cuda = &env.cudas[env.cuda_cnt];
	memset(cuda, 0, sizeof(*cuda));

	cuda->pid = info->pid;
	cuda->ns_pid = info->ns_pid;
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
			vprintf("PID %d (%s) has CUDA, but no CUPTI, skipping...\n", pid, proc_name(pid));
		}
		return 0;
	}

	dprintf(2, "Process %s has CUPTI!\n",
		proc_str(pid, ns_tid_by_host_tid(pid, pid), proc_name(pid)));

force_continue:
	snprintf(log_path, sizeof(log_path), LIBWPROFINJ_LOG_PATH_FMT, getpid(), pid);
	log_fd = openat(workdir_fd, log_path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
	if (log_fd < 0) {
		err = -errno;
		eprintf("Failed to create CUDA tracee %s log file at '%s': %d\n",
			proc_str(pid, ns_tid_by_host_tid(pid, pid), proc_name(pid)),
			log_path, err);
		return -errno;
	}

	struct tracee_state *tracee = tracee_inject(pid);
	if (!tracee) {
		err = -errno;
		close(log_fd);
		eprintf("PTRACE injection failed for %s: %d\n",
			proc_str(pid, ns_tid_by_host_tid(pid, pid), proc_name(pid)), err);
		return -errno;
	}

	err = tracee_handshake(tracee, log_fd);
	if (err) {
		eprintf("Injection handshake with %s failed: %d\n",
			proc_str(pid, ns_tid_by_host_tid(pid, pid), proc_name(pid)), err);
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
		eprintf("PTRACE retraction failed for %s: %d\n",
			proc_str(pid, ns_tid_by_host_tid(pid, pid), proc_name(pid)), rerr);
		return err;
	}

	tracee_free(tracee);
	return err;
}

int cuda_trace_setup(int workdir_fd)
{
	int err = 0;

retry:
	switch (env.cuda_discovery) {
	case CUDA_DISCOVER_PROC: {
		int *pidp, pid;

		wprof_for_each(proc, pidp) {
			pid = *pidp;
			err = discover_pid_cuda_binaries(pid, workdir_fd, false);
			if (err) {
				eprintf("Failed to check if PID %d (%s) uses CUDA+CUPTI: %d (skipping...)\n",
					pid, proc_name(pid), err);
				continue;
			}
		}
		break;
	}
	case CUDA_DISCOVER_SMI: {
		vprintf("Using nvidia-smi to find processes using CUDA...\n");

		FILE *f = popen("nvidia-smi --query-compute-apps=pid --format=csv,noheader", "r");
		if (!f) {
			eprintf("Failed to query nvidia-smi, falling back to process discovery logic...\n");
			env.cuda_discovery = CUDA_DISCOVER_PROC;
			goto retry;
		}

		char pidbuf[32];
		int pid;
		while (fgets(pidbuf, sizeof(pidbuf), f)) {
			if (sscanf(pidbuf, "%d", &pid) != 1) {
				eprintf("nvidia-smi returned invalid PID '%s', skipping...\n", pidbuf);
				continue;
			}
			vprintf("nvidia-smi returned PID %d (%s)\n", pid, proc_name(pid));

			bool found = false;
			for (int j = 0; j < env.cuda_cnt; j++) {
				if (env.cudas[j].pid == pid) {
					found = true;
					break;
				}
			}
			if (found)
				continue;

			err = discover_pid_cuda_binaries(pid, workdir_fd, true);
			if (err) {
				eprintf("Failed to check if PID %d (%s) uses CUDA+CUPTI: %d (skipping...)\n",
					pid, proc_name(pid), err);
				continue;
			}
		}

		pclose(f);
		break;
	}
	case CUDA_DISCOVER_NONE: {
		break;
	}
	default:
		eprintf("Unrecognized CUDA discovery strategy %d!\n", env.cuda_discovery);
		return -EOPNOTSUPP;
	}

	for (int i = 0; i < env.cuda_pid_cnt; i++) {
		int pid = env.cuda_pids[i];
		bool found = false;

		for (int j = 0; j < env.cuda_cnt; j++) {
			if (env.cudas[j].pid == pid) {
				found = true;
				break;
			}
		}

		if (found)
			continue;

		err = discover_pid_cuda_binaries(pid, workdir_fd, true);
		if (err) {
			eprintf("Failed to check if PID %d (%s) uses CUDA+CUPTI: %d (skipping...)\n",
				pid, proc_name(pid), err);
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
			eprintf("Failed to create CUDA tracee %s dump file at '%s': %d\n",
				cuda_str(cuda), dump_path, err);
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
			eprintf("Failed to start CUDA trace session for tracee %s: %d\n",
				cuda_str(cuda), err);
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

		dprintf(1 ,"Tracee #%d (%s, %s): LOG %s DUMP %s\n",
			i, cuda_str(cuda),
			cuda_tracee_state_str(cuda->state),
			cuda->log_path, cuda->dump_path);
	}

	vprintf("Waiting for CUDA tracees to be ready...\n");
	u64 start_ts = ktime_now_ns();
	for (int i = 0; i < env.cuda_cnt; i++) {
		struct cuda_tracee *cuda = &env.cudas[i];

		if (cuda->state != TRACEE_PENDING)
			continue;

		while (*(volatile enum inj_setup_state *)&cuda->ctx->setup_state == INJ_SETUP_PENDING &&
		       (ktime_now_ns() - start_ts < LIBWPROFINJ_SETUP_TIMEOUT_MS * 1000000ULL)) {
			usleep(10000);
		}

		switch (cuda->ctx->setup_state) {
		case INJ_SETUP_READY:
			vprintf("Tracee #%d (%s) is READY!\n",
				i, cuda_str(cuda));
			cuda->state = TRACEE_ACTIVE;
			break;
		case INJ_SETUP_FAILED:
		default:
			if (cuda->ctx->exit_hint == HINT_CUPTI_BUSY) {
				dprintf(1, "Tracee #%d (%s) will be IGNORED: NO CUDA USAGE (or, unlikely, CUPTI is used by another profiler).\n",
					i, cuda_str(cuda));
				cuda->state = TRACEE_IGNORED;
			} else if (cuda->ctx->exit_hint) {
				vprintf("Tracee #%d (%s) failed initial setup with message: '%s'.\n",
					i, cuda_str(cuda), cuda->ctx->exit_hint_msg);
				cuda->state = TRACEE_SETUP_FAILED;
			} else  {
				vprintf("Tracee #%d (%s) TIMED OUT! Ignoring it...\n",
					i, cuda_str(cuda));
				cuda->state = TRACEE_SETUP_TIMEOUT;
			}
			break;
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

static void dump_tracee_log(struct cuda_tracee *cuda, int idx)
{
	if (!(env_log_set & LOG_TRACEE))
		return;

	vprintf("Tracee #%d (%s) LOG (%s) DUMP (LAST STATE %s):\n"
		"=======================================================================================================\n",
		idx, cuda_str(cuda), cuda->log_path, cuda_tracee_state_str(cuda->state));

	lseek(cuda->log_fd, 0, SEEK_SET); /* just in case */

	FILE *f = fdopen(cuda->log_fd, "r");
	if (!f) {
		int err = -errno;
		eprintf("Failed to create FILE wrapper around tracee #%d (%s) log FD: %d\n",
			idx, cuda_str(cuda), err);
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

		if (cuda->state == TRACEE_IGNORED) {
			zclose(cuda->uds_fd);
			if (env.debug_level)
				dump_tracee_log(cuda, i);
			continue;
		}

		if (cuda->state == TRACEE_SETUP_FAILED || cuda->state == TRACEE_SETUP_TIMEOUT) {
			zclose(cuda->uds_fd);
			dump_tracee_log(cuda, i);
			continue;
		}

		vprintf("Signaling tracee #%d (%s) to exit...\n", i, cuda_str(cuda));

		struct inj_msg msg = {
			.kind = INJ_MSG_SHUTDOWN,
			.shutdown = { },
		};
		int err = uds_send_data(cuda->uds_fd, &msg, sizeof(msg), NULL, 0);

		/* regardless of outcome, close UDS fd */
		zclose(cuda->uds_fd);

		if (err < 0) {
			eprintf("Failed to send SHUTDOWN command cleanly to tracee #%d (%s): %d\n",
				i, cuda_str(cuda), err);
			if (cuda->state == TRACEE_ACTIVE)
				cuda->state = TRACEE_SHUTDOWN_FAILED;

			dump_tracee_log(cuda, i);
			continue;
		}
	}

	vprintf("Waiting for CUDA tracees to shut down...\n");
	u64 start_ts = ktime_now_ns();
	for (int i = 0; i < env.cuda_cnt; i++) {
		struct cuda_tracee *cuda = &env.cudas[i];

		if (cuda->state != TRACEE_ACTIVE &&
		    cuda->state != TRACEE_IGNORED &&
		    cuda->state != TRACEE_SETUP_FAILED) {
			vprintf("NOT WAITING for tracee #%d (%s, %s) as it was not successfully set up!\n",
				i, cuda_str(cuda), cuda_tracee_state_str(cuda->state));
			continue;
		}

		dprintf(1, "Waiting for tracee #%d (%s) to be done...\n", i, cuda_str(cuda));

		while (!cuda->ctx->worker_thread_done &&
		       (ktime_now_ns() - start_ts < LIBWPROFINJ_TEARDOWN_TIMEOUT_MS * 1000000ULL)) {
			usleep(10000);
		}

		if (!cuda->ctx->worker_thread_done) {
			eprintf("Tracee #%d (%s) TIMED OUT DURING TEARDOWN! SKIPPING PTRACE RETRACTION!\n",
				i, cuda_str(cuda));
			cuda->state = TRACEE_SHUTDOWN_TIMEOUT;
		} else {
			if (cuda->state == TRACEE_IGNORED) {
				dprintf(1, "Tracee #%d (%s) has shut down cleanly.\n",
					i, cuda_str(cuda));
			} else {
				vprintf("Tracee #%d (%s) has shut down cleanly.\n",
					i, cuda_str(cuda));
			}

			if (cuda->state != TRACEE_IGNORED && cuda->state != TRACEE_SETUP_FAILED)
				cuda->state = TRACEE_INACTIVE;

			int err = tracee_retract(cuda->tracee);
			if (err) {
				eprintf("Injection retraction for tracee #%d (%s) FAILED: %d!\n",
					i, cuda_str(cuda), err);
			}
		}

		if (cuda->state != TRACEE_IGNORED) /* we already emitted those logs */
			dump_tracee_log(cuda, i);
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
