// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Meta Platforms, Inc. */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "pytrace.h"
#include "cuda.h"
#include "proc.h"
#include "env.h"
#include "sys.h"
#include "inj_common.h"
#include "inject.h"
#include "elf_utils.h"

#define LIBWPROFINJ_PYTRACE_LOG_PATH_FMT "wprofinj-pytrace-log.%d.%d.log"
#define LIBWPROFINJ_PYTRACE_DUMP_PATH_FMT "wprofinj-pytrace.%d.%d.data"

static const char *pytrace_proc_str(int pid, int ns_pid, const char *proc_name)
{
	static char buf[128];

	if (pid == ns_pid)
		snprintf(buf, sizeof(buf), "%d, %s", pid, proc_name);
	else
		snprintf(buf, sizeof(buf), "%d=%d, %s", pid, ns_pid, proc_name);

	return buf;
}

const char *pytrace_str(const struct pytrace_tracee *t)
{
	return pytrace_proc_str(t->pid, t->ns_pid, t->proc_name);
}

static struct pytrace_tracee *add_pytrace_tracee(struct tracee_state *tracee)
{
	const struct tracee_info *info = tracee_info(tracee);
	struct pytrace_tracee *pf;

	env.pytraces = realloc(env.pytraces, (env.pytrace_cnt + 1) * sizeof(*env.pytraces));

	pf = &env.pytraces[env.pytrace_cnt];
	memset(pf, 0, sizeof(*pf));

	pf->pid = info->pid;
	pf->ns_pid = info->ns_pid;
	pf->proc_name = info->name;
	pf->uds_fd = info->uds_fd;
	pf->tracee = tracee;
	pf->ctx = info->run_ctx;

	pf->log_fd = -1;
	pf->dump_fd = -1;

	env.pytrace_cnt++;

	return pf;
}

/*
 * Resolve pytrace Python C API symbols from the binary using elf_find_syms.
 * Computes runtime addresses (base_addr + offset) for each symbol.
 * Returns 0 on success, -ENOENT if any required symbol is missing.
 */
static int pytrace_resolve_symbols(int pid, struct py_binary_info *bi, unsigned long *sym_addrs)
{
	long offsets[PYTRACE_SYM_CNT] = {};
	int err;

	err = elf_find_syms(bi->host_path, STT_FUNC, pytrace_sym_names, offsets, PYTRACE_SYM_CNT);
	if (err) {
		for (int i = 0; i < PYTRACE_SYM_CNT; i++) {
			if (offsets[i])
				continue;
			/* PyEval_SetProfileAllThreads is 3.12+ only */
			if (strcmp(pytrace_sym_names[i], "PyEval_SetProfileAllThreads") == 0) {
				vprintf("PID %d: %s not found, skipping\n", pid, pytrace_sym_names[i]);
				continue;
			}
			eprintf("PID %d: missing required Python symbol[%s] in %s\n", pid, pytrace_sym_names[i], bi->host_path);
			return -ENOENT;
		}
	}

	for (int i = 0; i < PYTRACE_SYM_CNT; i++) {
		sym_addrs[i] = offsets[i] ? bi->base_addr + offsets[i] : 0;
		if (offsets[i])
			dlogf(PYTRACE, 1, "  %s: offset=0x%lx addr=0x%lx\n", pytrace_sym_names[i], offsets[i], sym_addrs[i]);
	}

	return 0;
}

static int try_inject_to_python_process(int pid, int workdir_fd)
{
	struct py_binary_info bi;
	unsigned long sym_addrs[PYTRACE_SYM_CNT] = {};
	char log_path[128];
	int err = 0, log_fd = -1;

	err = py_find_binary(pid, &bi);
	if (err) {
		dlogf(PYTRACE, 1, "PID %d (%s) is not Python, skipping\n", pid, proc_name(pid));
		return -ENOENT;
	}

	vprint("Process %s is Python 3.%d!\n",
	      pytrace_proc_str(pid, ns_tid_by_host_tid(pid, pid), proc_name(pid)), bi.py_version_minor);

	dlogf(PYTRACE, 0, "PID %d: Python binary at '%s', base_addr=0x%lx\n", pid, bi.host_path, bi.base_addr);

	/* Resolve all required Python C API symbols before injection */
	err = pytrace_resolve_symbols(pid, &bi, sym_addrs);
	if (err) {
		eprintf("Failed to resolve Python symbols for %s, skipping injection\n",
			pytrace_proc_str(pid, ns_tid_by_host_tid(pid, pid), proc_name(pid)));
		return err;
	}

	snprintf(log_path, sizeof(log_path), LIBWPROFINJ_PYTRACE_LOG_PATH_FMT, getpid(), pid);
	log_fd = openat(workdir_fd, log_path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
	if (log_fd < 0) {
		err = -errno;
		eprintf("Failed to create pytrace tracee %s log file at '%s': %d\n",
			pytrace_proc_str(pid, ns_tid_by_host_tid(pid, pid), proc_name(pid)),
			log_path, err);
		return err;
	}

	vprintf("Injecting libwprofinj.so into %s (Python 3.%d)...\n",
		pytrace_proc_str(pid, ns_tid_by_host_tid(pid, pid), proc_name(pid)), bi.py_version_minor);

	struct tracee_state *tracee = tracee_inject(pid);
	if (!tracee) {
		err = -errno;
		close(log_fd);
		eprintf("PTRACE injection failed for %s: %d\n",
			pytrace_proc_str(pid, ns_tid_by_host_tid(pid, pid), proc_name(pid)), err);
		return err;
	}

	vprintf("Injection successful, performing handshake with %s...\n",
		pytrace_proc_str(pid, ns_tid_by_host_tid(pid, pid), proc_name(pid)));

	err = tracee_handshake(tracee, log_fd, false);
	if (err) {
		eprintf("Injection handshake with %s failed: %d\n",
			pytrace_proc_str(pid, ns_tid_by_host_tid(pid, pid), proc_name(pid)), err);
		goto err_retract;
	}

	struct pytrace_tracee *pf = add_pytrace_tracee(tracee);

	pf->log_fd = log_fd;
	pf->log_path = strdup(log_path);
	pf->py_version_minor = bi.py_version_minor;
	memcpy(pf->sym_addrs, sym_addrs, sizeof(sym_addrs));
	pf->state = TRACEE_INJECTED;

	return 0;

err_retract:
	close(log_fd);
	(void)tracee_retract(tracee);
	tracee_free(tracee);
	return err;
}

int pytrace_trace_setup(int workdir_fd)
{
	int err = 0;

retry:
	switch (env.pytrace_discovery) {
	case PYTRACE_DISCOVER_PROC: {
		int *pidp, pid;

		wprof_for_each(proc, pidp) {
			pid = *pidp;
			try_inject_to_python_process(pid, workdir_fd, false);
		}
		break;
	}
	case PYTRACE_DISCOVER_NVIDIA_SMI: {
		vprintf("Using nvidia-smi to find Python processes using GPU...\n");

		FILE *f = popen("nvidia-smi --query-compute-apps=pid --format=csv,noheader", "r");
		if (!f) {
			eprintf("Failed to query nvidia-smi, falling back to process discovery logic...\n");
			env.pytrace_discovery = PYTRACE_DISCOVER_PROC;
			goto retry;
		}

		char pidbuf[32];
		int pid;
		while (fgets(pidbuf, sizeof(pidbuf), f)) {
			if (sscanf(pidbuf, "%d", &pid) != 1)
				continue;

			try_inject_to_python_process(pid, workdir_fd, false);
		}

		pclose(f);
		break;
	}
	case PYTRACE_DISCOVER_NONE:
		break;
	default:
		eprintf("Unrecognized pytrace discovery strategy %d!\n", env.pytrace_discovery);
		return -EOPNOTSUPP;
	}

	/* Also try explicitly specified PIDs */
	for (int i = 0; i < env.pytrace_pid_cnt; i++) {
		int pid = env.pytrace_pids[i];

		/* TODO(patlu): refactor -fpy-trace=<PID> to valid no duplication, then we can drop this */
		bool found = false;
		for (int j = 0; j < env.pytrace_cnt; j++) {
			if (env.pytraces[j].pid == pid) {
				found = true;
				break;
			}
		}
		if (found)
			continue;

		try_inject_to_python_process(pid, workdir_fd);
	}

	return 0;
}

int pytrace_trace_prepare(int workdir_fd, long sess_timeout_ms)
{
	for (int i = 0; i < env.pytrace_cnt; i++) {
		struct pytrace_tracee *pf = &env.pytraces[i];

		char dump_path[128];
		snprintf(dump_path, sizeof(dump_path), LIBWPROFINJ_PYTRACE_DUMP_PATH_FMT, getpid(), pf->pid);

		int dump_fd = openat(workdir_fd, dump_path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
		if (dump_fd < 0) {
			int err = -errno;
			eprintf("Failed to create pytrace tracee %s dump file at '%s': %d\n",
				pytrace_str(pf), dump_path, err);
			return err;
		}

		vprintf("Sending PYTRACE_SESSION to tracee #%d (%s), Python 3.%d, timeout %ldms...\n",
			i, pytrace_str(pf), pf->py_version_minor, sess_timeout_ms);

		struct inj_msg msg = {
			.kind = INJ_MSG_PYTRACE_SESSION,
			.pytrace_session = {
				.session_timeout_ms = sess_timeout_ms,
				.py_version_minor = pf->py_version_minor,
			},
		};
		memcpy(msg.pytrace_session.sym_addrs, pf->sym_addrs, sizeof(pf->sym_addrs));
		int err = uds_send_data(pf->uds_fd, &msg, sizeof(msg), &dump_fd, 1);
		if (err < 0) {
			eprintf("Failed to start pytrace trace session for tracee %s: %d\n",
				pytrace_str(pf), err);
			close(dump_fd);
			pf->state = TRACEE_SETUP_FAILED;
			continue;
		}

		pf->dump_fd = dump_fd;
		pf->dump_path = strdup(dump_path);
		pf->state = TRACEE_PENDING;
	}

	/* Wait for tracees to be ready */
	vprintf("Waiting for pytrace tracees to be ready...\n");
	u64 start_ts = ktime_now_ns();
	for (int i = 0; i < env.pytrace_cnt; i++) {
		struct pytrace_tracee *pf = &env.pytraces[i];

		if (pf->state != TRACEE_PENDING)
			continue;

		while (*(volatile enum inj_setup_state *)&pf->ctx->setup_state == INJ_SETUP_PENDING &&
		       (ktime_now_ns() - start_ts < LIBWPROFINJ_SETUP_TIMEOUT_MS * 1000000ULL)) {
			usleep(10000);
		}

		switch (pf->ctx->setup_state) {
		case INJ_SETUP_READY:
			vprintf("pytrace tracee #%d (%s) is READY!\n", i, pytrace_str(pf));
			pf->state = TRACEE_ACTIVE;
			break;
		case INJ_SETUP_FAILED:
		default:
			if (pf->ctx->exit_hint) {
				vprintf("pytrace tracee #%d (%s) failed: '%s'.\n",
					i, pytrace_str(pf), pf->ctx->exit_hint_msg);
				pf->state = TRACEE_SETUP_FAILED;
			} else {
				vprintf("pytrace tracee #%d (%s) TIMED OUT!\n", i, pytrace_str(pf));
				pf->state = TRACEE_SETUP_TIMEOUT;
			}
			break;
		}
	}

	return 0;
}

int pytrace_trace_activate(long sess_start_ts, long sess_end_ts)
{
	for (int i = 0; i < env.pytrace_cnt; i++) {
		struct pytrace_tracee *pf = &env.pytraces[i];

		if (pf->state != TRACEE_ACTIVE)
			continue;

		pf->ctx->sess_end_ts = sess_end_ts;
		pf->ctx->sess_start_ts = sess_start_ts;
	}

	return 0;
}

static void dump_tracee_log(struct pytrace_tracee *pf, int idx)
{
	if (!(env_log_set & LOG_PYTRACE))
		return;

	vprintf("PyTrace tracee #%d (%s) LOG (%s) DUMP (LAST STATE %s):\n"
		"=======================================================================================================\n",
		idx, pytrace_str(pf), pf->log_path, cuda_tracee_state_str(pf->state));

	lseek(pf->log_fd, 0, SEEK_SET);

	FILE *f = fdopen(pf->log_fd, "r");
	if (!f) {
		int err = -errno;
		eprintf("Failed to create FILE wrapper around pytrace tracee #%d (%s) log FD: %d\n",
			idx, pytrace_str(pf), err);
		return;
	}

	char buf[4096];
	while (fgets(buf, sizeof(buf), f)) {
		vprintf("    %s", buf);
	}

	vprintf("=======================================================================================================\n");

	fclose(f);
	pf->log_fd = -1;
}

void pytrace_trace_deactivate(void)
{
	if (env.pytraces_deactivated)
		return;

	wprintf("Deactivating pytrace trace injections...\n");

	for (int i = 0; i < env.pytrace_cnt; i++) {
		struct pytrace_tracee *pf = &env.pytraces[i];

		if (pf->state == TRACEE_SETUP_FAILED || pf->state == TRACEE_SETUP_TIMEOUT) {
			zclose(pf->uds_fd);
			dump_tracee_log(pf, i);
			continue;
		}

		vprintf("Signaling pytrace tracee #%d (%s) to exit...\n", i, pytrace_str(pf));

		struct inj_msg msg = {
			.kind = INJ_MSG_SHUTDOWN,
			.shutdown = { },
		};
		int err = uds_send_data(pf->uds_fd, &msg, sizeof(msg), NULL, 0);

		zclose(pf->uds_fd);

		if (err < 0) {
			eprintf("Failed to send SHUTDOWN to pytrace tracee #%d (%s): %d\n",
				i, pytrace_str(pf), err);
			if (pf->state == TRACEE_ACTIVE)
				pf->state = TRACEE_SHUTDOWN_FAILED;
			dump_tracee_log(pf, i);
			continue;
		}
	}

	/* Wait for tracees to shut down */
	vprintf("Waiting for pytrace tracees to shut down...\n");
	u64 start_ts = ktime_now_ns();
	for (int i = 0; i < env.pytrace_cnt; i++) {
		struct pytrace_tracee *pf = &env.pytraces[i];

		if (pf->state != TRACEE_ACTIVE)
			continue;

		while (!pf->ctx->worker_thread_done &&
		       (ktime_now_ns() - start_ts < LIBWPROFINJ_TEARDOWN_TIMEOUT_MS * 1000000ULL)) {
			usleep(10000);
		}

		if (!pf->ctx->worker_thread_done) {
			eprintf("pytrace tracee #%d (%s) TIMED OUT DURING TEARDOWN!\n",
				i, pytrace_str(pf));
			pf->state = TRACEE_SHUTDOWN_TIMEOUT;
		} else {
			vprintf("pytrace tracee #%d (%s) shut down cleanly"
				" (%ld events, %ld code objects cached).\n",
				i, pytrace_str(pf),
				pf->ctx->pytrace_event_cnt, pf->ctx->pytrace_code_cache_cnt);
			pf->state = TRACEE_INACTIVE;
		}

		dump_tracee_log(pf, i);
	}

	env.pytraces_deactivated = true;
}

void pytrace_trace_retract(void)
{
	if (env.pytraces_retracted)
		return;

	wprintf("Retracting pytrace trace injections...\n");

	for (int i = 0; i < env.pytrace_cnt; i++) {
		struct pytrace_tracee *pf = &env.pytraces[i];

		switch (pf->state) {
		case TRACEE_SETUP_FAILED:
		case TRACEE_INACTIVE:
			break;
		default:
			continue;
		}

		dprintf(1, "Retracting pytrace tracee #%d (%s)...\n", i, pytrace_str(pf));

		int err = tracee_retract(pf->tracee);
		if (err) {
			eprintf("Retraction for pytrace tracee #%d (%s) FAILED: %d!\n",
				i, pytrace_str(pf), err);
		}
	}

	env.pytraces_retracted = true;
}

void pytrace_trace_teardown(void)
{
	pytrace_trace_deactivate();
	pytrace_trace_retract();

	for (int i = 0; i < env.pytrace_cnt; i++) {
		struct pytrace_tracee *pf = &env.pytraces[i];

		zclose(pf->uds_fd);
		zclose(pf->dump_fd);
		zclose(pf->log_fd);
	}
}
