// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2026 Meta Platforms, Inc.
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "injmgr.h"
#include "proc.h"
#include "env.h"
#include "sys.h"
#include "inj_common.h"
#include "inject.h"
#include "bpf_utils.h"

#define LIBWPROFINJ_LOG_PATH_FMT "wprofinj-log.%d.%d.log"
#define LIBWPROFINJ_CUDA_DUMP_PATH_FMT "wprofinj-cuda.%d.%d.data"
#define LIBWPROFINJ_PYTRACE_DUMP_PATH_FMT "wprofinj-pytrace.%d.%d.data"
#define LIBWPROFINJ_PYTORCH_DUMP_PATH_FMT "wprofinj-pytorch.%d.%d.data"

const char *inj_proc_str(int pid, int ns_pid, const char *name)
{
	static __thread char buf[128];

	if (pid == ns_pid)
		snprintf(buf, sizeof(buf), "PID %d (%s)", pid, name);
	else
		snprintf(buf, sizeof(buf), "PID %d=%d (%s)", pid, ns_pid, name);

	return buf;
}

const char *injectee_str(const struct injectee *inj)
{
	return inj_proc_str(inj->pid, inj->ns_pid, inj->proc_name);
}

static const char *inj_feat_str(enum inj_feature feats)
{
	static __thread char buf[32];
	int n = 0;

	buf[0] = '\0';
	if (feats & INJ_FEAT_CUDA)
		n += snprintf(buf + n, sizeof(buf) - n, "%sCUDA", buf[0] ? "+" : "");
	if (feats & INJ_FEAT_PYTRACE)
		n += snprintf(buf + n, sizeof(buf) - n, "%sPyTrace", buf[0] ? "+" : "");
	if (feats & INJ_FEAT_PYTORCH)
		n += snprintf(buf + n, sizeof(buf) - n, "%sPyTorch", buf[0] ? "+" : "");

	return buf[0] ? buf : "none";
}

/*
 * Candidate PID set built during enumeration. Each PID records which features
 * we intend to probe for (the union across discovery sources), so /proc is
 * scanned once even when several features use PROC discovery.
 */
struct inj_cand {
	int pid;
	enum inj_feature intents;
	bool force_cuda;
};

static struct inj_cand *inj_cands;
static int inj_cand_cnt;

static void injmgr_add_candidate(int pid, enum inj_feature intent, bool force_cuda)
{
	for (int i = 0; i < inj_cand_cnt; i++) {
		if (inj_cands[i].pid != pid)
			continue;
		inj_cands[i].intents |= intent;
		inj_cands[i].force_cuda |= force_cuda;
		return;
	}

	inj_cands = realloc(inj_cands, (inj_cand_cnt + 1) * sizeof(*inj_cands));
	inj_cands[inj_cand_cnt].pid = pid;
	inj_cands[inj_cand_cnt].intents = intent;
	inj_cands[inj_cand_cnt].force_cuda = force_cuda;
	inj_cand_cnt++;
}

static bool injmgr_cuda_uses_proc(void)    { return env.cuda_discovery == CUDA_DISCOVER_PROC; }
static bool injmgr_cuda_uses_smi(void)     { return env.cuda_discovery == CUDA_DISCOVER_SMI; }
static bool injmgr_pytrace_uses_proc(void) { return env.capture_pytrace == TRUE && env.pytrace_discovery == PYTRACE_DISCOVER_PROC; }
static bool injmgr_pytrace_uses_smi(void)  { return env.capture_pytrace == TRUE && env.pytrace_discovery == PYTRACE_DISCOVER_NV_SMI; }
static bool injmgr_pytorch_uses_proc(void) { return env.capture_pytorch == TRUE && env.pytorch_discovery == PYTRACE_DISCOVER_PROC; }
static bool injmgr_pytorch_uses_smi(void)  { return env.capture_pytorch == TRUE && env.pytorch_discovery == PYTRACE_DISCOVER_NV_SMI; }

static void injmgr_enumerate_candidates(void)
{
	enum inj_feature proc_intents = (injmgr_cuda_uses_proc() ? INJ_FEAT_CUDA : 0) |
					(injmgr_pytrace_uses_proc() ? INJ_FEAT_PYTRACE : 0) |
					(injmgr_pytorch_uses_proc() ? INJ_FEAT_PYTORCH : 0);
	enum inj_feature smi_intents = (injmgr_cuda_uses_smi() ? INJ_FEAT_CUDA : 0) |
				       (injmgr_pytrace_uses_smi() ? INJ_FEAT_PYTRACE : 0) |
				       (injmgr_pytorch_uses_smi() ? INJ_FEAT_PYTORCH : 0);

	if (proc_intents) {
		int *pidp;
		wprof_for_each(proc, pidp)
			injmgr_add_candidate(*pidp, proc_intents, false);
	}

	if (smi_intents) {
		vprintf("Using nvidia-smi to find processes for %s...\n", inj_feat_str(smi_intents));
		int *pidp;
		wprof_for_each(gpu_pid, pidp) {
			/* nvidia-smi/explicit CUDA forces past the CUPTI-present check */
			injmgr_add_candidate(*pidp, smi_intents, smi_intents & INJ_FEAT_CUDA);
		}
	}

	for (int i = 0; i < env.cuda_pid_cnt; i++)
		injmgr_add_candidate(env.cuda_pids[i], INJ_FEAT_CUDA, true);
	for (int i = 0; i < env.pytrace_pid_cnt; i++)
		injmgr_add_candidate(env.pytrace_pids[i], INJ_FEAT_PYTRACE, false);
	for (int i = 0; i < env.pytorch_pid_cnt; i++)
		injmgr_add_candidate(env.pytorch_pids[i], INJ_FEAT_PYTORCH, false);
}

static struct injectee *injmgr_add_injectee(struct tracee_state *tracee)
{
	const struct tracee_info *info = tracee_info(tracee);
	struct injectee *inj;

	env.injectees = realloc(env.injectees, (env.injectee_cnt + 1) * sizeof(*env.injectees));
	inj = &env.injectees[env.injectee_cnt];
	memset(inj, 0, sizeof(*inj));

	inj->pid = info->pid;
	inj->ns_pid = info->ns_pid;
	inj->proc_name = info->name;
	inj->uds_fd = info->uds_fd;
	inj->tracee = tracee;
	inj->ctx = info->run_ctx;
	inj->lib_fd = info->lib_fd;
	inj->log_fd = -1;
	inj->cuda_dump_fd = -1;
	inj->pytrace_dump_fd = -1;
	inj->pytorch_dump_fd = -1;

	env.injectee_cnt++;
	return inj;
}

struct inj_detect_info {
	int py_version_minor;
	unsigned long py_sym_addrs[PYTRACE_SYM_CNT];
	unsigned long pytorch_sym_addrs[PYTORCH_SYM_CNT];
};

static enum inj_feature injmgr_detect_feats(const struct inj_cand *c, struct inj_detect_info *d)
{
	enum inj_feature detect = 0;

	if ((c->intents & INJ_FEAT_CUDA) && cuda_detect(c->pid, c->force_cuda))
		detect |= INJ_FEAT_CUDA;

	/* PyTrace and PyTorch both require the process to be Python. */
	if (c->intents & (INJ_FEAT_PYTRACE | INJ_FEAT_PYTORCH)) {
		if (pytrace_detect(c->pid, &d->py_version_minor, d->py_sym_addrs)) {
			if (c->intents & INJ_FEAT_PYTRACE)
				detect |= INJ_FEAT_PYTRACE;
			if ((c->intents & INJ_FEAT_PYTORCH) && pytorch_detect(c->pid, d->pytorch_sym_addrs))
				detect |= INJ_FEAT_PYTORCH;
		}
	}

	return detect;
}

static int injmgr_inject(const struct inj_cand *c, int workdir_fd)
{
	int err = 0;
	struct inj_detect_info d = {};
	enum inj_feature detect = injmgr_detect_feats(c, &d);
	if (!detect)
		return 0;

	const char *who = inj_proc_str(c->pid, ns_tid_by_host_tid(c->pid, c->pid), proc_name(c->pid));
	vprintf("%s uses %s, injecting...\n", who, inj_feat_str(detect));

	char log_path[512];
	snprintf(log_path, sizeof(log_path), LIBWPROFINJ_LOG_PATH_FMT, getpid(), c->pid);
	int log_fd = openat(workdir_fd, log_path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
	if (log_fd < 0) {
		err = -errno;
		eprintf("Failed to create %s log file at '%s': %d\n", who, log_path, err);
		return err;
	}

	struct tracee_state *tracee = tracee_inject(c->pid);
	if (!tracee) {
		err = -errno;
		close(log_fd);
		eprintf("PTRACE injection failed for %s: %d\n", who, err);
		return err;
	}

	/* request libwprofinj-side USDTs to be triggered if we need stack traces */
	bool use_usdts = (detect & INJ_FEAT_CUDA) && (env.requested_stack_traces & ST_CUDA);
	err = tracee_handshake(tracee, log_fd, use_usdts);
	if (err) {
		eprintf("Injection handshake with %s failed: %d\n", who, err);
		close(log_fd);
		int rerr = tracee_retract(tracee);
		if (rerr)
			eprintf("PTRACE retraction failed for %s: %d\n", who, rerr);
		else
			tracee_free(tracee);
		return err;
	}

	/* handshake transfers UDS FD ownership to us, it's now our responsibility to close it */
	struct injectee *inj = injmgr_add_injectee(tracee);
	inj->log_fd = log_fd;
	inj->log_path = strdup(log_path);
	inj->detect_feats = detect;
	inj->force_cuda = c->force_cuda;
	inj->py_version_minor = d.py_version_minor;
	memcpy(inj->py_sym_addrs, d.py_sym_addrs, sizeof(inj->py_sym_addrs));
	memcpy(inj->pytorch_sym_addrs, d.pytorch_sym_addrs, sizeof(inj->pytorch_sym_addrs));
	inj->state = INJECTEE_INJECTED;

	return 0;
}

int injmgr_setup(int workdir_fd)
{
	injmgr_enumerate_candidates();

	for (int i = 0; i < inj_cand_cnt; i++) {
		int err = injmgr_inject(&inj_cands[i], workdir_fd);
		if (err) {
			eprintf("Injection into PID %d (%s) failed: %d (skipping...)\n",
				inj_cands[i].pid, proc_name(inj_cands[i].pid), err);
		}
	}

	free(inj_cands);
	inj_cands = NULL;
	inj_cand_cnt = 0;

	return 0;
}

static int injmgr_send_cuda_setup(struct injectee *inj, int workdir_fd)
{
	char path[512];
	snprintf(path, sizeof(path), LIBWPROFINJ_CUDA_DUMP_PATH_FMT, getpid(), inj->pid);
	int dump_fd = openat(workdir_fd, path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
	if (dump_fd < 0) {
		int err = -errno;
		eprintf("Failed to create CUDA dump file for %s at '%s': %d\n", injectee_str(inj), path, err);
		return err;
	}

	struct inj_msg msg = { .kind = INJ_MSG_CUDA_SETUP };
	int err = uds_send_data(inj->uds_fd, &msg, sizeof(msg), &dump_fd, 1);
	if (err < 0) {
		eprintf("Failed to send CUDA_SETUP to %s: %d\n", injectee_str(inj), err);
		close(dump_fd);
		return err;
	}

	inj->cuda_dump_fd = dump_fd;
	inj->cuda_dump_path = strdup(path);
	return 0;
}

static int injmgr_send_pytrace_setup(struct injectee *inj, int workdir_fd)
{
	char path[512];
	snprintf(path, sizeof(path), LIBWPROFINJ_PYTRACE_DUMP_PATH_FMT, getpid(), inj->pid);
	int dump_fd = openat(workdir_fd, path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
	if (dump_fd < 0) {
		int err = -errno;
		eprintf("Failed to create PyTrace dump file for %s at '%s': %d\n", injectee_str(inj), path, err);
		return err;
	}

	struct inj_msg msg = {
		.kind = INJ_MSG_PYTRACE_SETUP,
		.pytrace_setup = { .py_version_minor = inj->py_version_minor },
	};
	memcpy(msg.pytrace_setup.sym_addrs, inj->py_sym_addrs, sizeof(inj->py_sym_addrs));
	int err = uds_send_data(inj->uds_fd, &msg, sizeof(msg), &dump_fd, 1);
	if (err < 0) {
		eprintf("Failed to send PYTRACE_SETUP to %s: %d\n", injectee_str(inj), err);
		close(dump_fd);
		return err;
	}

	inj->pytrace_dump_fd = dump_fd;
	inj->pytrace_dump_path = strdup(path);
	return 0;
}

static int injmgr_send_pytorch_setup(struct injectee *inj, int workdir_fd)
{
	char path[512];
	snprintf(path, sizeof(path), LIBWPROFINJ_PYTORCH_DUMP_PATH_FMT, getpid(), inj->pid);
	int dump_fd = openat(workdir_fd, path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
	if (dump_fd < 0) {
		int err = -errno;
		eprintf("Failed to create PyTorch dump file for %s at '%s': %d\n", injectee_str(inj), path, err);
		return err;
	}

	struct inj_msg msg = { .kind = INJ_MSG_PYTORCH_SETUP };
	memcpy(msg.pytorch_setup.pytorch_sym_addrs, inj->pytorch_sym_addrs, sizeof(inj->pytorch_sym_addrs));
	int err = uds_send_data(inj->uds_fd, &msg, sizeof(msg), &dump_fd, 1);
	if (err < 0) {
		eprintf("Failed to send PYTORCH_SETUP to %s: %d\n", injectee_str(inj), err);
		close(dump_fd);
		return err;
	}

	inj->pytorch_dump_fd = dump_fd;
	inj->pytorch_dump_path = strdup(path);
	return 0;
}

int injmgr_prepare(int workdir_fd, long sess_timeout_ms)
{
	/* Pass 1: open dumps and send each detected feature's *_SETUP message. */
	for (int i = 0; i < env.injectee_cnt; i++) {
		struct injectee *inj = &env.injectees[i];
		int err = 0;

		if (inj->detect_feats & INJ_FEAT_CUDA)
			err = err ?: injmgr_send_cuda_setup(inj, workdir_fd);
		if (inj->detect_feats & INJ_FEAT_PYTRACE)
			err = err ?: injmgr_send_pytrace_setup(inj, workdir_fd);
		if (inj->detect_feats & INJ_FEAT_PYTORCH)
			err = err ?: injmgr_send_pytorch_setup(inj, workdir_fd);

		if (err) {
			inj->state = INJECTEE_SETUP_FAILED;
			continue;
		}
		inj->state = INJECTEE_PENDING;
	}

	/* Pass 2: now that every tracee is set up, start their sessions together. */
	for (int i = 0; i < env.injectee_cnt; i++) {
		struct injectee *inj = &env.injectees[i];

		if (inj->state != INJECTEE_PENDING)
			continue;

		struct inj_msg msg = {
			.kind = INJ_MSG_START_SESSION,
			.start_session = { .session_timeout_ms = sess_timeout_ms },
		};
		int err = uds_send_data(inj->uds_fd, &msg, sizeof(msg), NULL, 0);
		if (err < 0) {
			eprintf("Failed to send START_SESSION to %s: %d\n", injectee_str(inj), err);
			inj->state = INJECTEE_SETUP_FAILED;
		}
	}

	/* Pass 3: wait for each tracee to report readiness, record available features. */
	vprintf("Waiting for tracees to be ready...\n");
	u64 start_ts = ktime_now_ns();
	for (int i = 0; i < env.injectee_cnt; i++) {
		struct injectee *inj = &env.injectees[i];

		if (inj->state != INJECTEE_PENDING)
			continue;

		while (*(volatile enum inj_setup_state *)&inj->ctx->setup_state == INJ_SETUP_PENDING &&
		       (ktime_now_ns() - start_ts < LIBWPROFINJ_SETUP_TIMEOUT_MS * 1000000ULL)) {
			usleep(10000);
		}

		if (inj->ctx->cuda_feat_state == FEAT_READY)
			inj->avail_feats |= INJ_FEAT_CUDA;
		if (inj->ctx->pytrace_feat_state == FEAT_READY)
			inj->avail_feats |= INJ_FEAT_PYTRACE;
		if (inj->ctx->pytorch_feat_state == FEAT_READY)
			inj->avail_feats |= INJ_FEAT_PYTORCH;

		switch (inj->ctx->setup_state) {
		case INJ_SETUP_READY:
			vprintf("%s is READY (%s)!\n", injectee_str(inj), inj_feat_str(inj->avail_feats));
			inj->state = INJECTEE_ACTIVE;
			break;
		case INJ_SETUP_FAILED:
			/* A CUPTI-busy CUDA-only tracee is IGNORED, not failed. */
			if (inj->detect_feats == INJ_FEAT_CUDA && inj->ctx->cuda_feat_state == FEAT_IGNORED) {
				dprintf(1, "%s will be IGNORED: %s\n", injectee_str(inj), inj->ctx->cuda_feat_hint);
				inj->state = INJECTEE_IGNORED;
			} else {
				vprintf("%s failed initial setup.\n", injectee_str(inj));
				inj->state = INJECTEE_SETUP_FAILED;
			}
			break;
		default:
			vprintf("%s TIMED OUT! Ignoring it...\n", injectee_str(inj));
			inj->state = INJECTEE_SETUP_TIMEOUT;
			break;
		}

		/* Surface any per-feature problem even when another feature succeeded. */
		if ((inj->detect_feats & INJ_FEAT_CUDA) && inj->state == INJECTEE_ACTIVE && inj->ctx->cuda_feat_state == FEAT_IGNORED)
			vprintf("  CUDA: %s requested but not captured: %s\n", injectee_str(inj), inj->ctx->cuda_feat_hint);
		if ((inj->detect_feats & INJ_FEAT_CUDA) && inj->ctx->cuda_feat_state == FEAT_FAILED && inj->ctx->cuda_feat_hint[0])
			vprintf("  CUDA: %s: %s\n", injectee_str(inj), inj->ctx->cuda_feat_hint);
		if ((inj->detect_feats & INJ_FEAT_PYTRACE) && inj->ctx->pytrace_feat_state == FEAT_FAILED && inj->ctx->pytrace_feat_hint[0])
			vprintf("  PyTrace: %s: %s\n", injectee_str(inj), inj->ctx->pytrace_feat_hint);
		if ((inj->detect_feats & INJ_FEAT_PYTORCH) && inj->ctx->pytorch_feat_state == FEAT_FAILED && inj->ctx->pytorch_feat_hint[0])
			vprintf("  PyTorch: %s: %s\n", injectee_str(inj), inj->ctx->pytorch_feat_hint);
	}

	return 0;
}

int injmgr_activate(long sess_start_ts, long sess_end_ts)
{
	for (int i = 0; i < env.injectee_cnt; i++) {
		struct injectee *inj = &env.injectees[i];

		if (inj->state != INJECTEE_ACTIVE)
			continue;

		inj->ctx->sess_end_ts = sess_end_ts;
		inj->ctx->sess_start_ts = sess_start_ts;
	}

	return 0;
}

int injmgr_attach_usdts(struct bpf_state *st, struct bpf_program *prog)
{
	for (int i = 0; i < env.injectee_cnt; i++) {
		struct injectee *inj = &env.injectees[i];

		if (inj->state != INJECTEE_ACTIVE)
			continue;
		if (!(inj->avail_feats & INJ_FEAT_CUDA))
			continue;

		char lib_path[32];
		snprintf(lib_path, sizeof(lib_path), "/proc/%d/fd/%d", inj->pid, inj->lib_fd);

		int err = attach_usdt_probe(st, prog, "libwprofinj.so", lib_path, "wprof", "cuda_call");
		if (err) {
			eprintf("Failed to attach CUDA USDTs for %s: %d, skipping...\n", injectee_str(inj), err);
			continue;
		}

		vprintf("Attached CUDA USDTs for %s.\n", injectee_str(inj));
	}

	return 0;
}

static void injmgr_dump_tracee_log(struct injectee *inj)
{
	if (!(env_log_set & LOG_TRACEE))
		return;

	if (inj->log_fd < 0) /* already dumped (and consumed the fd) */
		return;

	vprintf("%s LOG (%s) DUMP (LAST STATE %s):\n"
		"=======================================================================================================\n",
		injectee_str(inj), inj->log_path, injectee_state_str(inj->state));

	lseek(inj->log_fd, 0, SEEK_SET); /* just in case */

	FILE *f = fdopen(inj->log_fd, "r");
	if (!f) {
		int err = -errno;
		eprintf("Failed to create FILE wrapper around %s log FD: %d\n", injectee_str(inj), err);
		return;
	}

	char buf[4096];
	while (fgets(buf, sizeof(buf), f))
		vprintf("    %s", buf);

	vprintf("=======================================================================================================\n");

	fclose(f);
	inj->log_fd = -1;
}

void injmgr_deactivate(void)
{
	if (env.injectees_deactivated)
		return;

	wprintf("Deactivating trace injections...\n");

	for (int i = 0; i < env.injectee_cnt; i++) {
		struct injectee *inj = &env.injectees[i];

		if (inj->state == INJECTEE_IGNORED) {
			zclose(inj->uds_fd);
			if (env.debug_level)
				injmgr_dump_tracee_log(inj);
			continue;
		}

		if (inj->state == INJECTEE_SETUP_FAILED || inj->state == INJECTEE_SETUP_TIMEOUT) {
			zclose(inj->uds_fd);
			injmgr_dump_tracee_log(inj);
			continue;
		}

		vprintf("Signaling %s to exit...\n", injectee_str(inj));

		struct inj_msg msg = { .kind = INJ_MSG_SHUTDOWN };
		int err = uds_send_data(inj->uds_fd, &msg, sizeof(msg), NULL, 0);

		/* regardless of outcome, close UDS fd */
		zclose(inj->uds_fd);

		if (err < 0) {
			eprintf("Failed to send SHUTDOWN command cleanly to %s: %d\n", injectee_str(inj), err);
			if (inj->state == INJECTEE_ACTIVE)
				inj->state = INJECTEE_SHUTDOWN_FAILED;
			injmgr_dump_tracee_log(inj);
			continue;
		}
	}

	vprintf("Waiting for tracees to shut down...\n");
	u64 start_ts = ktime_now_ns();
	for (int i = 0; i < env.injectee_cnt; i++) {
		struct injectee *inj = &env.injectees[i];

		if (inj->state != INJECTEE_ACTIVE &&
		    inj->state != INJECTEE_IGNORED &&
		    inj->state != INJECTEE_SETUP_FAILED)
			continue;

		while (!inj->ctx->worker_thread_done &&
		       (ktime_now_ns() - start_ts < LIBWPROFINJ_TEARDOWN_TIMEOUT_MS * 1000000ULL)) {
			usleep(10000);
		}

		if (!inj->ctx->worker_thread_done) {
			eprintf("%s TIMED OUT DURING TEARDOWN! SKIPPING PTRACE RETRACTION!\n", injectee_str(inj));
			inj->state = INJECTEE_SHUTDOWN_TIMEOUT;
			injmgr_dump_tracee_log(inj);
			continue;
		}

		if (inj->state == INJECTEE_ACTIVE) {
			if (inj->avail_feats & INJ_FEAT_CUDA)
				vprintf("CUDA: %s shut down cleanly: %ld records.\n", injectee_str(inj), inj->ctx->cupti_rec_cnt);
			if (inj->avail_feats & INJ_FEAT_PYTORCH)
				vprintf("PyTorch: %s shut down cleanly: %ld events.\n", injectee_str(inj), inj->ctx->pytorch_event_cnt);
			if (inj->avail_feats & INJ_FEAT_PYTRACE) {
				vprintf("PyTrace: %s shut down cleanly: %ld events, %ld code objects cached.\n",
					injectee_str(inj), inj->ctx->pytrace_event_cnt, inj->ctx->pytrace_code_cache_cnt);
			}
			inj->state = INJECTEE_INACTIVE;
		} else {
			dprintf(1, "%s has shut down cleanly.\n", injectee_str(inj));
		}
		injmgr_dump_tracee_log(inj);
	}

	env.injectees_deactivated = true;
}

void injmgr_retract(void)
{
	if (env.injectees_retracted)
		return;

	wprintf("Retracting trace injections...\n");

	for (int i = 0; i < env.injectee_cnt; i++) {
		struct injectee *inj = &env.injectees[i];

		if (inj->state != INJECTEE_IGNORED &&
		    inj->state != INJECTEE_SETUP_FAILED &&
		    inj->state != INJECTEE_INACTIVE)
			continue;

		dprintf(1, "Retracting %s...\n", injectee_str(inj));

		int err = tracee_retract(inj->tracee);
		if (err)
			eprintf("Retraction for %s FAILED: %d!\n", injectee_str(inj), err);
	}

	env.injectees_retracted = true;
}

void injmgr_teardown(void)
{
	injmgr_deactivate();
	injmgr_retract();

	for (int i = 0; i < env.injectee_cnt; i++) {
		struct injectee *inj = &env.injectees[i];

		zclose(inj->uds_fd);
		zclose(inj->cuda_dump_fd);
		zclose(inj->pytrace_dump_fd);
		zclose(inj->pytorch_dump_fd);
		zclose(inj->log_fd);

		/*
		 * Free the low-level ptrace state only here, at the very end: merge
		 * reads inj->proc_name (which aliases tracee->proc_name) and runs
		 * after deactivate/retract, so it must outlive retraction.
		 */
		tracee_free(inj->tracee);
		inj->tracee = NULL;
	}
}
