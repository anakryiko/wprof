// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/futex.h>

#include "inj_common.h"

static struct inj_setup_ctx *setup_ctx, _setup_ctx;
static struct inj_run_ctx *run_ctx;
static FILE *log;

#define logf(fmt, ...) do { fprintf(stderr, fmt, ##__VA_ARGS__); if (log) fprintf(log, fmt, ##__VA_ARGS__); } while (0)

#define WORKER_STACK_SIZE (256 * 1024)
static pid_t inj_tid = -1;
static void *stack = NULL;
static int exit_evfd = -1;
static pid_t worker_tid; /* for clone() and futex() only */

static int worker_thread_func(void *arg)
{
	int fds[MAX_UDS_FD_CNT] = { [0 ... MAX_UDS_FD_CNT - 1] = -1}, fd_cnt = 0;
	int ret, err = 0;
	int run_ctx_memfd = -1, workdir_fd = -1;

	logf("LIBINJ: Worker thread started (tid=%d)\n", gettid());

	struct iovec io = { .iov_base = &fd_cnt, .iov_len = sizeof(fd_cnt) };
	char buf[CMSG_SPACE(sizeof(fds))];
	struct msghdr msg = {
		.msg_iov = &io,
		.msg_iovlen = 1,
		.msg_control = buf,
		.msg_controllen = sizeof(buf),
	};

	ret = recvmsg(setup_ctx->uds_fd, &msg, 0);
	if (ret < 0) {
		err = -errno;
		logf("LIBINJ: UDS recvmsg() error (ret %d): %d\n", ret, err);
		goto cleanup;
	} else if (ret != sizeof(fd_cnt)) {
		err = -errno;
		logf("LIBINJ: UDS recvmsg() unexpected result (ret %d): %d\n", ret, err);
		goto cleanup;
	}

	int exp_cnt = 2;
	if (fd_cnt != exp_cnt) {
		err = -E2BIG;
		logf("LIBINJ: UDS recvmsg() returned invalid number of FDs (got %d, expected %d)\n", fd_cnt, exp_cnt);
		goto cleanup;
	}

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	memcpy(fds, CMSG_DATA(cmsg), sizeof(*fds) * fd_cnt);
	logf("LIBINJ: RECEIVED %d FDs FROM TRACER\n", fd_cnt);

	run_ctx_memfd = fds[0];
	workdir_fd = fds[1];

	/* fd[0] is memfd for run context */
	const size_t run_ctx_sz = sizeof(struct inj_run_ctx);
	run_ctx = mmap(NULL, run_ctx_sz, PROT_READ | PROT_WRITE, MAP_SHARED, run_ctx_memfd, 0);
	if (run_ctx == MAP_FAILED) {
		err = -errno;
		logf("LIBINJ: failed to mmap() provided run_ctx: %d\n", err);
		goto cleanup;
	}

	/* fd[1] is directory FD for working dir */
	char log_path[32];
	snprintf(log_path, sizeof(log_path), "log.%d.txt", getpid());
	int log_fd = openat(workdir_fd, log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (log_fd < 0) {
		err = -errno;
		logf("LIBINJ: failed to create log file '%s': %d\n", log_path, err);
		goto cleanup;
	}
	log = fdopen(log_fd, "w");
	if (!log) {
		err = -errno;
		logf("LIBINJ: failed to create FILE wrapper around log file '%s': %d\n", log_path, err);
		goto cleanup;
	}
	setlinebuf(log); /* line-buffered FILE for logging */

	for (int i = 0; i < fd_cnt; i++) {
		close(fds[i]);
		fds[i] = -1;
	}

	/* Wait for exit signal on eventfd */
	logf("LIBINJ: Worker thread waiting for exit signal...\n");
	
	long long unsigned tmp;
	ret = read(exit_evfd, &tmp, sizeof(tmp));
	if (ret != sizeof(tmp)) {
		err = -errno;
		logf("LIBINJ: Worker thread eventfd read failed (ret %d): %d\n", ret, err);
	} else {
		logf("LIBINJ: Worker thread received exit signal (value %llu)\n", tmp);
	}
	close(exit_evfd);
	exit_evfd = -1;

	logf("LIBINJ: Worker thread exiting\n");

cleanup:
	close(setup_ctx->uds_fd);
	if (run_ctx_memfd >= 0)
		close(run_ctx_memfd);

	logf("LIBINJ: Worker thread exited (err %d)\n", err);

	return err;
}

static int start_worker_thread(void)
{
	int err;

	logf("LIBINJ: Creating worker thread...\n");

	/* Create eventfd()s for exit signaling */
	exit_evfd = eventfd(0, EFD_CLOEXEC);
	if (exit_evfd < 0) {
		err = -errno;
		logf("LIBINJ: Failed to create exit-command eventfd: %d\n", err);
		goto err_out;
	}

	/* Allocate stack for the worker thread */
	stack = mmap(NULL, WORKER_STACK_SIZE, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (stack == MAP_FAILED) {
		err = -errno;
		logf("LIBINJ: Failed to allocate worker stack: %d\n", err);
		goto err_out;
	}

	inj_tid = clone(worker_thread_func, stack + WORKER_STACK_SIZE /* top-of-stack */,
			CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_SYSVSEM |
			CLONE_THREAD |
			CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID /* ! IMPORTANT ! */,
			NULL, /* arg */
			NULL, /* parent_tid */
			NULL, /* tls */
			&worker_tid); /* child_tid for SETTID/CLEARTID */
	if (inj_tid < 0) {
		err = -errno;
		logf("LIBINJ: Failed to clone() worker thread: %d\n", err);
		goto err_out;
	}

	logf("LIBINJ: Worker thread created successfully (tid=%d)\n", inj_tid);
	return 0;
err_out:
	if (stack && stack != MAP_FAILED)
		(void)munmap(stack, WORKER_STACK_SIZE);
	if (exit_evfd >= 0) {
		(void)close(exit_evfd);
		exit_evfd = -1;
	}
	return err;
}

/* Stop worker thread */
static void stop_worker_thread(void)
{
	int err = 0, ret;
	long long unsigned tmp;

	if (inj_tid < 0) {
		logf("LIBINJ: No worker thread to stop\n");
		return;
	}

	logf("LIBINJ: Signaling worker thread to exit...\n");

	/* Signal worker thread via eventfd */
	tmp = 1;
	ret = write(exit_evfd, &tmp, sizeof(tmp));
	if (ret != sizeof(tmp)) {
		err = -errno;
		logf("LIBINJ: Failed to write to eventfd: %d\n", err);
	}

	logf("LIBINJ: Waiting for worker thread to exit...\n");

	/* wait for worker thread to exit fully */
	while (*(volatile pid_t *)&worker_tid == inj_tid)
		syscall(SYS_futex, &worker_tid, FUTEX_WAIT, inj_tid, NULL, NULL, 0);

	/* now it's safe to munmap() thread's stack */
	if (stack) {
		(void)munmap(stack, WORKER_STACK_SIZE);
		stack = NULL;
	}

	logf("LIBINJ: Worker thread cleanup complete\n");
	inj_tid = -1;
}

__attribute__((constructor))
void libwprofinj_init()
{
    logf("LIBINJ: ========================================\n");
    logf("LIBINJ: libinj.so: Constructor called - library loaded\n");
    logf("LIBINJ: ========================================\n");
}

int LIBWPROFINJ_SETUP_SYM(struct inj_setup_ctx *ctx)
{
	/* memory backing setup_ctx might go away after this call, so copy */
	_setup_ctx = *ctx;
	setup_ctx = &_setup_ctx;

	logf("LIBINJ: INIT SETUP setup_ctx at %p\n", setup_ctx);

	close(setup_ctx->lib_mem_fd);
	close(setup_ctx->uds_parent_fd);

	/* Start worker thread (CUPTI will be initialized inside the thread) */
	int err = start_worker_thread();
	if (err) {
		logf("LIBINJ: FAILED TO START LIBINJ WORKER THREAD!\n");
		return err;
	}

	logf("LIBINJ: Constructor complete\n");
	return 0;
}

__attribute__((destructor))
void libwprofinj_fini()
{
    logf("LIBINJ: ========================================\n");
    logf("LIBINJ: libinj.so: Destructor called - library unloaded\n");
    logf("LIBINJ: ========================================\n");

    /* Stop worker thread (CUPTI will be finalized inside the thread before it exits) */
    stop_worker_thread();

    logf("LIBINJ: Destructor complete\n");
    logf("LIBINJ: ========================================\n");
}
