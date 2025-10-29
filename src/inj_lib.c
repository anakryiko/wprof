// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
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
#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/futex.h>

#include "inj_common.h"

#define zclose(fd) do { if (fd >= 0) { close(fd); fd = -1; } } while (0)
#define __printf(a, b)	__attribute__((format(printf, a, b)))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#define DEBUG_LOG 1
#define elog(fmt, ...) do { log_printf(0, fmt, ##__VA_ARGS__); } while (0)
#define log(fmt, ...) do { log_printf(1, fmt, ##__VA_ARGS__); } while (0)
#define vlog(fmt, ...) do { log_printf(2, fmt, ##__VA_ARGS__); } while (0)
#define dlog(fmt, ...) do { log_printf(3, fmt, ##__VA_ARGS__); } while (0)

static struct inj_setup_ctx *setup_ctx;
static struct inj_run_ctx *run_ctx;

static FILE *filelog = NULL;
static int filelog_verbosity = -1;

#if DEBUG_LOG
static int stderr_verbosity = 3;
#else /* DEBUG_LOG */
static int stderr_verbosity = -1;
#endif /* DEBUG_LOG */

__printf(2, 3)
static void log_printf(int verbosity, const char *fmt, ...)
{
	va_list args;
	int old_errno;

	old_errno = errno;

	if (verbosity <= stderr_verbosity) {
		/* append "WPROFINJ: " prefix for stderr-based log messages */
		char final_fmt[1024];
		snprintf(final_fmt, sizeof(final_fmt), "WPROFINJ: %s", fmt);

		va_start(args, fmt);
		vfprintf(stderr, final_fmt, args);
		va_end(args);
	}
	if (filelog && verbosity <= filelog_verbosity) {
		va_start(args, fmt);
		vfprintf(filelog, fmt, args);
		va_end(args);
	}

	errno = old_errno;
}

#define WORKER_STACK_SIZE (256 * 1024)
#define UDS_MAX_MSG_LEN 1024

static pid_t inj_tid = -1;
static void *stack = NULL;
static int exit_fd = -1;
static pid_t worker_tid; /* for clone() and futex() only */

static char msg_buf[UDS_MAX_MSG_LEN];

static int worker_thread_func(void *arg)
{
	int fds[MAX_UDS_FD_CNT] = { [0 ... MAX_UDS_FD_CNT - 1] = -1}, fd_cnt = 0;
	int ret, err = 0;
	int run_ctx_memfd = -1, workdir_fd = -1, ep_fd = -1;

	vlog("Worker thread started (TID %d, PID %d)\n", gettid(), getpid());

	struct iovec io = { .iov_base = msg_buf, .iov_len = sizeof(msg_buf) };
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
		elog("UDS recvmsg() error (ret %d): %d\n", ret, err);
		goto cleanup;
	} else if (ret != sizeof(fd_cnt)) {
		err = -errno;
		elog("UDS recvmsg() unexpected result (ret %d): %d\n", ret, err);
		goto cleanup;
	}

	int exp_cnt = 2;
	if (fd_cnt != exp_cnt) {
		err = -E2BIG;
		elog("UDS recvmsg() returned invalid number of FDs (got %d, expected %d)\n", fd_cnt, exp_cnt);
		goto cleanup;
	}

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	memcpy(fds, CMSG_DATA(cmsg), sizeof(*fds) * fd_cnt);
	dlog("RECEIVED %d FDs FROM TRACER\n", fd_cnt);

	run_ctx_memfd = fds[0];
	workdir_fd = fds[1];

	/* fd[0] is memfd for run context */
	const size_t run_ctx_sz = sizeof(struct inj_run_ctx);
	run_ctx = mmap(NULL, run_ctx_sz, PROT_READ | PROT_WRITE, MAP_SHARED, run_ctx_memfd, 0);
	if (run_ctx == MAP_FAILED) {
		err = -errno;
		elog("Failed to mmap() provided run_ctx: %d\n", err);
		goto cleanup;
	}
	zclose(run_ctx_memfd);

	/* fd[1] is directory FD for working dir */
	char log_path[64];
	snprintf(log_path, sizeof(log_path), LIBWPROFINJ_LOG_PATH_FMT,
		 setup_ctx->parent_pid, getpid());
	int log_fd = openat(workdir_fd, log_path, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
	if (log_fd < 0) {
		err = -errno;
		elog("Failed to create log file '%s': %d\n", log_path, err);
		goto cleanup;
	}
	zclose(workdir_fd);

	filelog = fdopen(log_fd, "w");
	if (!filelog) {
		err = -errno;
		elog("Failed to create FILE wrapper around log file '%s': %d\n", log_path, err);
		goto cleanup;
	}
	setlinebuf(filelog); /* line-buffered FILE for logging */

	ep_fd = epoll_create1(EPOLL_CLOEXEC);
	if (ep_fd < 0) {
		err = -errno;
		elog("Failed to create epoll FD: %d\n", err);
		goto cleanup;
	}

	struct epoll_event evs[2] = {};
	evs[0].events = EPOLLIN;
	evs[0].data.fd = exit_fd;
	if (epoll_ctl(ep_fd, EPOLL_CTL_ADD, exit_fd, &evs[0]) < 0) {
		err = -errno;
		elog("Failed to EPOLL_CTL_ADD eventfd: %d\n", err);
		goto cleanup;
	}
	evs[0].events = EPOLLIN;
	evs[0].data.fd = setup_ctx->uds_fd;
	if (epoll_ctl(ep_fd, EPOLL_CTL_ADD, setup_ctx->uds_fd, &evs[0]) < 0) {
		err = -errno;
		elog("Failed to EPOLL_CTL_ADD UDS FD: %d\n", err);
		goto cleanup;
	}

	vlog("Waiting for exit or incoming commands...\n");

wait:
	int n = epoll_wait(ep_fd, evs, ARRAY_SIZE(evs), -1);
	if (n < 0) {
		err = -errno;
		elog("epoll_wait() failed: %d\n", err);
		goto cleanup;
	}
	for (int i = 0; i < n; i++) {
		if (evs[i].data.fd == setup_ctx->uds_fd) {
			/* XXX */
			goto wait;
		} else if (evs[i].data.fd == exit_fd) {
			long long unsigned tmp;
			ret = read(exit_fd, &tmp, sizeof(tmp));
			if (ret != sizeof(tmp)) {
				err = -errno;
				elog("Worker thread exit eventfd read failed (ret %d): %d\n", ret, err);
			} else {
				vlog("Worker thread received exit signal (value %llu)\n", tmp);
				err = 0;
			}
			goto cleanup;
		} else {
			elog("Unrecognized epoll event w/ FD %d, exiting...\n", evs[i].data.fd);
			err = -EINVAL;
			goto cleanup;
		}
	}

cleanup:
	vlog("Worker thread exiting...\n");

	zclose(exit_fd);
	zclose(setup_ctx->uds_fd);
	zclose(run_ctx_memfd);
	zclose(workdir_fd);
	zclose(ep_fd);

	if (err)
		elog("Worker thread exited with ERROR %d.\n", err);
	else
		vlog("Worker thread exited successfully.\n");

	return err;
}

static int start_worker_thread(void)
{
	int err;

	vlog("Creating worker thread...\n");

	/* Create eventfd()s for exit signaling */
	exit_fd = eventfd(0, EFD_CLOEXEC);
	if (exit_fd < 0) {
		err = -errno;
		elog("Failed to create exit-command eventfd: %d\n", err);
		goto err_out;
	}

	/* Allocate stack for the worker thread */
	stack = mmap(NULL, WORKER_STACK_SIZE, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (stack == MAP_FAILED) {
		err = -errno;
		elog("Failed to allocate worker stack: %d\n", err);
		goto err_out;
	}

	/* Now finally create a thread */
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
		elog("Failed to clone() worker thread: %d\n", err);
		goto err_out;
	}

	log("Worker thread created successfully (TID %d, PID %d)\n", inj_tid, getpid());
	return 0;
err_out:
	if (stack && stack != MAP_FAILED)
		(void)munmap(stack, WORKER_STACK_SIZE);
	zclose(exit_fd);
	return err;
}

/* Stop worker thread */
static void stop_worker_thread(void)
{
	int err = 0, ret;
	long long unsigned tmp;

	if (inj_tid < 0) {
		elog("No worker thread to stop...\n");
		return;
	}

	vlog("Signaling worker thread to exit...\n");

	if (exit_fd < 0) {
		elog("No exit signaling eventfd, exiting.\n");
		return;
	}

	/* Signal worker thread via eventfd */
	tmp = 1;
	ret = write(exit_fd, &tmp, sizeof(tmp));
	if (ret != sizeof(tmp)) {
		err = -errno;
		elog("Failed to write to eventfd: %d\n", err);
	}

	vlog("Waiting for worker thread to exit...\n");

	/* wait for worker thread to exit fully */
	while (*(volatile pid_t *)&worker_tid == inj_tid)
		syscall(SYS_futex, &worker_tid, FUTEX_WAIT, inj_tid, NULL, NULL, 0);

	/* now it's safe to munmap() thread's stack */
	if (stack) {
		(void)munmap(stack, WORKER_STACK_SIZE);
		stack = NULL;
	}

	vlog("Worker thread teardown is complete.\n");
	inj_tid = -1;
}

__attribute__((constructor))
void libwprofinj_init()
{
    vlog("======= CONSTRUCTOR ======\n");
}

struct inj_setup_ctx *LIBWPROFINJ_SETUP_SYM(struct inj_setup_ctx *ctx)
{
	/*
	 * If we already went through the setup step, let caller know where
	 * out setup context is located (most probably for cleanup after
	 * unclean injection)
	 */
	if (setup_ctx) {
		elog("Setup called more than once! old_setup_ctx %p new_setup_ctx %p\n", setup_ctx, ctx);
		return setup_ctx;
	}

	setup_ctx = ctx;

	zclose(setup_ctx->uds_parent_fd);

	stderr_verbosity = ctx->stderr_verbosity;
	filelog_verbosity = ctx->filelog_verbosity;

	int err = start_worker_thread();
	if (err) {
		zclose(setup_ctx->uds_fd);
		elog("Failed to start worker thread!\n");
		return NULL;
	}

	vlog("Setup completed.\n");
	return setup_ctx;
}

__attribute__((destructor))
void libwprofinj_fini()
{
	vlog("======= DESTRUCTOR STARTED ======\n");

	stop_worker_thread();

	vlog("======= DESTRUCTOR FINISHED ======\n");

	if (filelog)
		fclose(filelog);
}
