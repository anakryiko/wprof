// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <time.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <linux/futex.h>

#include "inj.h"
#include "inj_common.h"
#include "strset.h"
#include "cuda_data.h"

#define zclose(fd) do { if (fd >= 0) { close(fd); fd = -1; } } while (0)
#define __printf(a, b)	__attribute__((format(printf, a, b)))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#define DEBUG_LOG 1
#define elog(fmt, ...) do { log_printf(0, fmt, ##__VA_ARGS__); } while (0)
#define log(fmt, ...) do { log_printf(1, fmt, ##__VA_ARGS__); } while (0)
#define vlog(fmt, ...) do { log_printf(2, fmt, ##__VA_ARGS__); } while (0)
#define dlog(fmt, ...) do { log_printf(3, fmt, ##__VA_ARGS__); } while (0)

struct inj_setup_ctx *setup_ctx;
struct inj_run_ctx *run_ctx;

static FILE *filelog = NULL;
static int filelog_verbosity = -1;

#if DEBUG_LOG
static int stderr_verbosity = 3;
#else /* DEBUG_LOG */
static int stderr_verbosity = -1;
#endif /* DEBUG_LOG */

__printf(2, 3)
void log_printf(int verbosity, const char *fmt, ...)
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
static int epoll_fd = -1;
static int timer_fd = -1;
static int workdir_fd = -1;

static __u64 cuda_sess_start_ts, cuda_sess_end_ts;

static char msg_buf[UDS_MAX_MSG_LEN] __attribute__((aligned(8)));

enum epoll_kind {
	EK_EXIT,
	EK_UDS,
	EK_TIMER,
};

static int epoll_add(int epoll_fd, int fd, __u32 epoll_events, enum epoll_kind kind)
{
	struct epoll_event ev = {
		.events = epoll_events,
		.data = {
			.u32 = kind,
		},
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		int err = -errno;
		elog("Failed to EPOLL_CTL_ADD FD %d (kind %d) to epoll_fd %d: %d\n", fd, kind, epoll_fd, err);
		return err;
	}
	return 0;
}

__attribute__((unused))
static int epoll_del(int epoll_fd, int fd)
{
	if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL) < 0) {
		int err = -errno;
		elog("Failed to EPOLL_CTL_DEL FD %d from epoll_fd %d: %d\n", fd, epoll_fd, err);
		return err;
	}
	return 0;
}

#define CUDA_DUMP_BUF_SZ (256 * 1024)
static FILE *cuda_dump;

#define CUDA_DUMP_MAX_STRS_SZ (1024 * 1024 * 1024)
struct strset *cuda_dump_strs;

static void init_wcuda_header(struct wcuda_data_hdr *hdr)
{
	memset(hdr, 0, sizeof(*hdr));
	memcpy(hdr->magic, "WCUDA", 6);
	hdr->hdr_sz = sizeof(*hdr);
	hdr->flags = 0;
	hdr->version_major = WCUDA_DATA_MAJOR;
	hdr->version_minor = WCUDA_DATA_MINOR;
}

static int init_wcuda_data(FILE *dump)
{
	int err;

	err = fseek(dump, 0, SEEK_SET);
	if (err) {
		err = -errno;
		elog("Failed to fseek(0) CUDA data dump: %d\n", err);
		return err;
	}

	struct wcuda_data_hdr hdr;
	init_wcuda_header(&hdr);
	hdr.flags = WCUDA_DATA_FLAG_INCOMPLETE;

	if (fwrite(&hdr, sizeof(hdr), 1, dump) != 1) {
		err = -errno;
		elog("Failed to fwrite() CUDA data dump header: %d\n", err);
		return err;
	}

	fflush(dump);
	fsync(fileno(dump));
	return 0;
}

static int cuda_dump_setup(void)
{
	char dump_path[128];
	int err = 0, dump_fd = -1;

	snprintf(dump_path, sizeof(dump_path), LIBWPROFINJ_DUMP_PATH_FMT,
		 setup_ctx->parent_pid, getpid());

	cuda_dump_strs = strset__new(CUDA_DUMP_MAX_STRS_SZ, "", 1);

	dump_fd = openat(workdir_fd, dump_path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
	if (dump_fd < 0) {
		err = -errno;
		elog("Failed to create CUDA data dump file '%s': %d\n", dump_path, err);
		goto cleanup;
	}

	cuda_dump = fdopen(dump_fd, "w");
	if (!cuda_dump) {
		err = -errno;
		elog("Failed to create FILE wrapper around dump FD for '%s': %d\n", dump_path, err);
		goto cleanup;
	}
	setvbuf(cuda_dump, NULL, _IOFBF, CUDA_DUMP_BUF_SZ);

	if ((err = init_wcuda_data(cuda_dump)) < 0) {
		elog("Failed to init CUDA dump: %d\n", err);
		goto cleanup;
	}

	return 0;

cleanup:
	strset__free(cuda_dump_strs);
	cuda_dump_strs = NULL;
	if (cuda_dump) { 
		fclose(cuda_dump);
		cuda_dump = NULL;
	} else {
		zclose(dump_fd);
	}
	return err;
}

static int cuda_dump_finalize(void)
{
	int err = 0;

	fflush(cuda_dump);

	long strs_off = ftell(cuda_dump);
	if (strs_off < 0) {
		err = -errno;
		elog("Failed to get CUDA dump file position: %d\n", err);
		return err;
	}

	const char *strs = strset__data(cuda_dump_strs);
	size_t strs_sz = strset__data_size(cuda_dump_strs);

	size_t written;
	if ((written = fwrite(strs, 1, strs_sz, cuda_dump)) != strs_sz) {
		err = -errno;
		elog("Failed to write strings (ret %zu) to CUDA dump: %d\n", written, err);
		return err;
	}

	fsync(fileno(cuda_dump));

	struct wcuda_data_hdr hdr;
	init_wcuda_header(&hdr);

	hdr.sess_start_ns = cuda_sess_start_ts;
	hdr.sess_end_ns = cuda_sess_end_ts;
	hdr.events_off = 0;
	hdr.events_sz = strs_off - sizeof(struct wcuda_data_hdr);
	hdr.strs_off = strs_off - sizeof(struct wcuda_data_hdr);
	hdr.strs_sz = strs_sz;
	hdr.cfg.dummy = 0;

	err = fseek(cuda_dump, 0, SEEK_SET);
	if (err) {
		err = -errno;
		elog("Failed to fseek(0): %d\n", err);
		return err;
	}

	if (fwrite(&hdr, sizeof(hdr), 1, cuda_dump) != 1) {
		err = -errno;
		elog("Failed to fwrite() CUDA dump header: %d\n", err);
		return err;
	}

	fflush(cuda_dump);
	fsync(fileno(cuda_dump));

	return 0;
}

static int cuda_dump_kernel_event(const char *name, u64 start_ns, u64 end_ns)
{
	struct wcuda_event e = {
		.sz = sizeof(e),
		.kind = WCK_CUDA_KERNEL,
		.ts = start_ns,
		.cuda_kernel = {
			.dur_ns = end_ns - start_ns,
			.name_off = strset__add_str(cuda_dump_strs, name),
		},
	};

	if (fwrite(&e, sizeof(e), 1, cuda_dump) != 1) {
		int err = -errno;
		elog("Failed to add CUDA dump event: %d\n", err);
		return err;
	}

	return 0;
}

static int handle_msg(struct inj_msg *msg)
{
	int err = 0;

	switch (msg->kind) {
	case INJ_MSG_CUDA_SESSION:
		__u64 now = ktime_now_ns();

		cuda_sess_start_ts = msg->cuda_session.session_start_ns;
		cuda_sess_end_ts = msg->cuda_session.session_end_ns;

		vlog("CUDA session request received (start delay %.3lfus, end delay %.3lfus)\n",
			(cuda_sess_start_ts - (double)now) / 1000.0,
			(cuda_sess_end_ts - (double)now) / 1000.0);

		timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
		if (timer_fd < 0) {
			err = -errno;
			elog("Failed to create timerfd: %d\n", err);
			return err;
		}

		struct itimerspec spec = {
			.it_value = {
				.tv_sec = cuda_sess_end_ts / 1000000000,
				.tv_nsec = cuda_sess_end_ts % 1000000000,
			},
		};
		if (timerfd_settime(timer_fd, TFD_TIMER_ABSTIME, &spec, NULL) < 0) {
			err = -errno;
			elog("Failed to timerfd_settime(): %d\n", err);
			return err;
		}

		if ((err = epoll_add(epoll_fd, timer_fd, EPOLLIN, EK_TIMER)) < 0) {
			elog("Failed to add timerfd into epoll: %d\n", err);
			return err;
		}

		if ((err = cuda_dump_setup()) < 0) {
			elog("Failed to setup CUDA data dump: %d\n:", err);
			return err;
		}

		vlog("CUDA session timeout successfully set up with auto-stop %.3lfus from now.\n",
		     (cuda_sess_end_ts - (double)now) / 1000.0);

		if ((err = cuda_dump_kernel_event("test_cuda_kernel1",
				cuda_sess_start_ts + (cuda_sess_end_ts - cuda_sess_start_ts) / 10,
				cuda_sess_start_ts + 2 * (cuda_sess_end_ts - cuda_sess_start_ts) / 10)) < 0) {
			elog("Failed to add CUDA kernel launch event to dump: %d\n", err);
			return err;
		}
		break;
	default:
		elog("Unexpected message (kind %d)!\n", msg->kind);
		return -EINVAL;
	}
	return 0;
}

__weak int init_cupti_activities(void)
{
	/*
	 * Normally this function implementation will be resolved to the one
	 * in inj_cupti.c, unless CUPTI headers were not available during
	 * build time.
	 */
	elog("CUPTI functionality wasn't built into wprof!\n");
	return -EOPNOTSUPP;
}

__weak void finalize_cupti_activities(void)
{
}

static int handle_session_end(void)
{
	int err = 0;

	finalize_cupti_activities();

	/* exit and timer events are racing each other, we finalize just once */
	if (!cuda_dump)
		return 0;

	/* XXX: CUPTI flush/unsubscribe */

	if ((err = cuda_dump_kernel_event(
			"test_cuda_kernel2",
			cuda_sess_start_ts + 8 * (cuda_sess_end_ts - cuda_sess_start_ts) / 10,
			cuda_sess_start_ts + 9 * (cuda_sess_end_ts - cuda_sess_start_ts) / 10)) < 0) {
		elog("Failed to add CUDA kernel launch event to dump: %d\n", err);
		return err;
	}

	err = cuda_dump_finalize();
	if (err) {
		elog("Failed to finalize CUDA data dump: %d\n", err);
		return err;
	}

	fclose(cuda_dump);
	cuda_dump = NULL;

	return 0;
}


static int worker_thread_func(void *arg)
{
	int ret, err = 0;
	int run_ctx_memfd = -1;

	vlog("Worker thread started (TID %d, PID %d)\n", gettid(), getpid());

	int fds[MAX_UDS_FD_CNT] = { [0 ... MAX_UDS_FD_CNT - 1] = -1};
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
	} else if (ret == 0) {
		err = -EFAULT;
		elog("UDS recvmsg() returned ZERO, meaning tracer process died, cleaning up...\n");
		goto cleanup;
	} else if (ret != sizeof(struct inj_msg)) {
		err = -EPROTO;
		elog("UDS recvmsg() returned unexpected setup msg size %d (expecting %zd). Exiting!\n",
		     ret, sizeof(struct inj_msg));
		goto cleanup;
	}

	struct inj_msg *setup_msg = (void *)msg_buf;
	if (setup_msg->kind != INJ_MSG_SETUP) {
		err = -EFAULT;
		elog("Unexpected UDS message (kind %d) received, bailing...\n", setup_msg->kind);
		goto cleanup;
	}

	const int exp_fd_cnt = 2;
	if (setup_msg->setup.fd_cnt != exp_fd_cnt) {
		err = -E2BIG;
		elog("Unexpected number of FDs received for INJ_MSG_SETUP message (got %d, expected %d)\n",
		     setup_msg->setup.fd_cnt, exp_fd_cnt);
		goto cleanup;
	}

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	memcpy(fds, CMSG_DATA(cmsg), sizeof(*fds) * exp_fd_cnt);
	run_ctx_memfd = fds[0];
	workdir_fd = fds[1];

	/* fd[0] is memfd for run context */
	run_ctx = mmap(NULL, sizeof(struct inj_run_ctx), PROT_READ | PROT_WRITE, MAP_SHARED, run_ctx_memfd, 0);
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

	filelog = fdopen(log_fd, "w");
	if (!filelog) {
		err = -errno;
		elog("Failed to create FILE wrapper around log file '%s': %d\n", log_path, err);
		goto cleanup;
	}
	setlinebuf(filelog); /* line-buffered FILE for logging */

	vlog("Log setup completed successfully! wprof PID is %d.\n", setup_ctx->parent_pid);

	err = init_cupti_activities();
	if (err)
		goto cleanup;

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0) {
		err = -errno;
		elog("Failed to create epoll FD: %d\n", err);
		goto cleanup;
	}

	if ((err = epoll_add(epoll_fd, exit_fd, EPOLLIN, EK_EXIT)) < 0)
		goto cleanup;
	if ((err = epoll_add(epoll_fd, setup_ctx->uds_fd, EPOLLIN, EK_UDS)) < 0)
		goto cleanup;

	vlog("Waiting for exit or incoming commands...\n");

event_loop:
	struct epoll_event evs[8];
	int n = epoll_wait(epoll_fd, evs, ARRAY_SIZE(evs), -1);
	if (n < 0) {
		err = -errno;
		elog("epoll_wait() failed: %d\n", err);
		goto cleanup;
	}
	for (int i = 0; i < n; i++) {
		switch (evs[i].data.u32) {
		case EK_UDS:
			ret = recvmsg(setup_ctx->uds_fd, &msg, 0);
			if (ret < 0) {
				err = -errno;
				elog("UDS recvmsg() error (ret %d): %d\n", ret, err);
				goto cleanup;
			} else if (ret == 0) {
				err = -EFAULT;
				elog("UDS recvmsg() returned ZERO, meaning tracer process died, cleaning up...\n");
				goto cleanup;
			} else if (ret != sizeof(struct inj_msg)) {
				err = -EPROTO;
				elog("UDS recvmsg() returned unexpected message size %d (expecting %zd), exiting!\n",
				     ret, sizeof(struct inj_msg));
				goto cleanup;
			}

			struct inj_msg *m = (void *)msg_buf;
			err = handle_msg(m);
			if (err) {
				elog("Failure while handling message (kind %d): %d, exiting!\n", m->kind, err);
				goto cleanup;
			}
			break;
		case EK_TIMER: {
			long long expirations;
			(void)read(timer_fd, &expirations, sizeof(expirations));

			err = handle_session_end();
			if (err) {
				elog("Failed to cleanly handle CUDA session end: %d\n", err);
				goto cleanup;
			}

			vlog("CUDA session timer expired with %.3lfus delay after planned session end.\n",
			     (ktime_now_ns() - cuda_sess_end_ts) / 1000.0);
			break;
		}
		case EK_EXIT:
			long long unsigned tmp;
			(void)read(exit_fd, &tmp, sizeof(tmp));

			err = handle_session_end();
			if (err) {
				elog("Failed to cleanly handle CUDA session end: %d\n", err);
				goto cleanup;
			}

			vlog("Worker thread received exit signal (value %llu)\n", tmp);
			err = 0;
			goto cleanup;
		default:
			elog("Unrecognized epoll event from FD %d, exiting...\n", evs[i].data.fd);
			err = -EINVAL;
			goto cleanup;
		}
	}
	goto event_loop;

cleanup:
	vlog("Worker thread exiting...\n");

	zclose(exit_fd);
	zclose(setup_ctx->uds_fd);
	zclose(run_ctx_memfd);
	if (run_ctx && run_ctx != MAP_FAILED)
		munmap(run_ctx, sizeof(struct inj_run_ctx));
	zclose(workdir_fd);
	zclose(epoll_fd);
	zclose(timer_fd);

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

/*
 * XXX: this is a hacky way to make sure strset from libbpf can be used
 * without dragging in entire libbpf...
 */
void *libbpf_add_mem(void **data, size_t *cap_cnt, size_t elem_sz,
		     size_t cur_cnt, size_t max_cnt, size_t add_cnt)
{
	size_t new_cnt;
	void *new_data;

	if (cur_cnt + add_cnt <= *cap_cnt)
		return *data + cur_cnt * elem_sz;

	/* requested more than the set limit */
	if (cur_cnt + add_cnt > max_cnt)
		return NULL;

	new_cnt = *cap_cnt;
	new_cnt += new_cnt / 4;		  /* expand by 25% */
	if (new_cnt < 16)		  /* but at least 16 elements */
		new_cnt = 16;
	if (new_cnt > max_cnt)		  /* but not exceeding a set limit */
		new_cnt = max_cnt;
	if (new_cnt < cur_cnt + add_cnt)  /* also ensure we have enough memory */
		new_cnt = cur_cnt + add_cnt;

	new_data = realloc(*data, new_cnt * elem_sz);
	if (!new_data)
		return NULL;

	/* zero out newly allocated portion of memory */
	memset(new_data + (*cap_cnt) * elem_sz, 0, (new_cnt - *cap_cnt) * elem_sz);

	*data = new_data;
	*cap_cnt = new_cnt;
	return new_data + cur_cnt * elem_sz;
}

