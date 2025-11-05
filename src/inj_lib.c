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
		snprintf(final_fmt, sizeof(final_fmt), "WPROFINJ(%d): %s",
			 setup_ctx ? setup_ctx->tracee_pid : getpid(), fmt);

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

void *dyn_resolve_sym(const char *sym_name, void *dlopen_handle)
{
	void *sym;

	if (dlopen_handle) {
		sym = dlsym(dlopen_handle, sym_name);
		if (sym) {
			vlog("Found '%s' at %p in shared lib.\n", sym_name, sym);
			return sym;
		}
	}

	sym = dlsym(RTLD_DEFAULT, sym_name);
	if (sym) {
		vlog("Found '%s' at %p in global symbols table.\n", sym_name, sym);
		return sym;
	}

	elog("Failed to resolve '%s()'!\n", sym_name);
	return NULL;
}

#define WORKER_STACK_SIZE (256 * 1024)
#define UDS_MAX_MSG_LEN 1024

typedef unsigned long int pthread_t;

static int (*pthread_create)(pthread_t *thread, const void *attr, typeof(void *(void *)) *start_routine, void *arg);
static int (*pthread_join)(pthread_t thread, void **retval);
static bool use_pthread;
static pthread_t worker_pthread;

static pid_t inj_tid = -1;
static void *stack = NULL;
static int exit_fd = -1;
static pid_t worker_tid; /* for clone() and futex() only */
static int epoll_fd = -1;
static int timer_fd = -1;
static int log_fd = -1;

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

int cuda_dump_event(struct wcuda_event *e)
{
	if (fwrite(e, sizeof(*e), 1, cuda_dump) != 1) {
		int err = -errno;
		elog("Failed to fwrite() CUDA event: %d\n", err);
		return err;
	}

	return 0;
}

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

static int cuda_dump_setup(int dump_fd)
{
	int err = 0;

	cuda_dump_strs = strset__new(CUDA_DUMP_MAX_STRS_SZ, "", 1);

	cuda_dump = fdopen(dump_fd, "w");
	if (!cuda_dump) {
		err = -errno;
		elog("Failed to create FILE wrapper around dump FD %d: %d\n", dump_fd, err);
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

__weak int start_cupti_activities(void)
{
	return -EOPNOTSUPP;
}

__weak void finalize_cupti_activities(void)
{
}

static int handle_msg(struct inj_msg *msg, int *fds, int fd_cnt)
{
	int err = 0;

	switch (msg->kind) {
	case INJ_MSG_SETUP: {
		const int exp_fd_cnt = 2;
		if (fd_cnt != exp_fd_cnt) {
			elog("Unexpected number of FDs received for INJ_MSG_SETUP message (got %d, expected %d)\n",
			     fd_cnt, exp_fd_cnt);
			return -EPROTO;
		}

		int run_ctx_memfd = fds[0];
		int log_fd = fds[1];

		/* fd[0] is memfd for run context */
		run_ctx = mmap(NULL, sizeof(struct inj_run_ctx), PROT_READ | PROT_WRITE, MAP_SHARED,
			       run_ctx_memfd, 0);
		if (run_ctx == MAP_FAILED) {
			err = -errno;
			elog("Failed to mmap() provided run_ctx: %d\n", err);
			return err;
		}

		/* fd[1] is log file FD */
		filelog = fdopen(log_fd, "w");
		if (!filelog) {
			err = -errno;
			elog("Failed to create FILE wrapper around log FD %d: %d\n", log_fd, err);
			return err;
		}
		setlinebuf(filelog); /* line-buffered FILE for logging */

		vlog("Log setup completed successfully! wprof PID is %d.\n", setup_ctx->parent_pid);

		err = init_cupti_activities();
		if (err)
			return err;

		zclose(run_ctx_memfd);
		break;
	}
	case INJ_MSG_CUDA_SESSION: {
		__u64 now = ktime_now_ns();

		if (fd_cnt != 1) {
			err = -EPROTO;
			elog("Received CUDA_SESSION command, but not log_fd!\n");
			return err;
		}

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

		int dump_fd = fds[0];
		if ((err = cuda_dump_setup(dump_fd)) < 0) {
			elog("Failed to setup CUDA data dump: %d\n:", err);
			return err;
		}

		if ((err = start_cupti_activities()) < 0) {
			elog("Failed to start CUDA activity tracing: %d\n:", err);
			return err;
		}

		vlog("CUDA session timeout successfully set up with auto-stop %.3lfus from now.\n",
		     (cuda_sess_end_ts - (double)now) / 1000.0);

		break;
	}
	default:
		elog("Unexpected message (kind %d)!\n", msg->kind);
		return -EINVAL;
	}
	return 0;
}

static int handle_session_end(void)
{
	int err = 0;

	finalize_cupti_activities();

	/* exit and timer events are racing each other, we finalize just once */
	if (!cuda_dump)
		return 0;

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

	vlog("Worker thread started (TID %d, PID %d, REAL PID %d)\n",
	     gettid(), getpid(), setup_ctx->tracee_pid);

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

	vlog("Waiting commands or exit signal...\n");

	int *fds = NULL, fd_cnt = 0;
	struct iovec io = { .iov_base = msg_buf, .iov_len = sizeof(msg_buf) };
	char buf[CMSG_SPACE(sizeof(int) * MAX_UDS_FD_CNT)];
	struct msghdr msg = {
		.msg_iov = &io,
		.msg_iovlen = 1,
		.msg_control = buf,
		.msg_controllen = sizeof(buf),
	};

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

			fds = NULL;
			fd_cnt = 0;
			if (msg.msg_controllen > 0) {
				struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

				if (cmsg->cmsg_level != SOL_SOCKET ||
				    cmsg->cmsg_type != SCM_RIGHTS) {
					err = -EPROTO;
					elog("UDS recvmsg() returned unexpected cmsghdr type, exiting!\n");
					goto cleanup;
				}

				int fds_sz = cmsg->cmsg_len - CMSG_LEN(0);
				if (fds_sz > sizeof(fds) || fds_sz % sizeof(int) != 0) {
					err = -EPROTO;
					elog("UDS recvmsg() returned unexpected cmsghdr FDs payload (size %d), exiting!\n", fds_sz);
					goto cleanup;
				}

				fds = (int *)CMSG_DATA(cmsg);
				fd_cnt = fds_sz / sizeof(int);
			}

			struct inj_msg *m = (void *)msg_buf;

			vlog("Received UDS message kind %d (%s) with %d FD%s.\n",
			     m->kind, inj_msg_str(m->kind), fd_cnt, fd_cnt > 1 ? "s" : "");

			err = handle_msg(m, fds, fd_cnt);
			if (err) {
				for (int i = 0; i < fd_cnt; i++)
					close(fds[i]);
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
	if (!filelog)
		zclose(log_fd);
	zclose(epoll_fd);
	zclose(timer_fd);

	if (err)
		elog("Worker thread exited with ERROR %d.\n", err);
	else
		vlog("Worker thread exited successfully.\n");

	return err;
}

static void *worker_pthread_func(void *arg)
{
	return (void *)(long)worker_thread_func(arg);
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

	pthread_create = dyn_resolve_sym("pthread_create", NULL);
	pthread_join = dyn_resolve_sym("pthread_join", NULL);
	use_pthread = pthread_create && pthread_join;

	vlog("Using %s to manage worker thread!\n", use_pthread ? "libpthread" : "clone() syscall");

	if (use_pthread) {
		err = pthread_create(&worker_pthread, NULL, worker_pthread_func, NULL);
		if (err) {
			elog("Failed to create worker thread using libpthread: %d (errno %d)!\n", err, errno);
			goto err_out;
		}

		log("Worker thread created successfully using libpthread (PID %d)\n", getpid());
		return 0;
	} else {
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
	}
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

	if ((use_pthread && worker_pthread == 0) || (!use_pthread && inj_tid < 0)) {
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

	if (use_pthread) {
		void *worker_retval;

		vlog("Waiting for pthread_join() to return...\n");
		ret = pthread_join(worker_pthread, &worker_retval);
		if (ret)
			elog("pthread_join() returned error: %d (errno %d)\n", ret, errno);

	} else {
		vlog("Waiting for futex_wait() to return...\n");

		/* wait for worker thread to exit fully */
		while (*(volatile pid_t *)&worker_tid == inj_tid)
			syscall(SYS_futex, &worker_tid, FUTEX_WAIT, inj_tid, NULL, NULL, 0);

		/* now it's safe to munmap() thread's stack */
		if (stack) {
			(void)munmap(stack, WORKER_STACK_SIZE);
			stack = NULL;
		}
	}

	vlog("Worker thread teardown is complete.\n");
	inj_tid = -1;
	worker_pthread = 0;
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

