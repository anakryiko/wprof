// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <linux/futex.h>

#include "inj_common.h"
#include "inject.h"
#include "env.h"
#include "utils.h"
#include "sys.h"
#include "proc.h"
#include "elf_utils.h"

struct tracee_state {
	int pid;
	int pid_fd;
	char *proc_name;

	struct user_regs_struct orig_regs;

	long data_mmap_addr;
	size_t data_mmap_sz;
	long exec_mmap_addr;
	size_t exec_mmap_sz;

	int uds_local_fd;

	long dlopen_addr;
	long dlclose_addr;
	long dlsym_addr;

	long dlopen_handle;
	long inj_setup_addr;

	struct inj_run_ctx *run_ctx;
};

enum ptrace_state {
	PTRACE_STATE_DETACHED,
	PTRACE_STATE_ATTACHED,
	PTRACE_STATE_PENDING_SYSCALL,
};

#define elog(fmt, ...) eprintf("tracee(%d, %s): " fmt, tracee->pid, tracee->proc_name, ##__VA_ARGS__)
#define vlog(fmt, ...) vprintf("tracee(%d, %s): " fmt, tracee->pid, tracee->proc_name, ##__VA_ARGS__)
#define dlog(fmt, ...) dlogf(INJECTION, 1, "tracee(%d, %s): " fmt, tracee->pid, tracee->proc_name, ##__VA_ARGS__)
#define ddlog(fmt, ...) dlogf(INJECTION, 2, "tracee(%d, %s): " fmt, tracee->pid, tracee->proc_name, ##__VA_ARGS__)

#define LIBWPROFINJ_SETUP_SYM_NAME __str(LIBWPROFINJ_SETUP_SYM)

extern const char libwprofinj_so_start[];
extern const char libwprofinj_so_end[];
#define libwprofinj_so_sz ((size_t)(libwprofinj_so_end - libwprofinj_so_start))

extern char __inj_call[];
extern char __inj_call_end[];
extern char __inj_trap[];
#define __inj_call_sz ((size_t)(__inj_call_end - __inj_call))

/* function calling injection code */
void __attribute__((naked)) inj_call(void)
{
#ifdef __x86_64__
	/*
	 * rax: address of a function to call
	 * rdi, rsi, rdx, rcx, r8, r9: arguments passed to a function
	 */
	__asm__ __volatile__ (
	"__inj_call:					\n\t"
	"	call *%rax				\n\t"
	"__inj_trap:					\n\t"
	"	int3					\n\t"
	"__inj_call_end:				\n\t"
	);
#else
	__asm__ __volatile__ (
	"__inj_call:					\n\t"
	"__inj_trap:					\n\t"
	"__inj_call_end:				\n\t"
	);
#endif
}

static int find_libc(const struct tracee_state *tracee, long *out_start_addr, long *out_end_addr, char *path_buf, size_t path_buf_sz)
{
	long base_addr = 0;
	struct vma_info *vma;

	wprof_for_each(vma, vma, tracee->pid, VMA_QUERY_FILE_BACKED_VMA) {
		if (vma->vma_name[0] != '/')
			continue; /* special file, ignore */

		const char *libc_pos = strstr(vma->vma_name, "libc");
		if (libc_pos &&
		    libc_pos > vma->vma_name &&
		    libc_pos[-1] == '/' &&
		    (libc_pos[4] == '.' || libc_pos[4] == '-') &&
		    strstr(libc_pos, ".so")) {

			base_addr = vma->vma_start;
			if (out_start_addr)
				*out_start_addr = vma->vma_start;
			if (out_end_addr)
				*out_end_addr = vma->vma_end;
			if (path_buf)
				snprintf(path_buf, path_buf_sz, "%s", vma->vma_name);

			ddlog("Found libc mapping: %llx-%llx %llx (%s)\n",
			      vma->vma_start, vma->vma_end, vma->vma_offset, vma->vma_name);

			errno = 0;
			break;
		}
		errno = 0;
	}
	if (errno && (errno != ENOENT && errno != ESRCH)) {
		elog("Failed VMA iteration: %d\n", -errno);
		return -errno;
	}

	return base_addr != 0 ? 0 : -ESRCH;
}


static int remote_vm_write(const struct tracee_state *tracee, long remote_dst, const void *local_src, size_t sz)
{
	struct iovec local, remote;

	local.iov_base = (void *)local_src;
	local.iov_len = sz;

	remote.iov_base = (void *)remote_dst;
	remote.iov_len = sz;

	if (process_vm_writev(tracee->pid, &local, 1, &remote, 1, 0) != (ssize_t)sz) {
		dlog("Failed to process_vm_writev() of %zu bytes: %d\n", sz, -errno);
		return -errno;
	}

	return 0;
}

static int remote_vm_read(const struct tracee_state *tracee, const void *local_dst, long remote_src, size_t sz)
{
	struct iovec local, remote;

	local.iov_base = (void *)local_dst;
	local.iov_len = sz;

	remote.iov_base = (void *)remote_src;
	remote.iov_len = sz;

	if (process_vm_readv(tracee->pid, &local, 1, &remote, 1, 0) != (ssize_t)sz) {
		dlog("Failed to process_vm_readv() of %zu bytes: %d\n", sz, -errno);
		return -errno;
	}

	return 0;
}

static int ptrace_get_regs(const struct tracee_state *tracee, struct user_regs_struct *regs)
{
	if (ptrace(PTRACE_GETREGS, tracee->pid, NULL, regs) < 0) {
		dlog("ptrace(PTRACE_GETREGS) failed: %d\n", -errno);
		return -errno;
	}
	ddlog("ptrace(PTRACE_GETREGS)\n");
	return 0;
}

static int ptrace_set_regs(const struct tracee_state *tracee, const struct user_regs_struct *regs)
{
	if (ptrace(PTRACE_SETREGS, tracee->pid, NULL, regs) < 0) {
		dlog("ptrace(PTRACE_SETREGS) failed: %d\n", -errno);
		return -errno;
	}
	ddlog("ptrace(PTRACE_SETREGS)\n");
	return 0;
}

static int ptrace_set_options(const struct tracee_state *tracee, int options)
{
	if (ptrace(PTRACE_SETOPTIONS, tracee->pid, NULL, options) < 0) {
		dlog("ptrace(PTRACE_SETOPTIONS, opts %x) failed: %d\n", options, -errno);
		return -errno;
	}
	ddlog("PTRACE_SET_OPTIONS(%x)\n", options);
	return 0;
}

static int ptrace_op(const struct tracee_state *tracee, enum __ptrace_request op, long data)
{
	const char *op_name;

	switch (op) {
	case PTRACE_TRACEME: op_name = "PTRACE_TRACEME"; break;
	case PTRACE_ATTACH: op_name = "PTRACE_ATTACH"; break;
	case PTRACE_DETACH: op_name = "PTRACE_DETACH"; break;
	case PTRACE_CONT: op_name = "PTRACE_CONT"; break;
	case PTRACE_LISTEN: op_name = "PTRACE_LISTEN"; break;
	case PTRACE_SEIZE: op_name = "PTRACE_SEIZE"; break;
	case PTRACE_INTERRUPT: op_name = "PTRACE_INTERRUPT"; break;
	case PTRACE_SINGLESTEP: op_name = "PTRACE_SINGLESTEP"; break;
	case PTRACE_SYSCALL: op_name = "PTRACE_SYSCALL"; break;
	default: op_name = "???";
	}

	if (ptrace(op, tracee->pid, NULL, data) < 0) {
		dlog("ptrace(%s) failed: %d\n", op_name, -errno);
		return -errno;
	}

	ddlog("%s\n", op_name);
	return 0;
}

static int __ptrace_wait(const struct tracee_state *tracee, int signal, bool ptrace_event, long ip)
{
	int status, err;

	while (true) {
		if (waitpid(tracee->pid, &status, __WALL) != tracee->pid) {
			dlog("waitpid() failed: %d\n", -errno);
			return -errno;
		}

		if (WIFEXITED(status)) {
			dlog("WIFEXITED()\n");
			return -ENOENT;
		}

		if (WIFSTOPPED(status) &&
		   (!ptrace_event || (status >> 16) == PTRACE_EVENT_STOP) &&
		    WSTOPSIG(status) == signal) {
			if (ip) {
				struct user_regs_struct regs;

				err = ptrace_get_regs(tracee, &regs);
				if (err)
					return err;

				/* XXX: RIP - 1 is x86-64 specific for trapping insn address */
				/* XXX: this logic is SIGTRAP specific */
				if (regs.rip - 1 != ip) {
					elog("UNEXPECTED IP %llx (expecting %lx) for STOPSIG=%d (%s), PASSING THROUGH BACK TO APP!\n",
					     regs.rip - 1, ip,
					     WSTOPSIG(status), sig_name(WSTOPSIG(status)));
					goto pass_through;
				}
			}

			ddlog("STOPPED%s PID=%d STOPSIG=%d (%s)\n",
			      ptrace_event ? " (PTRACE_EVENT_STOP)" : "",
			      tracee->pid, WSTOPSIG(status), sig_name(WSTOPSIG(status)));
			return 0;
		}

		dlog("PASS-THROUGH SIGNAL %d (%s) (status %x) BACK TO PID %d\n",
		     WSTOPSIG(status), sig_name(WSTOPSIG(status)), status, tracee->pid);
pass_through:
		err = ptrace_op(tracee, PTRACE_CONT, WSTOPSIG(status));
		if (err)
			return err;
	}
}

static int ptrace_wait_stop(const struct tracee_state *tracee)
{
	return __ptrace_wait(tracee, SIGTRAP, true /* PTRACE_EVENT_STOP */, 0);
}

static int ptrace_wait_trap(const struct tracee_state *tracee, long ip)
{
	return __ptrace_wait(tracee, SIGTRAP, false /* !PTRACE_EVENT_STOP */, ip);
}

static int ptrace_wait_syscall(const struct tracee_state *tracee)
{
	return __ptrace_wait(tracee, SIGTRAP | 0x80, false /* !PTRACE_EVENT_STOP */, 0);
}

static int ptrace_restart_syscall(const struct tracee_state *tracee)
{
	int err = 0;

	err = err ?: ptrace_set_regs(tracee, &tracee->orig_regs);
	err = err ?: ptrace_op(tracee, PTRACE_SYSCALL, 0);
	err = err ?: ptrace_wait_syscall(tracee);

	return err;
}

static int ptrace_exec_syscall(const struct tracee_state *tracee,
			       const struct user_regs_struct *pre_regs,
			       long *res)
{
	struct user_regs_struct post_regs;
	int err = 0;

	err = err ?: ptrace_set_regs(tracee, pre_regs);
	err = err ?: ptrace_op(tracee, PTRACE_SYSCALL, 0);
	err = err ?: ptrace_wait_syscall(tracee);
	err = err ?: ptrace_get_regs(tracee, &post_regs);
	err = err ?: ptrace_restart_syscall(tracee);

	/* XXX: ARCH SPECIFIC */
	if (!err)
		*res = post_regs.rax;

	return err;
}

static int ptrace_intercept(const struct tracee_state *tracee, struct user_regs_struct *regs)
{
	int err = 0;
	/*
	 * Attach to tracee
	 */
	dlog("Seizing...\n");
	if ((err = ptrace_op(tracee, PTRACE_SEIZE, 0)) < 0)
		return err;

	if ((err = ptrace_op(tracee, PTRACE_INTERRUPT, 0)) < 0)
		goto err_detach;
	if ((err = ptrace_wait_stop(tracee)) < 0)
		goto err_detach;
	/*
	 * Take over next syscall
	 */
	dlog("Resuming until syscall...\n");
	if ((err = ptrace_set_options(tracee, PTRACE_O_TRACESYSGOOD)) < 0)
		goto err_detach;
	if ((err = ptrace_op(tracee, PTRACE_SYSCALL, 0)) < 0)
		goto err_detach;
	if ((err = ptrace_wait_syscall(tracee)) < 0)
		goto err_detach;
	/* backup original registers */
	if ((err = ptrace_get_regs(tracee, regs)) < 0)
		goto err_detach;

	/* XXX: arm64 will need something else */
	regs->rip -= 2; /* adjust for syscall replay, syscall instruction is 2 bytes */
	return 0;

err_detach:
	(void)ptrace_op(tracee, PTRACE_DETACH, 0);
	return err;
}

static int tracee_dlclose(const struct tracee_state *tracee, long dl_handle)
{
	struct user_regs_struct regs;
	long inj_trap_addr = tracee->exec_mmap_addr + __inj_trap - __inj_call;
	int err;

	/* int dlclose(void *handle); */
	regs = tracee->orig_regs;
	/* XXX: arch specific */
	regs.orig_rax = -1; /* cancel pending syscall continuation, if any */
	regs.rip = tracee->exec_mmap_addr;
	regs.rax = tracee->dlclose_addr;
	regs.rdi = dl_handle;
	/* XXX: arch specific */
	regs.rsp = (regs.rsp & ~0xFULL) - 128; /* ensure 16-byte alignment and set up red zone */

	if ((err = ptrace_set_regs(tracee, &regs)) < 0)
		return err;
	if ((err = ptrace_op(tracee, PTRACE_CONT, 0)) < 0)
		return err;
	if ((err = ptrace_wait_trap(tracee, inj_trap_addr)) < 0)
		return err;
	if ((err = ptrace_get_regs(tracee, &regs)) < 0)
		return err;

	long dlclose_res = regs.rax;
	if (dlclose_res != 0) {
		elog("Failed to dlclose() injection library (result %ld)!\n", dlclose_res);
		return -EFAULT;
	}

	return 0;
}

static int tracee_munmap(const struct tracee_state *tracee, long mmap_addr, int mmap_sz, bool restart_syscall)
{
	struct user_regs_struct regs;
	int err;

	/* int munmap(void *addr, size_t len); */
	regs = tracee->orig_regs;
	regs.orig_rax = __NR_munmap;
	regs.rdi = mmap_addr; /* addr */
	regs.rsi = mmap_sz; /* size */

	if (restart_syscall) {
		if ((err = ptrace_restart_syscall(tracee)) < 0)
			return err;
	}

	long munmap_ret;
	if ((err = ptrace_exec_syscall(tracee, &regs, &munmap_ret)) < 0)
		return err;

	if (munmap_ret < 0) {
		elog("munmap() inside tracee failed: %ld, bailing!\n", munmap_ret);
		return munmap_ret;
	}
	return 0;
}

static int tracee_purge_leftovers(const struct tracee_state *tracee, long setup_ctx_addr, struct inj_setup_ctx *old_ctx)
{
	int err;

	vlog("Attempting to purge leftover injection w/ setup ctx at %lx...\n", setup_ctx_addr);

	err = remote_vm_read(tracee, old_ctx, setup_ctx_addr, sizeof(*old_ctx));
	if (err < 0) {
		elog("Failed to fetch setup context of previous injection at %lx: %d\n", setup_ctx_addr, err);
		return err;
	}

	if (old_ctx->version != LIBWPROFINJ_VERSION) {
		elog("Leftover injection context is of incompatible version %d (expecting %d), bailing!\n",
		     old_ctx->version, LIBWPROFINJ_VERSION);
		return -EOPNOTSUPP;
	}

	vlog("Leftover injection context: mmap_sz %d lib_handle %lx parent_pid %d\n",
	     old_ctx->mmap_sz, old_ctx->lib_handle, old_ctx->parent_pid);

	err = tracee_dlclose(tracee, old_ctx->lib_handle);
	if (err) {
		elog("Failed to dlclose() leftover libwprofinj.so w/ lib handle %lx and setup ctx at %lx: %d!\n",
		     old_ctx->lib_handle, setup_ctx_addr, err);
		return err;
	}
	err = tracee_munmap(tracee, setup_ctx_addr, old_ctx->mmap_sz, true /* restart_syscall */);
	if (err) {
		elog("Failed to munmap() leftover libwprofinj.so setup context at %lx: %d!\n", setup_ctx_addr, err);
		return err;
	}

	vlog("Leftover injection w/ setup ctx at %lx (parent PID %d) successfully purged!\n",
	      setup_ctx_addr, old_ctx->parent_pid);

	return 0;
}

struct tracee_state *tracee_inject(int pid)
{
	struct tracee_state *tracee;
	struct user_regs_struct regs;
	u64 start_ts = ktime_now_ns();
	int err = 0, pid_fd = -1, memfd_local_fd = -1;
	enum ptrace_state ptrace_state = PTRACE_STATE_DETACHED;

	tracee = calloc(1, sizeof(*tracee));
	tracee->pid = pid;
	tracee->proc_name = strdup(proc_name(pid));
	tracee->uds_local_fd = -1;

	/* We need pidfd to open tracee's FDs later on */
	pid_fd = sys_pidfd_open(pid, 0);
	if (pid_fd < 0) {
		elog("pidfd_open() failed: %d\n", -errno);
		goto cleanup;
	}

	/*
	 * Find dlopen(), dlclose(), dlsym() addresses (on tracee side)
	 */
	char libc_path[PATH_MAX];
	long libc_start = 0, libc_end = 0;
	err = find_libc(tracee, &libc_start, &libc_end, libc_path, sizeof(libc_path));
	if (err) {
		elog("Failed to find libc address: %d\n", -errno);
		goto cleanup;
	}

	char lib_path[128];
	snprintf(lib_path, sizeof(lib_path), "/proc/%d/map_files/%lx-%lx", pid, libc_start, libc_end);
	const char *sym_names[] = {"dlopen", "dlclose", "dlsym"};
	long sym_addrs[] = {0, 0, 0};
	err = elf_find_syms(lib_path, STT_FUNC, sym_names, sym_addrs, ARRAY_SIZE(sym_names));
	if (err) {
		elog("Failed to find dlopen/dlclose/dlsym symbols: %d\n", err);
		goto cleanup;
	}
	long dlopen_tracee_off = sym_addrs[0];
	long dlclose_tracee_off = sym_addrs[1];
	long dlsym_tracee_off = sym_addrs[2];

	tracee->dlopen_addr = libc_start + dlopen_tracee_off;
	tracee->dlclose_addr = libc_start + dlclose_tracee_off;
	tracee->dlsym_addr = libc_start + dlsym_tracee_off;

	dlog("Remote libc found at '%s' base 0x%lx (dlopen off %lx -> %lx, dlclose off %lx -> %lx, dlsym off %lx -> %lx)\n",
	     libc_path, libc_start,
	     dlopen_tracee_off, tracee->dlopen_addr,
	     dlclose_tracee_off, tracee->dlclose_addr,
	     dlsym_tracee_off, tracee->dlsym_addr);

	u64 ptrace_start_ts = ktime_now_ns();

	if ((err = ptrace_intercept(tracee, &tracee->orig_regs)) < 0)
		goto cleanup;
	ptrace_state = PTRACE_STATE_PENDING_SYSCALL;

	u64 ptrace_intercept_ts = ktime_now_ns();

	/*
	 * Inject mmap() syscall
	 */
	const long page_size = sysconf(_SC_PAGESIZE);
	tracee->data_mmap_sz = page_size;
	tracee->exec_mmap_sz = page_size;

	dlog("Executing mmap()...\n");
	/* void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset); */
	regs = tracee->orig_regs;
	regs.orig_rax = __NR_mmap;
	regs.rdi = 0; /* addr */
	regs.rsi = tracee->data_mmap_sz + tracee->exec_mmap_sz; /* length */
	regs.rdx = PROT_WRITE | PROT_READ; /* prot */
	regs.r10 = MAP_ANONYMOUS | MAP_PRIVATE; /* flags */
	regs.r8 = 0; /* fd */
	regs.r9 = 0; /* offset */

	if ((err = ptrace_exec_syscall(tracee, &regs, &tracee->data_mmap_addr)) < 0)
		goto cleanup;
	if (tracee->data_mmap_addr <= 0) {
		elog("mmap() inside tracee failed: %ld, bailing!\n", tracee->data_mmap_addr);
		goto cleanup;
	}

	tracee->exec_mmap_addr = tracee->data_mmap_addr + tracee->data_mmap_sz;
	dlog("mmap() returned 0x%lx (data @ %lx, code @ %lx)\n",
	     (long)tracee->data_mmap_addr, (long)tracee->data_mmap_addr, (long)tracee->exec_mmap_addr);

	/*
	 * Setup executable function call trampoline by copying inj_call()
	 * code into (soon-to-be) executable mmap()'ed memory
	 */
	if ((err = remote_vm_write(tracee, tracee->exec_mmap_addr, __inj_call, __inj_call_sz)) < 0)
		goto cleanup;

	/*
	 * Inject mprotect(r-x) syscall
	 */
	dlog("Executing mprotect(r-xp)...\n");
	/* int mprotect(void *addr, size_t size, int prot); */
	regs = tracee->orig_regs;
	regs.orig_rax = __NR_mprotect;
	regs.rdi = tracee->exec_mmap_addr; /* addr */
	regs.rsi = tracee->exec_mmap_sz; /* size */
	regs.rdx = PROT_EXEC | PROT_READ; /* prot */

	long mprotect_ret;
	if ((err = ptrace_exec_syscall(tracee, &regs, &mprotect_ret)) < 0)
		goto cleanup;
	if (mprotect_ret < 0) {
		elog("mprotect(r-x) inside tracee failed: %ld, bailing!\n", mprotect_ret);
		goto cleanup;
	}

	/*
	 * Inject memfd_create() syscall
	 */
	dlog("Executing memfd_create()...\n");

	char memfd_name[] = "wprof-injection";
	if ((err = remote_vm_write(tracee, tracee->data_mmap_addr, memfd_name, sizeof(memfd_name))) < 0)
		goto cleanup;

	/* int memfd_create(const char *name, unsigned int flags); */
	regs = tracee->orig_regs;
	regs.orig_rax = __NR_memfd_create;
	regs.rdi = tracee->data_mmap_addr; /* name */
	regs.rsi = MFD_CLOEXEC; /* flags */

	long memfd_remote_fd;
	if ((err = ptrace_exec_syscall(tracee, &regs, &memfd_remote_fd)) < 0)
		goto cleanup;
	if (memfd_remote_fd < 0) {
		elog("memfd_create() inside tracee failed: %ld, bailing!\n", memfd_remote_fd);
		goto cleanup;
	}
	dlog("memfd_create() result: %ld\n", memfd_remote_fd);

	/*
	 * Inject socketpair(AF_UNIX, SOCK_STREAM)
	 */
	dlog("Executing socketpair(AF_UNIX, SOCK_STREAM)...\n");

	/* int socketpair(int domain, int type, int protocol, int sv[2]); */
	regs = tracee->orig_regs;
	regs.orig_rax = __NR_socketpair;
	regs.rdi = AF_UNIX; /* domain */
	regs.rsi = SOCK_STREAM; /* length */
	regs.rdx = 0; /* protocol */
	regs.r10 = tracee->data_mmap_addr; /* sv */

	long sockpair_ret;
	if ((err = ptrace_exec_syscall(tracee, &regs, &sockpair_ret)) < 0)
		goto cleanup;
	if (sockpair_ret != 0) {
		elog("socketpair(AF_UNIX, SOCK_STREAM) failed: %ld\n", sockpair_ret);
		goto cleanup;
	}

	int uds_remote_fds[2];
	err = remote_vm_read(tracee, uds_remote_fds, tracee->data_mmap_addr, sizeof(uds_remote_fds));
	if (err)
		goto cleanup;
	dlog("socket_pair() FDs = {%d, %d}\n", uds_remote_fds[0], uds_remote_fds[1]);

	tracee->uds_local_fd = sys_pidfd_getfd(pid_fd, uds_remote_fds[0], 0);
	if (tracee->uds_local_fd < 0) {
		elog("pidfd_getfd(remote_fd %d) failed: %d\n", uds_remote_fds[0], -errno);
		goto cleanup;
	}
	dlog("pidfd_getfd() returned UDS FD %d for tracer\n", tracee->uds_local_fd);

	u64 ptrace_prepped_ts = ktime_now_ns();

	/* Open tracee's allocated FD for shared lib code */
	memfd_local_fd = sys_pidfd_getfd(pid_fd, memfd_remote_fd, 0);
	if (memfd_local_fd < 0) {
		elog("pidfd_getfd(remote_fd %ld) failed: %d\n", memfd_remote_fd, -errno);
		goto cleanup;
	}
	err = ftruncate(memfd_local_fd, libwprofinj_so_sz);
	if (err) {
		elog("Failed to ftruncate() memfd to %ld bytes: %d\n", libwprofinj_so_sz, -errno);
		goto cleanup;
	}
	/* Copy over contents of libinj.so into memfd file */
	void *libinj_so_mem = mmap(NULL, libwprofinj_so_sz, PROT_READ | PROT_WRITE, MAP_SHARED,
				   memfd_local_fd, 0);
	if (libinj_so_mem == MAP_FAILED) {
		elog("Failed to mmap() libinj.so destination memfd file: %d\n", -errno);
		goto cleanup;
	}
	memcpy(libinj_so_mem, libwprofinj_so_start, libwprofinj_so_sz);
	(void)munmap(libinj_so_mem, libwprofinj_so_sz);
	libinj_so_mem = NULL;

reattempt_dlopen:
	dlog("Inject dlopen() call...\n");
	long inj_trap_addr = tracee->exec_mmap_addr + __inj_trap - __inj_call;

	/* Copy over memfd path for passing into dlopen() */
	char memfd_path[64];
	snprintf(memfd_path, sizeof(memfd_path), "/proc/self/fd/%ld", memfd_remote_fd);
	if ((err = remote_vm_write(tracee, tracee->data_mmap_addr, memfd_path, sizeof(memfd_path))) < 0)
		goto cleanup;

	/* void *dlopen(const char *path, int flags); */
	regs = tracee->orig_regs;
	/* XXX: arch specific */
	regs.orig_rax = -1; /* cancel pending syscall continuation, if any */
	regs.rip = tracee->exec_mmap_addr;
	regs.rax = tracee->dlopen_addr;
	regs.rdi = tracee->data_mmap_addr; /* name */
	regs.rsi = RTLD_NOW | RTLD_LOCAL; /* flags */
	/* XXX: arch specific */
	regs.rsp = (regs.rsp & ~0xFULL) - 128; /* ensure 16-byte alignment and set up red zone */

	if ((err = ptrace_set_regs(tracee, &regs)) < 0)
		goto cleanup;
	if ((err = ptrace_op(tracee, PTRACE_CONT, 0)) < 0)
		goto cleanup;
	if ((err = ptrace_wait_trap(tracee, inj_trap_addr)) < 0)
		goto cleanup;
	if ((err = ptrace_get_regs(tracee, &regs)) < 0)
		goto cleanup;

	tracee->dlopen_handle = regs.rax;
	if (tracee->dlopen_handle == 0) {
		elog("Failed to dlopen() injection library!\n");
		goto cleanup;
	}
	dlog("dlopen() result: %lx\n", tracee->dlopen_handle);

reattempt_setup:
	dlog("Resolving __libinj_setup() through dlsym()...\n");
	if ((err = remote_vm_write(tracee, tracee->data_mmap_addr, LIBWPROFINJ_SETUP_SYM_NAME,
				   sizeof(LIBWPROFINJ_SETUP_SYM_NAME))) < 0)
		goto cleanup;

	/* void *dlsym(void *restrict handle, const char *restrict symbol); */
	regs = tracee->orig_regs;
	regs.orig_rax = -1; /* cancel pending syscall continuation, if any */
	regs.rip = tracee->exec_mmap_addr;
	regs.rax = tracee->dlsym_addr;
	regs.rdi = tracee->dlopen_handle; /* handle */
	regs.rsi = tracee->data_mmap_addr; /* symbol */
	regs.rsp = (regs.rsp & ~0xFULL) - 128; /* ensure 16-byte alignment and set up red zone */

	if ((err = ptrace_set_regs(tracee, &regs)) < 0)
		goto cleanup;
	if ((err = ptrace_op(tracee, PTRACE_CONT, 0)) < 0)
		goto cleanup;
	if ((err = ptrace_wait_trap(tracee, inj_trap_addr)) < 0)
		goto cleanup;
	if ((err = ptrace_get_regs(tracee, &regs)) < 0)
		goto cleanup;

	tracee->inj_setup_addr = regs.rax;
	if (tracee->inj_setup_addr == 0) {
		elog("Failed to find '%s' using dlsym()...\n", LIBWPROFINJ_SETUP_SYM_NAME);
		goto cleanup;
	}
	dlog("dlsym() returned address of %s(): %lx\n", LIBWPROFINJ_SETUP_SYM_NAME, tracee->inj_setup_addr);

	dlog("Setting up injected context calling into %s()...\n", LIBWPROFINJ_SETUP_SYM_NAME);
	struct inj_setup_ctx setup_ctx = {
		.version = LIBWPROFINJ_VERSION,
		.mmap_sz = tracee->data_mmap_sz + tracee->exec_mmap_sz,
		.lib_handle = tracee->dlopen_handle,
		.parent_pid = getpid(),
		.stderr_verbosity = 3, /* debug level */
		.filelog_verbosity = 3, /* debug level */
		.uds_fd = uds_remote_fds[1],
		.uds_parent_fd = uds_remote_fds[0],
		.lib_mem_fd = memfd_remote_fd,
	};
	if ((err = remote_vm_write(tracee, tracee->data_mmap_addr, &setup_ctx, sizeof(setup_ctx))) < 0)
		goto cleanup;

	/* int __libinj_setup(struct inj_init_ctx *ctx) */
	regs = tracee->orig_regs;
	regs.orig_rax = -1;
	regs.rip = tracee->exec_mmap_addr;
	regs.rax = tracee->inj_setup_addr;
	regs.rdi = tracee->data_mmap_addr; /* ctx */
	regs.rsp = (regs.rsp & ~0xFULL) - 128; /* ensure 16-byte alignment and set up red zone */

	if ((err = ptrace_set_regs(tracee, &regs)) < 0)
		goto cleanup;
	if ((err = ptrace_op(tracee, PTRACE_CONT, 0)) < 0)
		goto cleanup;
	if ((err = ptrace_wait_trap(tracee, inj_trap_addr)) < 0)
		goto cleanup;
	if ((err = ptrace_get_regs(tracee, &regs)) < 0)
		goto cleanup;

	long inj_setup_res = regs.rax;
	if (inj_setup_res == 0) {
		elog("Injection init call %s() failed (result %lx), bailing!\n",
		     LIBWPROFINJ_SETUP_SYM_NAME, inj_setup_res);
		goto cleanup;
	} else if (inj_setup_res != tracee->data_mmap_addr) {
		struct inj_setup_ctx old_ctx = {};

		err = tracee_purge_leftovers(tracee, inj_setup_res, &old_ctx);
		if (err) {
			elog("Purging leftover previous injection w/ setup ctx at %lx failed: %d, bailing!\n",
			     inj_setup_res, err);
			goto cleanup;
		}
		tracee->inj_setup_addr = 0;

		/*
		 * We can get unlucky and happen to use **exactly the same FD**
		 * for memfd (with libwprofinj.so contents) as previous
		 * instance of wprof that left libwprofinj.so loaded
		 * (presumably due to crash or buggy clean up).
		 *
		 * In such case, tracee's libc will just blindly reused cached
		 * previous libwprofinj.so, because its cache is based purely
		 * on file path, which in out case will be exactly the same
		 * /proc/self/fd/<memfd>, which is very unfortunate but there
		 * doesn't seem to be any clean way to 100% guarantee this can
		 * never happen.
		 *
		 * So, in an unlikely case (which isn't actually unlikely
		 * during local development due to exact FD allocation
		 * sequence between two attempts to inject, but I digress...)
		 * that such occurence happens, we need to dlclose()
		 * our tracee->dlopen_handle to make sure tracee's libc
		 * actually unload the library (due to last dropped refcount),
		 * and start over again with dlopen().
		 *
		 * No big deal.
		 */
		if (old_ctx.lib_handle == tracee->dlopen_handle) {
			err = tracee_dlclose(tracee, tracee->dlopen_handle);
			if (err) {
				elog("Failed dlclose() of own dlopen()-returend libwprofinj.so handle, bailing!\n");
				goto cleanup;
			}
			tracee->dlopen_handle = 0;
			goto reattempt_dlopen;
		}
		goto reattempt_setup;
	}
	dlog("Injection init %s() call succeeded!\n", LIBWPROFINJ_SETUP_SYM_NAME);

	/* 
	 * Prepare for execution of the original intercepted syscall
	 */
	dlog("Replaying original syscall and detaching tracee...\n");
	if ((err = ptrace_restart_syscall(tracee)) < 0)
		goto cleanup;
	ptrace_state = PTRACE_STATE_ATTACHED;
	if ((err = ptrace_op(tracee, PTRACE_DETACH, 0)) < 0)
		goto cleanup;
	ptrace_state = PTRACE_STATE_DETACHED;

	u64 ptrace_injected_ts = ktime_now_ns();

	dlog("PTRACE INJECTION TIMING:\n"
	     "\tprep\t%.3lfus,\n"
	     "\tattach\t%.3lfus,\n"
	     "\tsetup:\t%.3lfus,\n"
	     "\tinject:\t%.3lfus,\n"
	     "\ttotal:\t%.3lfus\n",
	     (ptrace_start_ts - start_ts) / 1000.0,
	     (ptrace_intercept_ts - ptrace_start_ts) / 1000.0,
	     (ptrace_prepped_ts - ptrace_intercept_ts) / 1000.0,
	     (ptrace_injected_ts - ptrace_prepped_ts) / 1000.0,
	     (ptrace_injected_ts - start_ts) / 1000.0);

	zclose(pid_fd);
	zclose(memfd_local_fd);

	return tracee;

cleanup:
	switch (ptrace_state) {
	case PTRACE_STATE_PENDING_SYSCALL:
		dlog("Trying to restore & replay the original syscall...\n");
		(void)ptrace_restart_syscall(tracee);
		/* fallthrough */
	case PTRACE_STATE_ATTACHED:
		dlog("Trying to detach tracee...\n");
		(void)ptrace_op(tracee, PTRACE_DETACH, 0);
		break;
	default:
	}
	zclose(pid_fd);
	zclose(memfd_local_fd);
	zclose(tracee->uds_local_fd);
	free(tracee->proc_name);
	free(tracee);
	errno = -err;
	return NULL;
}

int tracee_retract(struct tracee_state *tracee)
{
	enum ptrace_state ptrace_state = PTRACE_STATE_DETACHED;
	struct user_regs_struct regs;
	int err = 0;

	/* notify child we are pulling back */
	zclose(tracee->uds_local_fd);

	u64 ptrace_start_ts = ktime_now_ns();

	if ((err = ptrace_intercept(tracee, &tracee->orig_regs)) < 0)
		goto cleanup;
	ptrace_state = PTRACE_STATE_PENDING_SYSCALL;

	u64 ptrace_attached_ts = ktime_now_ns();

	/*
	 * Inject dlclose(libwprofinj.so)
	 */
	dlog("Executing dlclose(libwprofinj.so)...\n");
	long inj_trap_addr = tracee->exec_mmap_addr + __inj_trap - __inj_call;

	/* int dlclose(void *handle); */
	regs = tracee->orig_regs;
	/* XXX: arch specific */
	regs.orig_rax = -1; /* cancel pending syscall continuation */
	regs.rip = tracee->exec_mmap_addr;
	regs.rax = tracee->dlclose_addr;
	regs.rdi = tracee->dlopen_handle;
	/* XXX: arch specific */
	regs.rsp = (regs.rsp & ~0xFULL) - 128; /* ensure 16-byte alignment and set up red zone */

	if ((err = ptrace_set_regs(tracee, &regs)) < 0)
		goto cleanup;
	if ((err = ptrace_op(tracee, PTRACE_CONT, 0)) < 0)
		goto cleanup;
	if ((err = ptrace_wait_trap(tracee, inj_trap_addr)) < 0)
		goto cleanup;
	if ((err = ptrace_get_regs(tracee, &regs)) < 0)
		goto cleanup;

	long dlclose_res = regs.rax;
	if (dlclose_res != 0) {
		elog("Failed to dlclose() injection library (result %ld)!\n", dlclose_res);
		goto cleanup;
	}

	u64 ptrace_dlclosed_ts = ktime_now_ns();

	/*
	 * Inject munmap() syscall
	 */
	dlog("Executing munmap()...\n");
	/* int munmap(void *addr, size_t len); */
	regs = tracee->orig_regs;
	regs.orig_rax = __NR_munmap;
	regs.rdi = tracee->data_mmap_addr; /* addr */
	regs.rsi = tracee->data_mmap_sz + tracee->exec_mmap_sz; /* size */

	long munmap_ret;
	if ((err = ptrace_restart_syscall(tracee)) < 0)
		goto cleanup;
	if ((err = ptrace_exec_syscall(tracee, &regs, &munmap_ret)) < 0)
		goto cleanup;
	if (munmap_ret < 0) {
		elog("munmap() inside tracee failed: %ld, bailing!\n", munmap_ret);
		goto cleanup;
	}

	ptrace_state = PTRACE_STATE_ATTACHED;

	u64 ptrace_unmapped_ts = ktime_now_ns();

	/* 
	 * Prepare for execution of the original intercepted syscall
	 */
	dlog("Replaying original syscall and detaching tracee...\n");
	if ((err = ptrace_op(tracee, PTRACE_DETACH, 0)) < 0)
		goto cleanup;
	ptrace_state = PTRACE_STATE_DETACHED;

	u64 ptrace_retracted_ts = ktime_now_ns();

	dlog("PTRACE RETRACTION TIMING:\n"
	     "\tattach:\t%.3lfus,\n"
	     "\tunload:\t%.3lfus,\n"
	     "\tmunmap:\t%.3lfus,\n"
	     "\treplay:\t%.3lfus,\n"
	     "\ttotal:\t%.3lfus\n",
	     (ptrace_attached_ts - ptrace_start_ts) / 1000.0,
	     (ptrace_dlclosed_ts - ptrace_attached_ts) / 1000.0,
	     (ptrace_unmapped_ts - ptrace_dlclosed_ts) / 1000.0,
	     (ptrace_retracted_ts - ptrace_unmapped_ts) / 1000.0,
	     (ptrace_retracted_ts - ptrace_start_ts) / 1000.0);

	return 0;
cleanup:
	switch (ptrace_state) {
	case PTRACE_STATE_PENDING_SYSCALL:
		dlog("Trying to restore & replay the original syscall...\n");
		(void)ptrace_restart_syscall(tracee);
		/* fallthrough */
	case PTRACE_STATE_ATTACHED:
		dlog("Trying to detach tracee...\n");
		(void)ptrace_op(tracee, PTRACE_DETACH, 0);
		break;
	default:
	}
	return err;
}

void tracee_free(struct tracee_state *tracee)
{
	if (!tracee)
		return;
	free(tracee->proc_name);
	free(tracee);
}

int tracee_handshake(struct tracee_state *tracee, int workdir_fd)
{
	int err = 0, ctx_mem_fd = -1;

	dlog("Handshake with tracee PID %d (%s) started...\n", tracee->pid, tracee->proc_name);

	char memfd_name[64];
	snprintf(memfd_name, sizeof(memfd_name), "wprofinj-ctx-%d", tracee->pid);

	const size_t run_ctx_sz = sizeof(struct inj_run_ctx);
	ctx_mem_fd = memfd_create(memfd_name, MFD_CLOEXEC);
	if (ctx_mem_fd < 0) {
		err = -errno;
		elog("Failed to created shared context memfd file '%s': %d\n", memfd_name, err);
		goto cleanup;
	}
	err = ftruncate(ctx_mem_fd, run_ctx_sz);
	if (err) {
		err = -errno;
		elog("Failed to ftruncate() shared context memfd file '%s': %d\n", memfd_name, err);
		goto cleanup;
	}
	void *ctx_mem = mmap(NULL, run_ctx_sz, PROT_READ | PROT_WRITE, MAP_SHARED, ctx_mem_fd, 0);
	if (ctx_mem == MAP_FAILED) {
		err = -errno;
		elog("Failed to mmap() shared context memfd file '%s': %d\n", memfd_name, err);
		goto cleanup;
	}
	tracee->run_ctx = ctx_mem;

	int tracee_fds[2] = {ctx_mem_fd, workdir_fd};
	struct inj_msg msg = {
		.kind = INJ_MSG_SETUP,
		.setup = {
			.fd_cnt = ARRAY_SIZE(tracee_fds),
		},
	};

	err = uds_send_data(tracee->uds_local_fd, &msg, sizeof(msg), tracee_fds, ARRAY_SIZE(tracee_fds));
	if (err) {
		elog("Failed to send over FDs for handshake: %d\n", err);
		goto cleanup;
	}

	dlog("Handshake with tracee PID %d (%s) completed successfully.\n", tracee->pid, tracee->proc_name);

cleanup:
	zclose(ctx_mem_fd); /* we still have mmap()'ed memory active, no need for FD */
	return err;
}
