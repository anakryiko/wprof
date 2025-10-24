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

static int ptrace_restart_syscall(const struct tracee_state *tracee,
				  const struct user_regs_struct *orig_regs)
{
	int err = 0;

	err = err ?: ptrace_set_regs(tracee, orig_regs);
	err = err ?: ptrace_op(tracee, PTRACE_SYSCALL, 0);
	err = err ?: ptrace_wait_syscall(tracee);

	return err;
}

static int ptrace_exec_syscall(const struct tracee_state *tracee,
			       const struct user_regs_struct *orig_regs,
			       const struct user_regs_struct *pre_regs,
			       struct user_regs_struct *post_regs)
{
	int err = 0;

	err = err ?: ptrace_set_regs(tracee, pre_regs);
	err = err ?: ptrace_op(tracee, PTRACE_SYSCALL, 0);
	err = err ?: ptrace_wait_syscall(tracee);
	err = err ?: ptrace_get_regs(tracee, post_regs);
	err = err ?: ptrace_restart_syscall(tracee, orig_regs);

	return err;
}

int ptrace_inject(int pid, struct tracee_state *tracee)
{
	int err = 0;
	u64 start_ts = ktime_now_ns();

	memset(tracee, 0, sizeof(*tracee));

	tracee->pid = pid;
	tracee->proc_name = strdup(proc_name(pid));

	/* We need pidfd to open tracee's FDs later on */
	tracee->pid_fd = sys_pidfd_open(pid, 0);
	if (tracee->pid_fd < 0) {
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
	long dlopen_tracee_addr = libc_start + dlopen_tracee_off;
	long dlclose_tracee_addr = libc_start + dlclose_tracee_off;
	long dlsym_tracee_addr = libc_start + dlsym_tracee_off;

	dlog("Remote libc found at '%s' base 0x%lx (dlopen off %lx -> %lx, dlclose off %lx -> %lx, dlsym off %lx -> %lx)\n",
	     libc_path, libc_start,
	     dlopen_tracee_off, dlopen_tracee_addr,
	     dlclose_tracee_off, dlclose_tracee_addr,
	     dlsym_tracee_off, dlsym_tracee_addr);

	u64 ptrace_start_ts = ktime_now_ns();

	/*
	 * Attach to tracee
	 */
	dlog("Seizing...\n");
	if ((err = ptrace_op(tracee, PTRACE_SEIZE, 0)) < 0)
		goto cleanup;
	dlog("Interrupting...\n");
	if ((err = ptrace_op(tracee, PTRACE_INTERRUPT, 0)) < 0)
		goto cleanup;
	dlog("Waiting for SIGTRAP | PTRACE_EVENT_STOP...\n");
	if ((err = ptrace_wait_stop(tracee)) < 0)
		goto cleanup;

	/*
	 * Take over next syscall
	 */
	struct user_regs_struct orig_regs, regs;

	if ((err = ptrace_set_options(tracee, PTRACE_O_TRACESYSGOOD)) < 0)
		goto cleanup;
	dlog("Resuming until syscall...\n");
	if ((err = ptrace_op(tracee, PTRACE_SYSCALL, 0)) < 0)
		goto cleanup;
	if ((err = ptrace_wait_syscall(tracee)) < 0)
		goto cleanup;

	u64 ptrace_intercept_ts = ktime_now_ns();

	/* backup original registers */
	if ((err = ptrace_get_regs(tracee, &orig_regs)) < 0)
		goto cleanup;

	/* XXX: arm64 will need something else */
	orig_regs.rip -= 2; /* adjust for syscall replay, syscall instruction is 2 bytes */

	/*
	 * Inject mmap() syscall
	 */
	const long page_size = sysconf(_SC_PAGESIZE);
	const long data_mmap_sz = page_size;
	const long exec_mmap_sz = page_size;
	long data_mmap_addr = 0;
	long exec_mmap_addr = 0;

	dlog("Executing mmap()...\n");
	/* void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset); */
	memcpy(&regs, &orig_regs, sizeof(orig_regs));
	regs.orig_rax = __NR_mmap;
	regs.rdi = 0; /* addr */
	regs.rsi = data_mmap_sz + exec_mmap_sz; /* length */
	regs.rdx = PROT_WRITE | PROT_READ; /* prot */
	regs.r10 = MAP_ANONYMOUS | MAP_PRIVATE; /* flags */
	regs.r8 = 0; /* fd */
	regs.r9 = 0; /* offset */

	if ((err = ptrace_exec_syscall(tracee, &orig_regs, &regs, &regs)) < 0)
		goto cleanup;

	data_mmap_addr = regs.rax;
	if (data_mmap_addr <= 0) {
		elog("mmap() inside tracee failed: %ld, bailing!\n", data_mmap_addr);
		return 1;
	}
	exec_mmap_addr = data_mmap_addr + data_mmap_sz;
	dlog("mmap() returned 0x%lx (data @ %lx, code @ %lx)\n",
	     (long)data_mmap_addr, (long)data_mmap_addr, (long)exec_mmap_addr);

	/*
	 * Setup executable function call trampoline, by copying inj_call()
	 * code into (to be) executable mmap()'ed memory
	 */
	if ((err = remote_vm_write(tracee, exec_mmap_addr, __inj_call, __inj_call_sz)) < 0)
		goto cleanup;

	/*
	 * Inject mprotect(r-x) syscall
	 */
	dlog("Executing mprotect(r-xp)...\n");
	/* int mprotect(void *addr, size_t size, int prot); */
	memcpy(&regs, &orig_regs, sizeof(orig_regs));
	regs.orig_rax = __NR_mprotect;
	regs.rdi = exec_mmap_addr; /* addr */
	regs.rsi = exec_mmap_sz; /* size */
	regs.rdx = PROT_EXEC | PROT_READ; /* prot */

	if ((err = ptrace_exec_syscall(tracee, &orig_regs, &regs, &regs)) < 0)
		goto cleanup;

	long mprotect_ret = regs.rax;
	if (mprotect_ret < 0) {
		elog("mprotect(r-x) inside tracee failed: %ld, bailing!\n", mprotect_ret);
		goto cleanup;
	}

	/*
	 * Execute memfd_create() syscall
	 */
	dlog("Executing memfd_create()...\n");

	int memfd_remote_fd = -1;
	char memfd_name[] = "wprof-inject";

	if ((err = remote_vm_write(tracee, data_mmap_addr, memfd_name, sizeof(memfd_name))) < 0)
		goto cleanup;

	/* int memfd_create(const char *name, unsigned int flags); */
	memcpy(&regs, &orig_regs, sizeof(orig_regs));
	regs.orig_rax = __NR_memfd_create;
	regs.rdi = data_mmap_addr; /* name */
	regs.rsi = MFD_CLOEXEC; /* flags */
	if ((err = ptrace_exec_syscall(tracee, &orig_regs, &regs, &regs)) < 0)
		goto cleanup;

	memfd_remote_fd = regs.rax;
	if (memfd_remote_fd < 0) {
		elog("memfd_create() inside tracee failed: %d, bailing!\n", memfd_remote_fd);
		goto cleanup;
	}
	dlog("memfd_create() result: %d\n", memfd_remote_fd);

	/*
	 * Execute socketpair(AF_UNIX, SOCK_STREAM)
	 */
	dlog("Executing socketpair(AF_UNIX, SOCK_STREAM)...\n");

	/* int socketpair(int domain, int type, int protocol, int sv[2]); */
	memcpy(&regs, &orig_regs, sizeof(orig_regs));
	regs.orig_rax = __NR_socketpair;
	regs.rdi = AF_UNIX; /* domain */
	regs.rsi = SOCK_STREAM; /* length */
	regs.rdx = 0; /* protocol */
	regs.r10 = data_mmap_addr; /* sv */
	if ((err = ptrace_exec_syscall(tracee, &orig_regs, &regs, &regs)) < 0)
		goto cleanup;

	int sockpair_ret = regs.rax;
	if (sockpair_ret != 0) {
		elog("socketpair(AF_UNIX, SOCK_STREAM) failed: %d\n", sockpair_ret);
		goto cleanup;
	}

	int uds_remote_fds[2];
	err = remote_vm_read(tracee, uds_remote_fds, data_mmap_addr, sizeof(uds_remote_fds));
	if (err)
		goto cleanup;
	dlog("socket_pair() FDs = {%d, %d}\n", uds_remote_fds[0], uds_remote_fds[1]);

	int uds_local_fd = sys_pidfd_getfd(tracee->pid_fd, uds_remote_fds[0], 0);
	if (uds_local_fd < 0) {
		elog("pidfd_getfd(remote_fd %d) failed: %d\n", uds_remote_fds[0], -errno);
		goto cleanup;
	}
	dlog("pidfd_getfd() returned UDS FD %d for tracer\n", uds_local_fd);

	u64 ptrace_prepped_ts = ktime_now_ns();

	/* Open tracee's allocated FD for shared lib code */
	int memfd_local_fd = sys_pidfd_getfd(tracee->pid_fd, memfd_remote_fd, 0);
	if (memfd_local_fd < 0) {
		elog("pidfd_getfd(remote_fd %d) failed: %d\n", memfd_remote_fd, -errno);
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
		elog("Failed to mmap() libinj.so desitnation memfd file: %d\n", -errno);
		goto cleanup;
	}
	memcpy(libinj_so_mem, libwprofinj_so_start, libwprofinj_so_sz);
	(void)munmap(libinj_so_mem, libwprofinj_so_sz);
	libinj_so_mem = NULL;

	/* Copy over memfd path for passing into dlopen() */
	char memfd_path[64];
	snprintf(memfd_path, sizeof(memfd_path), "/proc/self/fd/%d", memfd_remote_fd);
	if ((err = remote_vm_write(tracee, data_mmap_addr, memfd_path, sizeof(memfd_path))) < 0)
		goto cleanup;

	dlog("Executing dlopen()...\n");
	long inj_trap_addr = exec_mmap_addr + __inj_trap - __inj_call;

	/* void *dlopen(const char *path, int flags); */
	memcpy(&regs, &orig_regs, sizeof(orig_regs));
	regs.orig_rax = -1; /* cancel pending syscall continuation */
	regs.rip = exec_mmap_addr;
	regs.rax = dlopen_tracee_addr;
	regs.rdi = data_mmap_addr; /* name */
	regs.rsi = RTLD_LAZY; /* flags */
	regs.rsp = (regs.rsp & ~0xFULL) - 128; /* ensure 16-byte alignment and set up red zone */

	if ((err = ptrace_set_regs(tracee, &regs)) < 0)
		goto cleanup;
	if ((err = ptrace_op(tracee, PTRACE_CONT, 0)) < 0)
		goto cleanup;
	if ((err = ptrace_wait_trap(tracee, inj_trap_addr)) < 0)
		goto cleanup;
	if ((err = ptrace_get_regs(tracee, &regs)) < 0)
		goto cleanup;

	long dlopen_handle = regs.rax;
	if (dlopen_handle == 0) {
		elog("Failed to dlopen() injection library!\n");
		goto cleanup;
	}
	dlog("dlopen() result: %lx\n", dlopen_handle);

	dlog("Resolving __libinj_setup() through dlsym()...\n");
	if ((err = remote_vm_write(tracee, data_mmap_addr, LIBWPROFINJ_SETUP_SYM_NAME,
				   sizeof(LIBWPROFINJ_SETUP_SYM_NAME))) < 0)
		goto cleanup;

	/* void *dlsym(void *restrict handle, const char *restrict symbol); */
	memcpy(&regs, &orig_regs, sizeof(orig_regs));
	regs.rip = exec_mmap_addr;
	regs.rax = dlsym_tracee_addr;
	regs.rdi = dlopen_handle; /* handle */
	regs.rsi = data_mmap_addr; /* symbol */
	regs.rsp = (regs.rsp & ~0xFULL) - 128; /* ensure 16-byte alignment and set up red zone */

	if ((err = ptrace_set_regs(tracee, &regs)) < 0)
		goto cleanup;
	if ((err = ptrace_op(tracee, PTRACE_CONT, 0)) < 0)
		goto cleanup;
	if ((err = ptrace_wait_trap(tracee, inj_trap_addr)) < 0)
		goto cleanup;
	if ((err = ptrace_get_regs(tracee, &regs)) < 0)
		goto cleanup;

	long inj_setup_addr = regs.rax;
	dlog("dlsym() result: %lx\n", inj_setup_addr);
	if (inj_setup_addr == 0) {
		elog("Failed to find '%s' using dlsym()...\n", LIBWPROFINJ_SETUP_SYM_NAME);
		goto cleanup;
	}

	dlog("Setting up injected context calling into %s()...\n", LIBWPROFINJ_SETUP_SYM_NAME);
	struct inj_setup_ctx setup_ctx = {
		.uds_fd = uds_remote_fds[1],
		.uds_parent_fd = uds_remote_fds[0],
		.lib_mem_fd = memfd_remote_fd,
	};
	if ((err = remote_vm_write(tracee, data_mmap_addr, &setup_ctx, sizeof(setup_ctx))) < 0)
		goto cleanup;

	/* int __libinj_setup(struct inj_init_ctx *ctx) */
	memcpy(&regs, &orig_regs, sizeof(orig_regs));
	regs.rip = exec_mmap_addr;
	regs.rax = inj_setup_addr;
	regs.rdi = data_mmap_addr; /* ctx */
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
	dlog("%s() result: %ld\n", LIBWPROFINJ_SETUP_SYM_NAME, inj_setup_res);
	if (inj_setup_res != 0) {
		elog("Injection init with %s() failed (result %ld), bailing!..\n",
		     LIBWPROFINJ_SETUP_SYM_NAME, inj_setup_res);
		goto cleanup;
	}

	/* 
	 * Prepare for execution of the original intercepted syscall
	 */
	dlog("Replaying original syscall and detaching tracee...\n");
	if ((err = ptrace_restart_syscall(tracee, &orig_regs)) < 0)
		goto cleanup;
	if ((err = ptrace_op(tracee, PTRACE_DETACH, 0)) < 0)
		goto cleanup;

	u64 ptrace_injected_ts = ktime_now_ns();

	dlog("PTRACE TIMING:\n"
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

	return 0;

cleanup:
	/* XXX: ACTUALLY CLEANUP */
	return err;
#undef elog
}
