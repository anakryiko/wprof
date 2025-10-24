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
#define dlog(fmt, ...) dlogf(INJECTION, 2, "tracee(%d, %s): " fmt, tracee->pid, tracee->proc_name, ##__VA_ARGS__)
#define delog(fmt, ...) dlogf(INJECTION, 1, "tracee(%d, %s): " fmt, tracee->pid, tracee->proc_name, ##__VA_ARGS__)

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

			dlog("Found libc mapping: %llx-%llx %llx (%s)\n",
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
		delog("Failed to process_vm_writev() of %zu bytes: %d\n", sz, -errno);
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
		delog("Failed to process_vm_readv() of %zu bytes: %d\n", sz, -errno);
		return -errno;
	}

	return 0;
}

static int ptrace_get_regs(const struct tracee_state *tracee, struct user_regs_struct *regs)
{
	if (ptrace(PTRACE_GETREGS, tracee->pid, NULL, regs) < 0) {
		delog("ptrace(PTRACE_GETREGS) failed: %d\n", -errno);
		return -errno;
	}
	dlog("ptrace(PTRACE_GETREGS)\n");
	return 0;
}

static int ptrace_set_regs(const struct tracee_state *tracee, const struct user_regs_struct *regs)
{
	if (ptrace(PTRACE_SETREGS, tracee->pid, NULL, regs) < 0) {
		delog("ptrace(PTRACE_SETREGS) failed: %d\n", -errno);
		return -errno;
	}
	dlog("ptrace(PTRACE_SETREGS)\n");
	return 0;
}

static int ptrace_set_options(const struct tracee_state *tracee, int options)
{
	if (ptrace(PTRACE_SETOPTIONS, tracee->pid, NULL, options) < 0) {
		delog("ptrace(PTRACE_SETOPTIONS, opts %x) failed: %d\n", options, -errno);
		return -errno;
	}
	dlog("PTRACE_SET_OPTIONS(%x)\n", options);
	return 0;
}

/*
static int ptrace_write_insns(int pid, long rip, void *insns, size_t insn_sz, const char *descr)
{
	long word;
	int err;

	for (size_t i = 0; i < insn_sz; i += sizeof(word)) {
		memcpy(&word, insns + i, sizeof(word));

		errno = 0;
		if (ptrace(PTRACE_POKETEXT, pid, rip + i, word) < 0) {
			err = -errno;
			eprintf("ptrace(PTRACE_POKETEXT, pid %d, off %zu, %s) failed: %d\n",
				pid, i, descr, err);
			return err;
		}
		dlog(RACE_POKETEXT(%d, dst %lx, src %lx, word %lx)\n",
			pid, (long)rip + i, (long)insns + i, word);
	}
	return 0;
}
*/

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
		delog("ptrace(%s) failed: %d\n", op_name, -errno);
		return -errno;
	}

	dlog("%s\n", op_name);
	return 0;
}

static int __ptrace_wait(const struct tracee_state *tracee, int signal, bool ptrace_event, long ip)
{
	int status, err;

	while (true) {
		if (waitpid(tracee->pid, &status, __WALL) != tracee->pid) {
			delog("waitpid() failed: %d\n", -errno);
			return -errno;
		}

		if (WIFEXITED(status)) {
			delog("WIFEXITED()\n");
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
					eprintf("UNEXPECTED IP %llx (expecting %lx) for STOPSIG=%d (%s), PASSING THROUGH BACK TO APP!\n",
						regs.rip - 1, ip,
						WSTOPSIG(status), sig_name(WSTOPSIG(status)));
					goto pass_through;
				}
			}

			dlog("STOPPED%s PID=%d STOPSIG=%d (%s)\n",
				ptrace_event ? " (PTRACE_EVENT_STOP)" : "",
				tracee->pid, WSTOPSIG(status), sig_name(WSTOPSIG(status)));
			return 0;
		}

		vprintf("PASS-THROUGH SIGNAL %d (%s) (status %x) BACK TO PID %d\n",
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

static int ptrace_exec_syscall(const struct tracee_state *tracee,
			       const struct user_regs_struct *pre_regs,
			       struct user_regs_struct *post_regs)
{
	int err = 0;

	err = err ?: ptrace_set_regs(tracee, pre_regs);
	err = err ?: ptrace_op(tracee, PTRACE_SYSCALL, 0);
	err = err ?: ptrace_wait_syscall(tracee);
	err = err ?: ptrace_get_regs(tracee, post_regs);

	return err;
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

	u64 ptrace_attached_ts = ktime_now_ns();

	dlog("Detaching...\n");
	if ((err = ptrace_op(tracee, PTRACE_DETACH, 0)) < 0)
		goto cleanup;
	dlog("Detached successfully!\n");

	u64 ptrace_detached_ts = ktime_now_ns();

	dlog("PTRACE TIMING: discovery %.3lfus, attach %.3lfus, detach %.3lfus, total %.3lfus\n",
	     (ptrace_start_ts - start_ts) / 1000.0,
	     (ptrace_attached_ts - ptrace_start_ts) / 1000.0,
	     (ptrace_detached_ts - ptrace_attached_ts) / 1000.0,
	     (ptrace_detached_ts - start_ts) / 1000.0);

	return 0;

cleanup:
	/* XXX: ACTUALLY CLEANUP */
	return err;
#undef elog
}
