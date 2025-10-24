// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <gelf.h>
#include <libelf.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <linux/fs.h>

#include "utils.h"
#include "sys.h"
#include "proc.h"

static const char *signal_names[] = {
	[0] = "!!!SIGZERO!!!",
	[SIGHUP] = "SIGHUP",
	[SIGINT] = "SIGINT",
	[SIGQUIT] = "SIGQUIT",
	[SIGILL] = "SIGILL",
	[SIGTRAP] = "SIGTRAP",
	[SIGABRT] = "SIGABRT",
	[SIGBUS] = "SIGBUS",
	[SIGFPE] = "SIGFPE",
	[SIGKILL] = "SIGKILL",
	[SIGUSR1] = "SIGUSR1",
	[SIGSEGV] = "SIGSEGV",
	[SIGUSR2] = "SIGUSR2",
	[SIGPIPE] = "SIGPIPE",
	[SIGALRM] = "SIGALRM",
	[SIGTERM] = "SIGTERM",
	[SIGSTKFLT] = "SIGSTKFLT",
	[SIGCHLD] = "SIGCHLD",
	[SIGCONT] = "SIGCONT",
	[SIGSTOP] = "SIGSTOP",
	[SIGTSTP] = "SIGTSTP",
	[SIGTTIN] = "SIGTTIN",
	[SIGTTOU] = "SIGTTOU",
	[SIGURG] = "SIGURG",
	[SIGXCPU] = "SIGXCPU",
	[SIGXFSZ] = "SIGXFSZ",
	[SIGVTALRM] = "SIGVTALRM",
	[SIGPROF] = "SIGPROF",
	[SIGWINCH] = "SIGWINCH",
	[SIGIO] = "SIGIO",
	[SIGPWR] = "SIGPWR",
	[SIGSYS] = "SIGSYS"
};

const char *sig_name(int sig)
{
	static __thread char buf[256];

	if (sig < 0 || sig >= ARRAY_SIZE(signal_names) || !signal_names[sig]) {
		snprintf(buf, sizeof(buf), "SIGNAL(%d)", sig);
		return buf;
	}

	return signal_names[sig];
}

int find_elf_syms(const char *path, const char **sym_names, size_t sym_cnt, long *sym_values)
{
	Elf *elf = NULL;
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	Elf_Data *data = NULL;
	size_t found_cnt = 0;
	int fd = -1, err = 0;

	if (elf_version(EV_CURRENT) == EV_NONE)
		return -EOPNOTSUPP;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		err = -errno;
		eprintf("Failed to open ELF file '%s': %d\n", path, err);
		return err;
	}

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) {
		err = -EINVAL;
		eprintf("Failed to read ELF file '%s': %s\n", path, elf_errmsg(-1));
		goto cleanup;
	}

	/* Verify this is an ELF file */
	if (elf_kind(elf) != ELF_K_ELF) {
		err = -EINVAL;
		eprintf("File '%s' is not an ELF file\n", path);
		goto cleanup;
	}

	/* Iterate through sections to find symbol tables */
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdr) != &shdr) {
			eprintf("Failed to get section header: %s\n", elf_errmsg(-1));
			continue;
		}

		/* Look for symbol table or dynamic symbol table */
		if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
			continue;

		data = elf_getdata(scn, NULL);
		if (!data) {
			eprintf("Failed to get section data: %s\n", elf_errmsg(-1));
			continue;
		}

		/* Calculate number of symbols in this table */
		size_t sym_count = shdr.sh_size / shdr.sh_entsize;

		/* Iterate through symbols in this table */
		for (size_t j = 0; j < sym_count; j++) {
			GElf_Sym sym;
			if (gelf_getsym(data, j, &sym) != &sym)
				continue;

			const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
			if (!name)
				continue;

			/* Check if this symbol matches any requested symbol */
			for (size_t k = 0; k < sym_cnt; k++) {
				if (sym_values[k] != -1)
					continue; /* Already found */

				if (strcmp(name, sym_names[k]) == 0) {
					sym_values[k] = sym.st_value;
					found_cnt++;
					dlogf(INJECTION, 2,
					      "Found symbol '%s' = 0x%lx in '%s'\n",
					      name, sym_values[k], path);

					/* Early exit if all symbols found */
					if (found_cnt == sym_cnt)
						goto success;
					break;
				}
			}
		}
	}

success:
	if (found_cnt != sym_cnt) {
		eprintf("Found only %zu of %zu symbols in '%s'\n", found_cnt, sym_cnt, path);
		for (size_t i = 0; i < sym_cnt; i++) {
			if (sym_values[i] == -1)
				eprintf("  Missing symbol: '%s'\n", sym_names[i]);
		}
		err = -ENOENT;
	}

cleanup:
	if (elf)
		elf_end(elf);
	if (fd >= 0)
		close(fd);
	return err;
}

int uds_send_fds(int uds_fd, int *fds, int fd_cnt)
{
	if (fd_cnt > MAX_UDS_FD_CNT)
		return -E2BIG;

	struct msghdr msg = {};
	int fds_sz = sizeof(*fds) * fd_cnt;
	char buf[CMSG_SPACE(fds_sz)];
	struct iovec io = { .iov_base = &fd_cnt, .iov_len = sizeof(fd_cnt) };

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(fds_sz);
	memcpy(CMSG_DATA(cmsg), fds, fds_sz);

	int sent = sendmsg(uds_fd, &msg, 0);
	if (sent != sizeof(fd_cnt)) {
		eprintf("Failed to send data over UDS, got %d (err %d), expected %d\n", sent, -errno, fds_sz);
		return -errno;
	}

	return 0;
}
