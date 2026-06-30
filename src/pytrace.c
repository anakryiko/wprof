// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Meta Platforms, Inc. */
#include <string.h>
#include <errno.h>
#include <sys/sysmacros.h>
#include <linux/fs.h>

#include "pytrace.h"
#include "injmgr.h"
#include "proc.h"
#include "env.h"
#include "inj_common.h"
#include "elf_utils.h"
#include "pydisc.h"

static int pytrace_resolve_symbols(struct py_binary_info *bi, unsigned long *sym_addrs)
{
	int err;

	err = elf_resolve_syms(bi->pid, bi->vma_start, bi->vma_end, bi->vma_offset,
			       STT_FUNC, pytrace_sym_names, PYTRACE_SYM_CNT, sym_addrs);
	if (err) {
		for (int i = 0; i < PYTRACE_SYM_CNT; i++) {
			if (sym_addrs[i])
				continue;
			/* PyEval_SetProfileAllThreads is 3.12+ only */
			if (strcmp(pytrace_sym_names[i], "PyEval_SetProfileAllThreads") == 0) {
				dlogf(DISCOVERY, 1, "PID %d: %s not found, skipping\n", bi->pid, pytrace_sym_names[i]);
				continue;
			}
			eprintf("PID %d: missing required Python symbol[%s] in %s\n",
				bi->pid, pytrace_sym_names[i], bi->host_path);
			return -ENOENT;
		}
	}

	for (int i = 0; i < PYTRACE_SYM_CNT; i++) {
		if (sym_addrs[i])
			dlogf(DISCOVERY, 1, "  %s: addr=0x%lx\n", pytrace_sym_names[i], sym_addrs[i]);
	}

	return 0;
}

/*
 * Iterate over tracee's VMA mappings to resolve PyTorch RecordFunction symbols
 * via ELF parsing. Works for both dynamically and statically linked PyTorch.
 */
static int torch_resolve_symbols(int pid, unsigned long *sym_addrs)
{
	struct vma_info *vma;
	__u64 last_dev = 0;
	__u64 last_inode = 0;

	wprof_for_each(vma, vma, pid, VMA_QUERY_FILE_BACKED_VMA | VMA_QUERY_VMA_EXECUTABLE) {
		if (vma->vma_flags & PROCMAP_QUERY_VMA_SHARED)
			continue;
		if (vma->vma_name[0] != '/')
			continue;

		__u64 curr_dev = makedev(vma->dev_major, vma->dev_minor);

		if (vma->inode == last_inode && curr_dev == last_dev)
			continue;

		last_inode = vma->inode;
		last_dev = curr_dev;

		if (elf_resolve_syms(pid, vma->vma_start, vma->vma_end, vma->vma_offset,
				     STT_FUNC, pytorch_sym_names, PYTORCH_SYM_CNT, sym_addrs) == 0) {
			for (int i = 0; i < PYTORCH_SYM_CNT; i++)
				dlogf(DISCOVERY, 1, "  %s: addr=0x%lx\n", pytorch_sym_names[i], sym_addrs[i]);
			return 0;
		}
	}

	return -ENOENT;
}

bool pytrace_detect(int pid, int *out_py_minor, unsigned long *out_py_sym_addrs)
{
	struct py_binary_info bi;
	int err;

	err = py_find_binary(pid, &bi);
	if (err) {
		dlogf(DISCOVERY, 1, "PID %d (%s) is not Python, skipping\n", pid, proc_name(pid));
		return false;
	}

	vprintf("%s is Python 3.%d.\n", inj_proc_str(pid, ns_tid_by_host_tid(pid, pid), proc_name(pid)), bi.py_minor);

	dlogf(DISCOVERY, 0, "PID %d: Python binary at '%s'\n", pid, bi.host_path);

	/* Resolve all required Python C API symbols before injection */
	u64 ts = ktime_now_ns();
	err = pytrace_resolve_symbols(&bi, out_py_sym_addrs);
	dlogf(DISCOVERY, 1, "PID %d: PyTrace symbol resolution took %.3lfms\n", pid, (ktime_now_ns() - ts) / 1e6);
	if (err) {
		eprintf("Failed to resolve Python symbols for %s, skipping injection\n",
			inj_proc_str(pid, ns_tid_by_host_tid(pid, pid), proc_name(pid)));
		return false;
	}

	*out_py_minor = bi.py_minor;
	return true;
}

bool pytorch_detect(int pid, unsigned long *out_pytorch_sym_addrs)
{
	u64 ts = ktime_now_ns();
	int err = torch_resolve_symbols(pid, out_pytorch_sym_addrs);
	dlogf(DISCOVERY, 1, "PID %d: PyTorch symbol resolution took %.3lfms\n", pid, (ktime_now_ns() - ts) / 1e6);
	if (err) {
		eprintf("Failed to resolve PyTorch symbols for PID %d (%s), skipping injection...\n",
				pid, proc_name(pid));
		return false;
	}

	vprintf("%s uses PyTorch.\n", inj_proc_str(pid, ns_tid_by_host_tid(pid, pid), proc_name(pid)));
	return true;
}
