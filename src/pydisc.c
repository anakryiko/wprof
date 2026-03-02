// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <elf.h>
#include <linux/fs.h>

#include <bpf/bpf.h>

#include "pyoffsets.h"
#include "env.h"
#include "proc.h"
#include "elf_utils.h"

#include "strobelight/bpf_lib/python/include/PyPidData.h"

#include "wprof.skel.h"

struct py_tracee {
	int pid;
	int py_major;
	int py_minor;
	char binary_path[PATH_MAX];
};

static struct py_tracee *py_tracees;
static int py_tracee_cnt;

static int add_py_tracee(int pid, int major, int minor, const char *binary_path)
{
	py_tracees = realloc(py_tracees, (py_tracee_cnt + 1) * sizeof(*py_tracees));
	if (!py_tracees)
		return -ENOMEM;

	struct py_tracee *t = &py_tracees[py_tracee_cnt];
	t->pid = pid;
	t->py_major = major;
	t->py_minor = minor;
	snprintf(t->binary_path, sizeof(t->binary_path), "%s", binary_path);
	py_tracee_cnt++;
	return 0;
}

int pydisc_py_minor(int pid)
{
	for (int i = 0; i < py_tracee_cnt; i++) {
		if (py_tracees[i].pid == pid)
			return py_tracees[i].py_minor;
	}
	return -1;
}

static bool is_py_tracee(int pid)
{
	for (int i = 0; i < py_tracee_cnt; i++) {
		if (py_tracees[i].pid == pid)
			return true;
	}
	return false;
}

static bool has_pyruntime_sym(const char *binary_path)
{
	const char *syms[] = { "_PyRuntime" };
	long addrs[1] = { 0 };

	return elf_find_syms(binary_path, STT_OBJECT, syms, addrs, 1) == 0;
}

/*
 * Extract Python major.minor version from the ELF Py_Version symbol.
 * CPython 3.11+ exports Py_Version as (major << 24) | (minor << 16) | ...
 * If the symbol is absent (Python 3.10 and earlier), default to 3.10 —
 * the only pre-3.11 version we support.
 */
static void extract_version_from_elf(const char *binary_path, int *major, int *minor)
{
	unsigned long ver;

	if (elf_read_sym_value(binary_path, "Py_Version", STT_OBJECT, &ver, sizeof(ver)) == 0) {
		*major = (ver >> 24) & 0xFF;
		*minor = (ver >> 16) & 0xFF;
	} else {
		*major = 3;
		*minor = 10;
	}
}

/*
 * Find the Python runtime binary for a process. This is the binary or shared
 * library that contains the _PyRuntime symbol. On systems with dynamically
 * linked Python, this is typically libpython3.X.so rather than the python3
 * executable itself.
 *
 * Returns 0 if found (binary_path and base_addr set), -ENOENT if not Python.
 */
static int find_python_runtime(int pid, char *binary_path, size_t path_sz,
			       unsigned long *base_addr, int *py_major, int *py_minor)
{
	struct vma_info *vma;
	char exe_path[PATH_MAX];
	char resolved[PATH_MAX];
	ssize_t len;

	*base_addr = 0;

	/*
	 * Find where _PyRuntime lives:
	 * 1. In the executable itself (statically linked Python, e.g. python3)
	 * 2. In libpython*.so (dynamically linked, covers both python3 and
	 *    custom binaries like Cinder's trainer_main)
	 */

	/* try the executable first (statically linked Python) */
	snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
	len = readlink(exe_path, resolved, sizeof(resolved) - 1);
	if (len > 0) {
		resolved[len] = '\0';
		if (has_pyruntime_sym(exe_path)) {
			extract_version_from_elf(exe_path, py_major, py_minor);
			snprintf(binary_path, path_sz, "%s", exe_path);
			/* Use the first private VMA for this binary to compute
			 * base_addr. Skip shared VMAs — those are mmap(MAP_SHARED)
			 * from package managers, not ELF PT_LOAD mappings. The
			 * first private VMA corresponds to the first PT_LOAD
			 * segment (offset=0), giving correct load_bias. */
			wprof_for_each(vma, vma, pid, VMA_QUERY_FILE_BACKED_VMA) {
				if (vma->vma_flags & PROCMAP_QUERY_VMA_SHARED)
					continue;
				if (strcmp(vma->vma_name, resolved) == 0) {
					*base_addr = vma->vma_start - vma->vma_offset;
					break;
				}
			}
			return 0;
		}
	}

	/* Scan maps for libpython*.so with _PyRuntime. Don't filter by
	 * VMA_QUERY_VMA_EXECUTABLE — we want the first VMA (first PT_LOAD)
	 * for correct base_addr with -z separate-code ELFs. Skip shared VMAs —
	 * those are mmap(MAP_SHARED) from package managers, not ELF loads. */
	wprof_for_each(vma, vma, pid, VMA_QUERY_FILE_BACKED_VMA) {
		char host_path[PATH_MAX];

		if (vma->vma_flags & PROCMAP_QUERY_VMA_SHARED)
			continue;

		if (vma->vma_name[0] != '/')
			continue;

		if (!strstr(vma->vma_name, "/libpython") || !strstr(vma->vma_name, ".so"))
			continue;

		snprintf(host_path, sizeof(host_path), "/proc/%d/map_files/%llx-%llx",
			 pid, (unsigned long long)vma->vma_start, (unsigned long long)vma->vma_end);

		if (!has_pyruntime_sym(host_path))
			continue;

		snprintf(binary_path, path_sz, "%s", host_path);
		*base_addr = vma->vma_start - vma->vma_offset;
		extract_version_from_elf(host_path, py_major, py_minor);
		return 0;
	}

	return -ENOENT;
}

/*
 * Build PyPidData for a discovered Python process and populate BPF maps.
 */
static int setup_pid(int pid, const char *binary_path, unsigned long base_addr,
		     int py_major, int py_minor, struct wprof_bpf *skel)
{
	PyPidData pid_data = {};
	int err;

	err = pyoffsets_for_version(py_major, py_minor, &pid_data.offsets);
	if (err) {
		eprintf("Unsupported Python version %d.%d for PID %d\n", py_major, py_minor, pid);
		return -EOPNOTSUPP;
	}

	/* resolve _PyRuntime address */
	const char *syms[] = { "_PyRuntime" };
	long addrs[1] = { 0 };
	err = elf_find_syms(binary_path, STT_OBJECT, syms, addrs, 1);
	if (err) {
		eprintf("Failed to find _PyRuntime symbol in '%s' for PID %d: %d\n", binary_path, pid, err);
		return err;
	}

	unsigned long py_runtime_addr = base_addr + (unsigned long)addrs[0];

	vprintf("PID %d: _PyRuntime ELF sym=0x%lx base=0x%lx runtime_addr=0x%lx\n",
		pid, (unsigned long)addrs[0], base_addr, py_runtime_addr);

	pid_data.py_runtime_addr = py_runtime_addr;
	pid_data.tls_key_addr = py_runtime_addr + pid_data.offsets.TLSKey_offset;

	/*
	 * For Python < 3.12, current thread state is at a fixed offset from
	 * _PyRuntime. For 3.12+, TLS is used instead (use_tls = true).
	 */
	if (pid_data.offsets.TCurrentState_offset != BPF_LIB_DEFAULT_FIELD_OFFSET)
		pid_data.current_state_addr = py_runtime_addr + pid_data.offsets.TCurrentState_offset;

	/*
	 * GIL addresses: for 3.10-3.11, GIL state is at fixed offsets from
	 * _PyRuntime. For 3.12+, GIL moves to per-interpreter state; we leave
	 * these at 0 for now (GIL tracking will be best-effort).
	 */
	if (pid_data.offsets.PyGIL_offset != BPF_LIB_DEFAULT_FIELD_OFFSET)
		pid_data.gil_locked_addr = py_runtime_addr + pid_data.offsets.PyGIL_offset;
	if (pid_data.offsets.PyGIL_last_holder != BPF_LIB_DEFAULT_FIELD_OFFSET)
		pid_data.gil_last_holder_addr = py_runtime_addr + pid_data.offsets.PyGIL_last_holder;

	pid_data.use_tls = (pid_data.tls_key_addr > 0);

	vprintf("PID %d: tls_key=0x%lx current_state=0x%lx gil_locked=0x%lx use_tls=%d\n",
		pid, (unsigned long)pid_data.tls_key_addr,
		(unsigned long)pid_data.current_state_addr,
		(unsigned long)pid_data.gil_locked_addr,
		pid_data.use_tls);

	/* populate pystacks_pid_config BPF map */
	pid_t bpf_pid = pid;
	int map_fd = bpf_map__fd(skel->maps.pystacks_pid_config);
	err = bpf_map_update_elem(map_fd, &bpf_pid, &pid_data, BPF_ANY);
	if (err) {
		eprintf("Failed to update pystacks_pid_config for PID %d: %d\n", pid, err);
		return err;
	}

	/* populate targeted_pids BPF map */
	bool targeted = true;
	int targeted_fd = bpf_map__fd(skel->maps.targeted_pids);
	err = bpf_map_update_elem(targeted_fd, &bpf_pid, &targeted, BPF_ANY);
	if (err) {
		eprintf("Failed to update targeted_pids for PID %d: %d\n", pid, err);
		return err;
	}

	return 0;
}

/*
 * Try to discover and set up a single PID as a Python process.
 * Returns 0 on success (process is Python and was set up),
 * positive value if process is not Python (not an error),
 * negative value on error.
 */
static int discover_pid(int pid, struct wprof_bpf *skel, bool force)
{
	char binary_path[PATH_MAX];
	unsigned long base_addr;
	int py_major, py_minor;
	int err;

	if (is_py_tracee(pid))
		return 0;

	err = find_python_runtime(pid, binary_path, sizeof(binary_path), &base_addr, &py_major, &py_minor);
	if (err) {
		if (force)
			eprintf("PID %d (%s) does not appear to be a Python process\n", pid, proc_name(pid));
		return err == -ENOENT ? 1 : err;
	}

	if (py_major != 3 || py_minor < 10) {
		if (force)
			eprintf("PID %d (%s): Python %d.%d is not supported (need 3.10+)\n",
				pid, proc_name(pid), py_major, py_minor);
		else
			vprintf("PID %d (%s): Python %d.%d is not supported (need 3.10+), skipping\n",
				pid, proc_name(pid), py_major, py_minor);
		return -EOPNOTSUPP;
	}

	err = setup_pid(pid, binary_path, base_addr, py_major, py_minor, skel);
	if (err) {
		eprintf("Failed to set up Python stack tracing for PID %d (%s): %d\n", pid, proc_name(pid), err);
		return err;
	}

	err = add_py_tracee(pid, py_major, py_minor, binary_path);
	if (err)
		return err;

	vprintf("Discovered Python %d.%d process PID=%d (%s) binary='%s'\n",
		py_major, py_minor, pid, proc_name(pid), binary_path);
	return 0;
}

static void discover_proc(struct wprof_bpf *skel)
{
	int *pidp, pid;

	vprintf("Scanning /proc for Python processes...\n");
	wprof_for_each(proc, pidp) {
		pid = *pidp;
		discover_pid(pid, skel, false);
	}
}

static void discover_nvidia_smi(struct wprof_bpf *skel)
{
	vprintf("Using nvidia-smi to find GPU Python processes...\n");

	FILE *f = popen("nvidia-smi --query-compute-apps=pid --format=csv,noheader", "r");
	if (!f) {
		eprintf("Failed to query nvidia-smi for Python process discovery\n");
		return;
	}

	char pidbuf[32];
	int pid;
	while (fgets(pidbuf, sizeof(pidbuf), f)) {
		if (sscanf(pidbuf, "%d", &pid) != 1) {
			eprintf("nvidia-smi returned invalid PID '%s', skipping...\n", pidbuf);
			continue;
		}
		vprintf("nvidia-smi returned PID %d (%s)\n", pid, proc_name(pid));
		discover_pid(pid, skel, true);
	}
	pclose(f);
}

int pydisc_discover(struct wprof_bpf *skel)
{
	int err;

	switch (env.pystacks_discovery) {
	case PYSTACKS_DISCOVER_PROC:
		discover_proc(skel);
		break;
	case PYSTACKS_DISCOVER_NVIDIA_SMI:
		discover_nvidia_smi(skel);
		break;
	case PYSTACKS_DISCOVER_NONE:
		break;
	}

	/* process user-specified PIDs */
	for (int i = 0; i < env.pystacks_pid_cnt; i++) {
		int pid = env.pystacks_pids[i];

		err = discover_pid(pid, skel, true);
		if (err < 0) {
			eprintf("Failed to set up pystacks for user-specified PID %d: %d (skipping...)\n",
				pid, err);
			continue;
		}
	}

	if (py_tracee_cnt > 0) {
		/* enable targeted PID filtering in BPF */
		skel->bss->pid_target_helpers_prog_cfg.has_targeted_pids = true;
	}

	vprintf("Pystacks: discovered %d Python process(es)\n", py_tracee_cnt);
	return py_tracee_cnt;
}

