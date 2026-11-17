// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Meta Platforms, Inc. */
#include <fcntl.h>

#include "bpf_utils.h"
#include "cuda_api.h"
#include "cuda_data.h"
#include "elf_utils.h"
#include "env.h"
#include "proc.h"
#include "wprof_cupti.h"
#include "wprof.skel.h"

extern const char *cupti_driver_cbid_str_map[];
extern int cupti_driver_cbid_str_map_sz;
extern const char *cupti_runtime_cbid_str_map[];
extern int cupti_runtime_cbid_str_map_sz;

static bool library_name_matches(const char *path, const char *library)
{
	const char *basename = strrchr(path, '/');
	size_t library_len = strlen(library);
	if (!basename)
		return false;
	basename += 1;
	if (strncmp(basename, library, library_len))
		return false;
	char suffix = basename[library_len];
	return suffix == '\0' || suffix == '.' || suffix == ' ';
}

static int attach_probes(struct bpf_state *st, int pid, struct bpf_program *prog, const char *path,
			 const struct bpf_uprobe_multi_opts *opts)
{
	struct bpf_link *link = bpf_program__attach_uprobe_multi(prog, pid, path, NULL, opts);
	if (!link)
		return -errno;
	return bpf_add_link(st, link);
}

static int attach_file(struct bpf_state *st, int pid, int fd, const char *label, CUpti_CallbackDomain domain)
{
	bool driver = domain == CUPTI_CB_DOMAIN_DRIVER_API;
	const char **cbid_names = driver ? cupti_driver_cbid_str_map : cupti_runtime_cbid_str_map;
	int cbid_cnt = driver ? cupti_driver_cbid_str_map_sz : cupti_runtime_cbid_str_map_sz;
	enum wcuda_cuda_api_kind kind = driver ? WCUDA_CUDA_API_DRIVER : WCUDA_CUDA_API_RUNTIME;
	const char **names = malloc(cbid_cnt * sizeof(*names));
	unsigned long *offsets = malloc(cbid_cnt * sizeof(*offsets));
	u64 *cookies = malloc(cbid_cnt * sizeof(*cookies));
	size_t probe_cnt = 0;
	int err = 0;
	if (!names || !offsets || !cookies) {
		err = -ENOMEM;
		goto out;
	}

	size_t selected_cnt = 0;
	for (int cbid = 0; cbid < cbid_cnt; cbid++) {
		if (cuda_api_category(domain, cbid) == CUDA_CAT_OTHER)
			continue;
		names[selected_cnt] = cbid_names[cbid];
		cookies[selected_cnt] = ((u64)kind << 32) | cbid;
		selected_cnt++;
	}

	char path[64];
	snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
	err = elf_find_syms(path, STT_FUNC, names, selected_cnt, offsets, NULL);
	if (err && err != -ENOENT)
		goto out;
	err = 0;

	for (size_t i = 0; i < selected_cnt; i++) {
		if (!offsets[i])
			continue;
		size_t j;
		for (j = 0; j < probe_cnt; j++) {
			if (offsets[j] == offsets[i])
				break;
		}
		if (j < probe_cnt)
			continue;
		offsets[probe_cnt] = offsets[i];
		cookies[probe_cnt] = cookies[i];
		probe_cnt++;
	}
	if (!probe_cnt)
		goto out;

	LIBBPF_OPTS(bpf_uprobe_multi_opts, opts, .offsets = offsets, .cookies = cookies,
		    .cnt = probe_cnt, .retprobe = true);
	/* Arm returns first: entry-first attachment can miss an exit and leave cuda_depth stuck. */
	err = attach_probes(st, pid, st->skel->progs.wprof_cuda_api_exit, path, &opts);
	if (err)
		goto out;
	opts.retprobe = false;
	err = attach_probes(st, pid, st->skel->progs.wprof_cuda_api_entry, path, &opts);

out:
	free(names);
	free(offsets);
	free(cookies);
	if (err) {
		eprintf("cuda-api: failed to attach %s for PID %d: %d\n", label, pid, err);
		return err;
	}
	return probe_cnt;
}

static int attach_mapped_files(struct bpf_state *st, int pid)
{
	struct mapped_file {
		u32 dev_major;
		u32 dev_minor;
		u64 inode;
	} *files = NULL;
	size_t file_cnt = 0;
	int runtime_cnt = 0;
	bool driver_library_seen = false;
	struct vma_info *vma;
	int err = 0;

	wprof_for_each(vma, vma, pid, VMA_QUERY_FILE_BACKED_VMA | VMA_QUERY_VMA_EXECUTABLE) {
		if (vma->vma_name[0] != '/')
			continue;
		bool driver_library = library_name_matches(vma->vma_name, "libcuda.so");
		driver_library_seen |= driver_library;
		size_t i;
		for (i = 0; i < file_cnt; i++) {
			if (files[i].dev_major == vma->dev_major && files[i].dev_minor == vma->dev_minor &&
			    files[i].inode == vma->inode)
				break;
		}
		if (i < file_cnt)
			continue;
		struct mapped_file *tmp = realloc(files, (file_cnt + 1) * sizeof(*files));
		if (!tmp) {
			err = -ENOMEM;
			eprintf("cuda-api: failed to scan %s for PID %d: %d\n", vma->vma_name, pid, err);
			goto out;
		}
		files = tmp;
		files[file_cnt] = (struct mapped_file){vma->dev_major, vma->dev_minor, vma->inode};
		file_cnt++;

		/*
		 * Use map_files for mount namespace access and pin the inode through
		 * symbol resolution and attachment.
		 */
		char path[128];
		snprintf(path, sizeof(path), "/proc/%d/map_files/%llx-%llx", pid,
			 vma->vma_start, vma->vma_end);
		int fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			err = -errno;
			eprintf("cuda-api: failed to open %s for PID %d: %d\n", vma->vma_name, pid, err);
			goto out;
		}
		CUpti_CallbackDomain domain = driver_library
			? CUPTI_CB_DOMAIN_DRIVER_API : CUPTI_CB_DOMAIN_RUNTIME_API;
		int cnt = attach_file(st, pid, fd, vma->vma_name, domain);
		close(fd);
		if (cnt < 0) {
			err = cnt;
			goto out;
		}
		if (cnt && !driver_library) {
			vprintf("cuda-api: attached %d runtime API probes in %s for PID %d\n", cnt, vma->vma_name, pid);
			runtime_cnt += cnt;
		}
	}
	err = -errno;
	if (err == -ENOENT)
		err = -ESRCH;
	if (err) {
		eprintf("cuda-api: failed to scan mapped binaries for PID %d: %d\n", pid, err);
		goto out;
	}
	if (!runtime_cnt)
		eprintf("WARNING: cuda-api: no runtime API symbols found in mapped binaries for PID %d; "
			"runtime API calls will not be traced.\n", pid);
	if (!driver_library_seen)
		eprintf("WARNING: cuda-api: libcuda.so is not mapped in PID %d; "
			"driver API calls will not be traced.\n", pid);

out:
	free(files);
	return err;
}

static int attach_pid(struct bpf_state *st, int pid)
{
	int initial_link_cnt = st->link_cnt;
	int err = attach_mapped_files(st, pid);
	if (err < 0)
		goto fail;
	if (st->link_cnt == initial_link_cnt) {
		eprintf("cuda-api: no selected APIs found in mapped binaries for PID %d\n", pid);
		err = -ENOENT;
		goto fail;
	}
	return 0;

fail:
	bpf_remove_links_since(st, initial_link_cnt);
	return err;
}

void cuda_api_attach(struct bpf_state *st)
{
	int pid_cnt = env.cuda_api_pid_cnt;
	int attached_cnt = 0;
	for (int i = 0; i < pid_cnt; i++) {
		int pid = env.cuda_api_pids[i];
		int err = attach_pid(st, pid);
		if (err) {
			eprintf("WARNING: failed to attach CUDA API probes to PID %d: %d, skipping...\n", pid, err);
			continue;
		}
		env.cuda_api_pids[attached_cnt] = pid;
		attached_cnt++;
	}
	env.cuda_api_pid_cnt = attached_cnt;
	if (pid_cnt && !attached_cnt) {
		eprintf("WARNING: no CUDA API targets could be attached, disabling CUDA capture\n");
		env.capture_cuda = false;
		env.requested_stack_traces &= ~ST_CUDA;
	}
}
