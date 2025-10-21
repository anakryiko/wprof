// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */

#include <string.h>
#include <linux/fs.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <fcntl.h>
#include "proc.h"
#include "utils.h"

int proc_iter_new(struct proc_iter *it)
{
	memset(it, 0, sizeof(*it));

	it->proc_dir = opendir("/proc");
	if (!it->proc_dir) {
		int err = -errno;
		eprintf("Failed to open /proc directory: %d\n", err);
		return err;
	}

	return 0;
}

int *proc_iter_next(struct proc_iter *it)
{
	if (!it->proc_dir)
		return NULL;

again:
	it->entry = readdir(it->proc_dir);
	if (it->entry == NULL)
		return NULL;

	int pid, n;
	if (sscanf(it->entry->d_name, "%d%n", &pid, &n) != 1 || it->entry->d_name[n] != '\0')
		goto again;

	it->cur_pid = pid;
	return &it->cur_pid;
}

void proc_iter_destroy(struct proc_iter *it)
{
	if (!it || !it->proc_dir)
		return;

	closedir(it->proc_dir);
	it->proc_dir = NULL;
}

int vma_iter_new(struct vma_iter *it, int pid, int query_flags)
{
	char proc_path[64];
	int err = 0;

	memset(it, 0, sizeof(*it));
	it->procmap_fd = -1;
	it->pid = pid;

	snprintf(proc_path, sizeof(proc_path), "/proc/%d/maps", pid);
	it->procmap_fd = open(proc_path, O_RDONLY);
	if (it->procmap_fd < 0) {
		err = -errno; /* -ENOENT if process is gone */
		return err;
	}

	/* feature-test PROCMAP_QUERY availability */
	memset(&it->query, 0, sizeof(struct procmap_query));
	it->query.size = sizeof(struct procmap_query);
	it->query.query_flags = PROCMAP_QUERY_COVERING_OR_NEXT_VMA;
	it->query.query_addr = 0;

	err = ioctl(it->procmap_fd, PROCMAP_QUERY, &it->query);
	it->use_procmap_query = err == 0 || errno != ENOTTY;

	it->query_flags = query_flags;
	it->addr = 0;

	errno = 0;
	return 0;
}

struct vma_info *vma_iter_next(struct vma_iter *it)
{
	int err = 0;

	if (it->use_procmap_query) {
		it->query.size = sizeof(it->query);
		it->query.query_flags = PROCMAP_QUERY_COVERING_OR_NEXT_VMA | it->query_flags;
		it->query.query_addr = it->addr;
		it->query.vma_name_addr = (__u64)it->path_buf;
		it->query.vma_name_size = sizeof(it->path_buf);
		it->path_buf[0] = '\0';

		err = ioctl(it->procmap_fd, PROCMAP_QUERY, &it->query);
		if (err && (errno == ENOENT || errno == ESRCH))
			return NULL; /* we are done or process is gone */
		if (err) {
			err = -errno;
			eprintf("PROCMAP_QUERY failed for PID %d: %d\n", it->pid, err);
			errno = -err;
			return NULL;
		}

		it->vma.vma_start = it->query.vma_start;
		it->vma.vma_end = it->query.vma_end;
		it->vma.vma_offset = it->query.vma_offset;
		it->vma.vma_flags = it->query.vma_flags;
		it->vma.dev_minor = it->query.dev_minor;
		it->vma.dev_major = it->query.dev_major;
		it->vma.inode = it->query.inode;
		it->vma.vma_name = it->path_buf[0] ? it->path_buf : NULL;

		it->addr = it->query.vma_end;
		errno = 0;
		return &it->vma;
	} else {
		/* TODO: fallback to /proc/PID/maps text parsing */
		return NULL;
	}
}

void vma_iter_destroy(struct vma_iter *it)
{
	if (it->procmap_fd < 0)
		return;

	int old_errno = errno;

	close(it->procmap_fd);
	it->procmap_fd = -1;

	errno = old_errno;
}

