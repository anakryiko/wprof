// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <linux/fs.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <fcntl.h>
#include "proc.h"
#include "utils.h"

int proc_name_by_pid(int pid, char *buf, size_t buf_sz)
{
	char path[32];
	snprintf(path, sizeof(path), "/proc/%d/comm", pid);

	FILE *fp = fopen(path, "re");
	if (!fp) {
		snprintf(buf, buf_sz, "???");
		return -errno;
	}

	if (fgets(buf, buf_sz, fp)) {
		char *endline = strchr(buf, '\n');
		if (endline)
			*endline = '\0';
		fclose(fp);
		return 0;
	}

	fclose(fp);
	return -ESRCH;
}

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

int vma_iter_new(struct vma_iter *it, int pid, enum vma_query_flags query_flags)
{
	char proc_path[64];
	int err = 0;

	memset(it, 0, sizeof(*it));
	it->procmap_fd = -1;
	it->pid = pid;

	if (pid < 0)
		snprintf(proc_path, sizeof(proc_path), "/proc/self/maps");
	else
		snprintf(proc_path, sizeof(proc_path), "/proc/%d/maps", pid);
	it->procmap_fd = open(proc_path, O_RDONLY);
	if (it->procmap_fd < 0) {
		err = -errno; /* -ENOENT if process is gone */
		return err;
	}

	/* feature-test PROCMAP_QUERY availability */
	struct procmap_query query;
	memset(&query, 0, sizeof(struct procmap_query));
	query.size = sizeof(struct procmap_query);
	query.query_flags = PROCMAP_QUERY_COVERING_OR_NEXT_VMA;
	query.query_addr = 0;

	err = ioctl(it->procmap_fd, PROCMAP_QUERY, &query);
	it->use_procmap_query = err == 0 || errno != ENOTTY;
	if (!it->use_procmap_query) {
		it->file = fdopen(it->procmap_fd, "re");
		if (!it->file) {
			err = -errno;
			close(it->procmap_fd);
			it->procmap_fd = -1;
			errno = -err;
			return err;
		}
		it->procmap_fd = -1;
	}

	it->query_flags = query_flags;
	it->addr = 0;

	errno = 0;
	return 0;
}

#define PROCMAP_QUERY_VMA_FLAGS (				\
		PROCMAP_QUERY_VMA_READABLE |			\
		PROCMAP_QUERY_VMA_WRITABLE |			\
		PROCMAP_QUERY_VMA_EXECUTABLE |			\
		PROCMAP_QUERY_VMA_SHARED			\
)

struct vma_info *vma_iter_next(struct vma_iter *it)
{
	int err = 0;

	if (it->procmap_fd < 0 && !it->file)
		return NULL;

	if (it->use_procmap_query) {
		struct procmap_query query;

		memset(&query, 0, sizeof(query));
		query.size = sizeof(query);
		query.query_flags = PROCMAP_QUERY_COVERING_OR_NEXT_VMA;
		if (it->query_flags & VMA_QUERY_FILE_BACKED_VMA)
			it->query_flags |= PROCMAP_QUERY_FILE_BACKED_VMA;
		if (it->query_flags & VMA_QUERY_VMA_EXECUTABLE)
			it->query_flags |= PROCMAP_QUERY_VMA_EXECUTABLE;
		query.query_addr = it->addr;
		query.vma_name_addr = (__u64)it->path_buf;
		query.vma_name_size = sizeof(it->path_buf);
		it->path_buf[0] = '\0';

		err = ioctl(it->procmap_fd, PROCMAP_QUERY, &query);
		if (err && errno == ENOENT) {
			errno = 0;
			return NULL; /* exhausted all VMA entries, expected outcome */
		}
		if (err && errno == ESRCH)
			return NULL; /* process is gone, sort of expected, but let caller know */
		if (err) {
			err = -errno;
			eprintf("PROCMAP_QUERY failed for PID %d: %d\n", it->pid, err);
			errno = -err; /* unexpected error, let caller deal with it */
			return NULL;
		}

		it->vma.vma_start = query.vma_start;
		it->vma.vma_end = query.vma_end;
		it->vma.vma_offset = query.vma_offset;
		it->vma.vma_flags = query.vma_flags;
		it->vma.dev_minor = query.dev_minor;
		it->vma.dev_major = query.dev_major;
		it->vma.inode = query.inode;
		it->vma.vma_name = it->path_buf[0] ? it->path_buf : NULL;

		it->addr = query.vma_end;
		errno = 0;
		return &it->vma;
	} else {
		/* We need to handle lines with no path at the end:
		 *
		 * 7f5c6f5d1000-7f5c6f5d3000 rw-p 001c7000 08:04 21238613      /usr/lib64/libc-2.17.so
		 * 7f5c6f5d3000-7f5c6f5d8000 rw-p 00000000 00:00 0
		 * 7f5c6f5d8000-7f5c6f5d9000 r-xp 00000000 103:01 362990598    /data/users/andriin/linux/tools/bpf/usdt/libhello_usdt.so
		 */
again:
		char mode[8];
		int ret;

		ret = fscanf(it->file, "%llx-%llx %s %llx %x:%x %lld%[^\n]",
			     &it->vma.vma_start, &it->vma.vma_end, mode, &it->vma.vma_offset,
			     &it->vma.dev_major, &it->vma.dev_minor, &it->vma.inode, it->path_buf);
		if (ret != 8) {
			err = -errno;
			if (feof(it->file)) {
				errno = 0;
				return NULL; /* expected outcome, no more VMAs */
			}
			errno = -err;
			return NULL;
		}

		it->vma.vma_flags = 0;
		if (mode[0] == 'r')
			it->vma.vma_flags |= PROCMAP_QUERY_VMA_READABLE;
		if (mode[1] == 'w')
			it->vma.vma_flags |= PROCMAP_QUERY_VMA_WRITABLE;
		if (mode[2] == 'x')
			it->vma.vma_flags |= PROCMAP_QUERY_VMA_EXECUTABLE;
		if (mode[3] == 's')
			it->vma.vma_flags |= PROCMAP_QUERY_VMA_SHARED;

		int perm_query = it->query_flags & PROCMAP_QUERY_VMA_FLAGS;
		if (perm_query && (it->vma.vma_flags & perm_query) != perm_query)
			goto again;

		/*
		 * To handle no path case (see above) we need to capture line
		 * without skipping any whitespaces. So we need to strip
		 * leading whitespaces manually here
		 */
		int i = 0;
		while (isblank(it->path_buf[i]))
			i++;
		it->vma.vma_name = it->path_buf + i;

		if ((it->query_flags & PROCMAP_QUERY_FILE_BACKED_VMA) && it->path_buf[i] == '\0')
			goto again;

		errno = 0;
		return &it->vma;
	}
}

void vma_iter_destroy(struct vma_iter *it)
{
	int old_errno = errno;

	if (it->procmap_fd >= 0) {
		close(it->procmap_fd);
		it->procmap_fd = -1;
	}
	if (it->file) {
		fclose(it->file);
		it->file = NULL;
	}

	errno = old_errno;
}

