/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __PROC_H_
#define __PROC_H_

#include <unistd.h>
#include <sys/syscall.h>
#include <dirent.h>

#include "utils.h"

int proc_name_by_pid(int pid, char *buf, size_t buf_sz);
int thread_name_by_tid(int pid, int tid, char *buf, size_t buf_sz);
int ns_tid_by_host_tid(int host_pid, int host_tid);
int host_tid_by_ns_tid(int host_pid, int ns_tid);

static inline const char *proc_name(int pid)
{
	static __thread char comm[64];

	return proc_name_by_pid(pid, comm, sizeof(comm)) < 0 ? "???" : comm;
}

static inline const char *thread_name(int pid, int tid)
{
	static __thread char comm[64];

	return thread_name_by_tid(pid, tid, comm, sizeof(comm)) < 0 ? "???" : comm;
}

struct proc_iter {
	DIR *proc_dir;
	struct dirent *entry;
	int cur_pid;
};

int proc_iter_new(struct proc_iter *it);
int *proc_iter_next(struct proc_iter *it);
void proc_iter_destroy(struct proc_iter *it);

struct vma_info {
	__u64 vma_start;
	__u64 vma_end;
	__u64 vma_offset;
	__u64 vma_flags;
	__u32 dev_major;
	__u32 dev_minor;
	__u64 inode;
	const char *vma_name;
};

enum vma_query_flags {
	VMA_QUERY_FILE_BACKED_VMA = 0x01,
	VMA_QUERY_VMA_EXECUTABLE = 0x02,
};

struct vma_iter {
	int pid;
	int procmap_fd;
	FILE *file;
	enum vma_query_flags query_flags;
	bool use_procmap_query;
	__u64 addr;
	char path_buf[PATH_MAX];
	struct vma_info vma;
};

int vma_iter_new(struct vma_iter *it, int pid, enum vma_query_flags query_flags);
struct vma_info *vma_iter_next(struct vma_iter *it);
void vma_iter_destroy(struct vma_iter *it);

#endif /* __PROC_H__ */
