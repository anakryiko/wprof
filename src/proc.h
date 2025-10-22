/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __PROC_H_
#define __PROC_H_

#include <unistd.h>
#include <sys/syscall.h>
#include <dirent.h>

int proc_name_by_pid(int pid, char *buf, size_t buf_sz);

static inline const char *proc_name(int pid)
{
	static __thread char comm[64];

	return proc_name_by_pid(pid, comm, sizeof(comm)) < 0 ? "???" : comm;
}

#define wprof_for_each(type, cur, args...) for (						\
	/* initialize and define destructor */							\
	struct type##_iter ___it __attribute__((cleanup(type##_iter_destroy))),			\
			       *___p __attribute__((unused)) = (				\
					type##_iter_new(&___it, ##args),			\
					(void *)0);						\
	(((cur) = type##_iter_next(&___it)));							\
)

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

struct vma_iter {
	int pid;
	int procmap_fd;
	FILE *file;
	int query_flags;
	bool use_procmap_query;
	struct procmap_query query;
	__u64 addr;
	char path_buf[PATH_MAX];
	struct vma_info vma;
};

int vma_iter_new(struct vma_iter *it, int pid, int query_flags);
struct vma_info *vma_iter_next(struct vma_iter *it);
void vma_iter_destroy(struct vma_iter *it);

#endif /* __PROC_H__ */
