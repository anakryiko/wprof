/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __SYS_H__
#define __SYS_H__

#include <sys/syscall.h>
#include <unistd.h>

const char *sig_name(int sig);

#ifndef MAX_UDS_FD_CNT
#define MAX_UDS_FD_CNT 16
#endif
int uds_send_data(int uds_fd, void *data, size_t data_len, int *fds, int fd_cnt);

int delete_dir(const char *path);

struct perf_event_attr;

static inline long sys_perf_event_open(struct perf_event_attr *attr,
				       int pid, int cpu, int group_fd,
				       unsigned long flags)
{
	return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static inline int sys_pidfd_open(int pid, unsigned int flags)
{
	return syscall(SYS_pidfd_open, pid, flags);
}

static inline int sys_pidfd_getfd(int pid, int targetfd, unsigned int flags)
{
	return syscall(SYS_pidfd_getfd, pid, targetfd, flags);
}

#endif /* __SYS_H__ */
