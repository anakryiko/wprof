// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <time.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <pthread.h>

#include "utils.h"

int append_str(char ***strs, int *cnt, const char *str)
{
	void *tmp;
	char *s;

	tmp = realloc(*strs, (*cnt + 1) * sizeof(**strs));
	if (!tmp)
		return -ENOMEM;
	*strs = tmp;

	(*strs)[*cnt] = s = strdup(str);
	if (!s)
		return -ENOMEM;

	*cnt = *cnt + 1;
	return 0;
}

int append_str_file(char ***strs, int *cnt, const char *file)
{
	char buf[256];
	FILE *f;
	int err = 0;

	f = fopen(file, "r");
	if (!f) {
		err = -errno;
		fprintf(stderr, "Failed to open '%s': %d\n", file, err);
		return err;
	}

	while (fscanf(f, "%s", buf) == 1) {
		if (append_str(strs, cnt, buf)) {
			err = -ENOMEM;
			goto cleanup;
		}
	}

cleanup:
	fclose(f);
	return err;
}

int append_num(int **nums, int *cnt, const char *arg)
{
	void *tmp;
	int pid;

	errno = 0;
	pid = strtol(arg, NULL, 10);
	if (errno || pid < 0) {
		fprintf(stderr, "Invalid PID: %d\n", pid);
		return -EINVAL;
	}

	tmp = realloc(*nums, (*cnt + 1) * sizeof(**nums));
	if (!tmp)
		return -ENOMEM;
	*nums = tmp;

	(*nums)[*cnt] = pid;
	*cnt = *cnt + 1;

	return 0;
}

ssize_t file_size(FILE *f)
{
	int fd = fileno(f);
	struct stat st;

	fflush(f);

	if (fstat(fd, &st))
		return -errno;

	return st.st_size;
}

#define FMT_BUF_LEVELS 16
#define FMT_BUF_LEN 1024

static __thread char fmt_bufs[FMT_BUF_LEVELS][FMT_BUF_LEN];
static __thread int fmt_buf_idx = 0;

__attribute__((format(printf, 1, 2)))
const char *sfmt(const char *fmt, ...)
{
	va_list ap;
	char *fmt_buf = fmt_bufs[fmt_buf_idx % FMT_BUF_LEVELS];

	va_start(ap, fmt);
	(void)vsnprintf(fmt_buf, FMT_BUF_LEN, fmt, ap);
	va_end(ap);

	fmt_buf_idx++;
	return fmt_buf;
}

const char *vsfmt(const char *fmt, va_list ap)
{
	char *fmt_buf = fmt_bufs[fmt_buf_idx % FMT_BUF_LEVELS];

	(void)vsnprintf(fmt_buf, FMT_BUF_LEN, fmt, ap);

	fmt_buf_idx++;
	return fmt_buf;
}

/* adapted from libbpf sources */
bool glob_matches(const char *glob, const char *s)
{
	while (*s && *glob && *glob != '*') {
		/* Matches any single character */
		if (*glob == '?') {
			s++;
			glob++;
			continue;
		}
		if (*s != *glob)
			return false;
		s++;
		glob++;
	}
	/* Check wild card */
	if (*glob == '*') {
		while (*glob == '*') {
			glob++;
		}
		if (!*glob) /* Tail wild card matches all */
			return true;
		while (*s) {
			if (glob_matches(glob, s++))
				return true;
		}
	}
	return !*s && !*glob;
}


static u64 ktime_off;

void calibrate_ktime(void)
{
	int i;
	struct timespec t1, t2, t3;
	uint64_t best_delta = 0, delta, ts;

	for (i = 0; i < 10; i++) {
		clock_gettime(CLOCK_REALTIME, &t1);
		clock_gettime(CLOCK_MONOTONIC, &t2);
		clock_gettime(CLOCK_REALTIME, &t3);

		delta = timespec_to_ns(&t3) - timespec_to_ns(&t1);
		ts = (timespec_to_ns(&t3) + timespec_to_ns(&t1)) / 2;

		if (i == 0 || delta < best_delta) {
			best_delta = delta;
			ktime_off = ts - timespec_to_ns(&t2);
		}
	}
}

void set_ktime_off(u64 ktime_ns, u64 realtime_ns)
{
	ktime_off = realtime_ns - ktime_ns;
}

u64 ktime_to_realtime_ns(u64 ts_ns)
{
	return ktime_off + ts_ns;
}
