/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __WPROF_BPF_H_
#define __WPROF_BPF_H_

#ifndef E2BIG
#define E2BIG		7
#endif
#ifndef ENODATA
#define ENODATA		61
#endif

#define __cleanup(callback) __attribute__((cleanup(callback)))

#define TASK_RUNNING 0

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

__hidden int glob_match(const char *pat, size_t pat_sz, const char *str, size_t str_sz);

#endif /* __WPROF_BPF_H_ */
