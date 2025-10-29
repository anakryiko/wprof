/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __CUDA_H_
#define __CUDA_H_

#include <stdint.h>

int setup_cuda_tracking_discovery(int workdir_fd);
void teardown_cuda_tracking(void);

#endif /* __CUDA_H_ */
