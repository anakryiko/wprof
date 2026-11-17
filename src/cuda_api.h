/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __CUDA_API_H__
#define __CUDA_API_H__

struct bpf_state;

void cuda_api_attach(struct bpf_state *st);

#endif /* __CUDA_API_H__ */
