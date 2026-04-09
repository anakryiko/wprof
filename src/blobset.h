/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __BLOBSET_H_
#define __BLOBSET_H_

#include <stddef.h>

struct blobset;

struct blobset *blobset__new(void);
void blobset__free(struct blobset *set);

const void *blobset__data(const struct blobset *set);
size_t blobset__data_size(const struct blobset *set);

int blobset__add_blob(struct blobset *set, const void *data, size_t len, size_t align);

#endif /* __BLOBSET_H_ */
