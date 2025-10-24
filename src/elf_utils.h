/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Meta Platforms, Inc. */
#ifndef __ELF_UTILS_H__
#define __ELF_UTILS_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <elf.h>
#include <libelf.h>
#include <gelf.h>

/* ELF helpers taken from libbpf source code */

struct elf_sym {
	const char *name;
	GElf_Sym sym;
	GElf_Shdr sh;
	int ver;
	bool hidden;
};

struct elf_sym_iter {
	Elf *elf;
	Elf_Data *syms;
	Elf_Data *versyms;
	Elf_Data *verdefs;
	size_t nr_syms;
	size_t strtabidx;
	size_t verdef_strtabidx;
	size_t next_sym_idx;
	struct elf_sym sym;
	int st_type;
};

int elf_sym_iter_new(struct elf_sym_iter *it,
		     Elf *elf, const char *binary_path,
		     int sh_type, int st_type);

struct elf_sym *elf_sym_iter_next(struct elf_sym_iter *it);

static inline void elf_sym_iter_destroy(struct elf_sym_iter *it) {}

int elf_find_syms(const char *binary_path, int st_type,
		  const char **syms, long *addrs, size_t cnt);

#endif /* __ELF_UTILS_H__ */
