// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <string.h>
#include <elf.h>
#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>
#include <unistd.h>

#include "elf_utils.h"
#include "utils.h"

/* A SHT_GNU_versym section holds 16-bit words. This bit is set if
 * the symbol is hidden and can only be seen when referenced using an
 * explicit version number. This is a GNU extension.
 */
#define VERSYM_HIDDEN	0x8000

/* This is the mask for the rest of the data in a word read from a
 * SHT_GNU_versym section.
 */
#define VERSYM_VERSION	0x7fff

struct elf_fd {
	Elf *elf;
	int fd;
};

static int elf_open(const char *binary_path, struct elf_fd *elf_fd)
{
	int fd;
	Elf *elf;

	elf_fd->elf = NULL;
	elf_fd->fd = -1;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		eprintf("Failed to init libelf for '%s'\n", binary_path);
		return -EOPNOTSUPP;
	}
	fd = open(binary_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		dprintf(2, "Failed open ELF binary '%s': %d\n", binary_path, -errno);
		return -errno;
	}
	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!elf) {
		dprintf(2, "Failed to read ELF file '%s': %s\n", binary_path, elf_errmsg(-1));
		close(fd);
		return -EINVAL;
	}
	elf_fd->fd = fd;
	elf_fd->elf = elf;
	return 0;
}

static void elf_close(struct elf_fd *elf_fd)
{
	if (!elf_fd)
		return;
	elf_end(elf_fd->elf);
	close(elf_fd->fd);
}

/* Return next ELF section of sh_type after scn, or first of that type if scn is NULL. */
static Elf_Scn *elf_find_next_scn_by_type(Elf *elf, int sh_type, Elf_Scn *scn)
{
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		GElf_Shdr sh;

		if (!gelf_getshdr(scn, &sh))
			continue;
		if (sh.sh_type == sh_type)
			return scn;
	}
	return NULL;
}

int elf_sym_iter_new(struct elf_sym_iter *it,
		     Elf *elf, const char *binary_path,
		     int sh_type, int st_type)
{
	Elf_Scn *scn = NULL;
	GElf_Ehdr ehdr;
	GElf_Shdr sh;

	memset(it, 0, sizeof(*it));

	if (!gelf_getehdr(elf, &ehdr)) {
		dprintf(2, "Failed to get ELF ehdr from '%s': %s\n", binary_path, elf_errmsg(-1));
		return -EINVAL;
	}

	scn = elf_find_next_scn_by_type(elf, sh_type, NULL);
	if (!scn) {
		dprintf(2, "Failed to find symbol table ELF sections in '%s'\n", binary_path);
		return -ENOENT;
	}

	if (!gelf_getshdr(scn, &sh))
		return -EINVAL;

	it->strtabidx = sh.sh_link;
	it->syms = elf_getdata(scn, 0);
	if (!it->syms) {
		dprintf(2, "Failed to get symbols for ELF symtab section in '%s': %s\n",
			binary_path, elf_errmsg(-1));
		return -EINVAL;
	}
	it->nr_syms = it->syms->d_size / sh.sh_entsize;
	it->elf = elf;
	it->st_type = st_type;

	/* Version symbol table is meaningful to dynsym only */
	if (sh_type != SHT_DYNSYM)
		return 0;

	scn = elf_find_next_scn_by_type(elf, SHT_GNU_versym, NULL);
	if (!scn)
		return 0;
	it->versyms = elf_getdata(scn, 0);

	scn = elf_find_next_scn_by_type(elf, SHT_GNU_verdef, NULL);
	if (!scn)
		return 0;

	it->verdefs = elf_getdata(scn, 0);
	if (!it->verdefs || !gelf_getshdr(scn, &sh)) {
		dprintf(2, "Failed to get verdef ELF section in '%s'\n", binary_path);
		return -EINVAL;
	}
	it->verdef_strtabidx = sh.sh_link;

	return 0;
}

struct elf_sym *elf_sym_iter_next(struct elf_sym_iter *it)
{
	struct elf_sym *ret = &it->sym;
	GElf_Sym *sym = &ret->sym;
	const char *name = NULL;
	GElf_Versym versym;
	Elf_Scn *sym_scn;
	size_t idx;

	for (idx = it->next_sym_idx; idx < it->nr_syms; idx++) {
		if (!gelf_getsym(it->syms, idx, sym))
			continue;
		if (GELF_ST_TYPE(sym->st_info) != it->st_type)
			continue;
		if (sym->st_shndx == SHN_UNDEF)
			continue;
		name = elf_strptr(it->elf, it->strtabidx, sym->st_name);
		if (!name)
			continue;
		sym_scn = elf_getscn(it->elf, sym->st_shndx);
		if (!sym_scn)
			continue;
		if (!gelf_getshdr(sym_scn, &ret->sh))
			continue;

		it->next_sym_idx = idx + 1;
		ret->name = name;
		ret->ver = 0;
		ret->hidden = false;

		if (it->versyms) {
			if (!gelf_getversym(it->versyms, idx, &versym))
				continue;
			ret->ver = versym & VERSYM_VERSION;
			ret->hidden = versym & VERSYM_HIDDEN;
		}
		return ret;
	}

	return NULL;
}

int elf_read_sym_value(const char *binary_path, const char *sym_name,
		       int st_type, void *buf, size_t buf_sz)
{
	int sh_types[2] = { SHT_DYNSYM, SHT_SYMTAB };
	struct elf_fd elf_fd;
	int err;

	err = elf_open(binary_path, &elf_fd);
	if (err)
		return err;

	for (int i = 0; i < ARRAY_SIZE(sh_types); i++) {
		struct elf_sym *sym;

		wprof_for_each(elf_sym, sym, elf_fd.elf, binary_path, sh_types[i], st_type) {
			if (strcmp(sym->name, sym_name) != 0)
				continue;

			Elf_Scn *scn = elf_getscn(elf_fd.elf, sym->sym.st_shndx);
			if (!scn)
				continue;

			GElf_Shdr shdr;
			if (!gelf_getshdr(scn, &shdr))
				continue;

			Elf_Data *data = elf_getdata(scn, NULL);
			if (!data || !data->d_buf)
				continue;

			size_t offset = sym->sym.st_value - shdr.sh_addr;
			if (offset + buf_sz > data->d_size)
				continue;

			memcpy(buf, (char *)data->d_buf + offset, buf_sz);
			elf_close(&elf_fd);
			return 0;
		}
	}

	elf_close(&elf_fd);
	return -ENOENT;
}

/*
 * Resolve ELF symbols and, for each, optionally compute:
 *   - virt_offs: virtual address offset relative to the binary's base load
 *     address (first PT_LOAD's p_vaddr - p_offset). Callers typically add the
 *     runtime load base (vma_start - vma_offset) to get a runtime address.
 *     For shared libs / PIE binaries this is simply st_value.
 *   - file_offs: file offset of the symbol within the binary file, computed
 *     per-symbol via its containing section's (sh_addr, sh_offset). This is
 *     what uprobe attach APIs want.
 *
 * Either output array may be NULL. Both are populated with 0 for symbols
 * that were not found.
 */
int elf_find_syms(const char *binary_path, int st_type,
		  const char **syms, size_t cnt,
		  unsigned long *virt_offs, unsigned long *file_offs)
{
	int sh_types[2] = { SHT_DYNSYM, SHT_SYMTAB };
	unsigned long st_values[cnt];
	unsigned long sh_addrs[cnt], sh_offsets[cnt];
	int cnt_done = 0;
	struct elf_fd elf_fd;
	int err;

	err = elf_open(binary_path, &elf_fd);
	if (err)
		return err;

	memset(st_values, 0, sizeof(st_values));

	/*
	 * All PT_LOAD segments in ELF should (according to ELF spec) have the same
	 * (p_vaddr - p_offset) difference, which gives us virtual address base address.
	 *
	 * For shared libs and PIE executables that difference has to be zero, so we can skip this
	 * step, but we currently don't for consistency. It's a fast step.
	 *
	 * We later will subtract this base address to give pure offsets as an output.
	 */
	unsigned long base_vaddr = 0;
	GElf_Ehdr ehdr;
	size_t phnum;
	if (!gelf_getehdr(elf_fd.elf, &ehdr) || elf_getphdrnum(elf_fd.elf, &phnum) != 0)
		return -EINVAL; /* invalid ELF */

	for (size_t i = 0; i < phnum; i++) {
		GElf_Phdr phdr;
		if (!gelf_getphdr(elf_fd.elf, i, &phdr))
			return -EINVAL; /* invalid ELF */
		if (phdr.p_type != PT_LOAD)
			continue;

		base_vaddr = phdr.p_vaddr - phdr.p_offset;
		break;
	}

	for (int ti = 0; ti < ARRAY_SIZE(sh_types) && cnt_done < cnt; ti++) {
		struct elf_sym *sym;

		wprof_for_each(elf_sym, sym, elf_fd.elf, binary_path, sh_types[ti], st_type) {
			int bind = GELF_ST_BIND(sym->sym.st_info);

			for (int i = 0; i < cnt; i++) {
				if (strcmp(syms[i], sym->name) != 0)
					continue;
				if (st_values[i] && bind == STB_WEAK)
					continue;
				if (st_values[i] == 0)
					cnt_done++;
				st_values[i] = sym->sym.st_value;
				sh_addrs[i] = sym->sh.sh_addr;
				sh_offsets[i] = sym->sh.sh_offset;
				break;
			}

			if (cnt_done == cnt)
				break;
		}
	}

	elf_close(&elf_fd);

	for (int i = 0; i < cnt; i++) {
		if (virt_offs)
			virt_offs[i] = st_values[i] ? st_values[i] - base_vaddr : 0;
		if (file_offs)
			file_offs[i] = st_values[i] ? st_values[i] - sh_addrs[i] + sh_offsets[i] : 0;
	}

	return cnt_done == cnt ? 0 : -ENOENT;
}

