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
 * Find ELF symbols and return their file offsets (for uprobe attach).
 * File offset is computed per-symbol via its containing section's
 * (sh_addr, sh_offset): file_off = st_value - sh_addr + sh_offset.
 */
int elf_find_syms(const char *binary_path, int st_type,
		  const char **syms, size_t cnt, unsigned long *file_offs)
{
	int sh_types[2] = { SHT_DYNSYM, SHT_SYMTAB };
	int cnt_done = 0;
	struct elf_fd elf_fd;
	int err;

	err = elf_open(binary_path, &elf_fd);
	if (err)
		return err;

	memset(file_offs, 0, sizeof(*file_offs) * cnt);

	for (int ti = 0; ti < ARRAY_SIZE(sh_types) && cnt_done < cnt; ti++) {
		struct elf_sym *sym;

		wprof_for_each(elf_sym, sym, elf_fd.elf, binary_path, sh_types[ti], st_type) {
			int bind = GELF_ST_BIND(sym->sym.st_info);

			for (int i = 0; i < cnt; i++) {
				if (strcmp(syms[i], sym->name) != 0)
					continue;
				if (file_offs[i] && bind == STB_WEAK)
					continue;
				unsigned long off = sym->sym.st_value - sym->sh.sh_addr + sym->sh.sh_offset;
				if (file_offs[i] && file_offs[i] != off) {
					eprintf("elf: ambiguous symbol '%s' in '%s'\n", syms[i], binary_path);
					elf_close(&elf_fd);
					return -EEXIST;
				}
				if (file_offs[i] == 0)
					cnt_done++;
				file_offs[i] = off;
				break;
			}

			if (cnt_done == cnt)
				break;
		}
	}

	elf_close(&elf_fd);

	return cnt_done == cnt ? 0 : -ENOENT;
}

/*
 * Resolve symbols to absolute runtime addresses. Opens the ELF once via
 * /proc/<pid>/map_files/, computes the base load address from the VMA's
 * corresponding PT_LOAD segment, and returns base + st_value for each symbol.
 */
int elf_resolve_syms(int pid, unsigned long vma_start, unsigned long vma_end,
		     unsigned long vma_offset, int st_type,
		     const char **syms, size_t cnt, unsigned long *addrs)
{
	int sh_types[2] = { SHT_DYNSYM, SHT_SYMTAB };
	unsigned long st_values[cnt];
	int cnt_done = 0;
	char path[128];
	struct elf_fd ef;
	long base = -ENOENT;
	int err;

	memset(st_values, 0, sizeof(st_values));

	snprintf(path, sizeof(path), "/proc/%d/map_files/%llx-%llx",
		 pid, (unsigned long long)vma_start, (unsigned long long)vma_end);

	err = elf_open(path, &ef);
	if (err)
		return err;

	/* find base load address by matching VMA file offset to a PT_LOAD segment */
	GElf_Ehdr ehdr;
	size_t phnum;
	if (!gelf_getehdr(ef.elf, &ehdr) || elf_getphdrnum(ef.elf, &phnum) != 0) {
		elf_close(&ef);
		return -EINVAL;
	}
	for (size_t i = 0; i < phnum; i++) {
		GElf_Phdr phdr;
		if (!gelf_getphdr(ef.elf, i, &phdr)) {
			elf_close(&ef);
			return -EINVAL;
		}
		if (phdr.p_type != PT_LOAD)
			continue;
		if ((phdr.p_offset & ~(phdr.p_align - 1)) != vma_offset)
			continue;
		base = vma_start - (phdr.p_vaddr & ~(phdr.p_align - 1));
		break;
	}
	if (base < 0) {
		elf_close(&ef);
		return base;
	}

	/* resolve symbol st_values */
	for (int ti = 0; ti < ARRAY_SIZE(sh_types) && cnt_done < cnt; ti++) {
		struct elf_sym *sym;

		wprof_for_each(elf_sym, sym, ef.elf, path, sh_types[ti], st_type) {
			int bind = GELF_ST_BIND(sym->sym.st_info);

			for (int i = 0; i < cnt; i++) {
				if (strcmp(syms[i], sym->name) != 0)
					continue;
				if (st_values[i] && bind == STB_WEAK)
					continue;
				if (st_values[i] && st_values[i] != sym->sym.st_value) {
					eprintf("elf: ambiguous symbol '%s' in '%s'\n", syms[i], path);
					elf_close(&ef);
					return -EEXIST;
				}
				if (st_values[i] == 0)
					cnt_done++;
				st_values[i] = sym->sym.st_value;
				break;
			}

			if (cnt_done == cnt)
				break;
		}
	}

	elf_close(&ef);

	for (size_t i = 0; i < cnt; i++)
		addrs[i] = st_values[i] ? base + st_values[i] : 0;

	return cnt_done == cnt ? 0 : -ENOENT;
}

#define USDT_NOTE_SEC  ".note.stapsdt"
#define USDT_NOTE_TYPE 3
#define USDT_NOTE_NAME "stapsdt"

static Elf_Scn *elf_find_sec_by_name(Elf *elf, const char *name, GElf_Shdr *shdr_out)
{
	size_t shstrndx;

	if (elf_getshdrstrndx(elf, &shstrndx))
		return NULL;

	Elf_Scn *scn = NULL;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		GElf_Shdr sh;

		if (!gelf_getshdr(scn, &sh))
			continue;
		const char *sec_name = elf_strptr(elf, shstrndx, sh.sh_name);
		if (sec_name && strcmp(sec_name, name) == 0) {
			if (shdr_out)
				*shdr_out = sh;
			return scn;
		}
	}
	return NULL;
}

/*
 * Parse a single USDT ELF note from '.note.stapsdt' section.
 * Adapted from libbpf's parse_usdt_note().
 */
static int parse_usdt_note(GElf_Nhdr *nhdr, const char *data, size_t name_off, size_t desc_off,
			   const char **provider_out, const char **name_out, const char **args_out)
{
	const char *provider, *name, *args;
	long addrs[3];
	size_t len;

	if (strncmp(data + name_off, USDT_NOTE_NAME, nhdr->n_namesz) != 0)
		return -EINVAL;
	if (nhdr->n_type != USDT_NOTE_TYPE)
		return -EINVAL;

	len = nhdr->n_descsz;
	data = data + desc_off;

	/* descriptor: 3 longs (loc, base, sema) followed by null-terminated strings */
	if (len < sizeof(addrs) + 3)
		return -EINVAL;

	provider = data + sizeof(addrs);

	name = memchr(provider, '\0', data + len - provider);
	if (!name)
		return -EINVAL;
	name++;
	if (name >= data + len || *name == '\0')
		return -EINVAL;

	args = memchr(name, '\0', data + len - name);
	if (!args)
		return -EINVAL;
	args++;
	if (args >= data + len)
		return -EINVAL;

	*provider_out = provider;
	*name_out = name;
	*args_out = (*args == '\0' || *args == ':') ? "" : args;
	return 0;
}

/*
 * Parse USDT arg spec string to extract count and sizes.
 * Format: "-4@%edi -4@-1204(%rbp) 8@%rdx" -- we only parse the <size>@ prefix.
 */
static int parse_usdt_arg_info(const char *args, struct usdt_info *info)
{
	const char *s = args;
	int i = 0;

	memset(info, 0, sizeof(*info));

	while (*s && i < MAX_USDT_ARGS) {
		int sz, n = 0;

		if (sscanf(s, " %d @ %n", &sz, &n) < 1 || n == 0)
			return -EINVAL;
		info->args[i].is_signed = sz < 0;
		info->args[i].size = sz < 0 ? -sz : sz;
		i++;
		s += n;
		while (*s && *s != ' ')
			s++;
	}
	info->arg_cnt = i;
	return 0;
}

int elf_find_usdt(const char *binary_path, const char *provider, const char *name,
		  struct usdt_info *info)
{
	struct elf_fd ef;
	int err;

	err = elf_open(binary_path, &ef);
	if (err)
		return err;

	GElf_Shdr shdr;
	Elf_Scn *scn = elf_find_sec_by_name(ef.elf, USDT_NOTE_SEC, &shdr);
	if (!scn || shdr.sh_type != SHT_NOTE) {
		elf_close(&ef);
		return -ENOENT;
	}

	Elf_Data *data = elf_getdata(scn, 0);
	if (!data) {
		elf_close(&ef);
		return -EINVAL;
	}

	size_t off = 0, name_off, desc_off;
	GElf_Nhdr nhdr;
	err = -ENOENT;

	while ((off = gelf_getnote(data, off, &nhdr, &name_off, &desc_off)) > 0) {
		const char *note_provider, *note_name, *note_args;

		if (parse_usdt_note(&nhdr, data->d_buf, name_off, desc_off,
				    &note_provider, &note_name, &note_args))
			continue;

		if (strcmp(note_provider, provider) != 0 || strcmp(note_name, name) != 0)
			continue;

		err = parse_usdt_arg_info(note_args, info);
		if (err) {
			eprintf("usdt: failed to parse arg spec '%s' for '%s:%s' in '%s'\n",
				note_args, provider, name, binary_path);
			elf_close(&ef);
			return err;
		}
		elf_close(&ef);
		return 0;
	}

	elf_close(&ef);
	return -ENOENT;
}
