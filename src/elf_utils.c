// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <string.h>
#include <elf.h>
#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>
#include <unistd.h>
#include <link.h>

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

/*
 * Initialize libelf up front, on the main thread. libelf's selected version is
 * a process-global; pre-setting it here keeps later concurrent ELF parsing from
 * racing on it (each elf_open() sets it too, but always to the same value).
 */
void elf_init(void)
{
	elf_version(EV_CURRENT);
}

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

struct elf_dynsym_hash {
	Elf_Data *hash;
	bool wide_bloom;
	Elf_Data *syms;
	Elf_Data *versyms;
	size_t strtabidx;
};

/* Find .gnu.hash and the dynamic symbol table it indexes. */
static int elf_dynsym_hash_init(Elf *elf, struct elf_dynsym_hash *h)
{
	Elf_Scn *scn, *sym_scn;
	GElf_Shdr sh, sym_sh;

	memset(h, 0, sizeof(*h));

	scn = elf_find_next_scn_by_type(elf, SHT_GNU_HASH, NULL);
	if (!scn || !gelf_getshdr(scn, &sh))
		return -ENOENT;

	sym_scn = elf_getscn(elf, sh.sh_link);
	if (!sym_scn || !gelf_getshdr(sym_scn, &sym_sh) || sym_sh.sh_type != SHT_DYNSYM)
		return -ENOENT;

	h->hash = elf_getdata(scn, NULL);
	h->syms = elf_getdata(sym_scn, NULL);
	if (!h->hash || !h->hash->d_buf || !h->syms)
		return -ENOENT;
	h->strtabidx = sym_sh.sh_link;
	h->wide_bloom = gelf_getclass(elf) == ELFCLASS64;

	scn = elf_find_next_scn_by_type(elf, SHT_GNU_versym, NULL);
	if (scn)
		h->versyms = elf_getdata(scn, NULL);

	return 0;
}

static bool elf_dynsym_match(const struct elf_dynsym_hash *h, Elf *elf, size_t idx,
			     const char *name, int st_type, GElf_Sym *sym, bool *hidden)
{
	GElf_Versym versym;
	const char *sym_name;

	if (!gelf_getsym(h->syms, idx, sym))
		return false;
	if (GELF_ST_TYPE(sym->st_info) != st_type || sym->st_shndx == SHN_UNDEF)
		return false;
	sym_name = elf_strptr(elf, h->strtabidx, sym->st_name);
	if (!sym_name || strcmp(sym_name, name) != 0)
		return false;

	*hidden = h->versyms && gelf_getversym(h->versyms, idx, &versym) && (versym & VERSYM_HIDDEN);
	return true;
}

/*
 * Look up a defined dynamic symbol of st_type through .gnu.hash,
 * preferring the default version of versioned symbols.
 */
static bool elf_dynsym_hash_lookup(const struct elf_dynsym_hash *h, Elf *elf,
				   const char *name, int st_type, GElf_Sym *sym)
{
	const unsigned char *p = (const unsigned char *)name;
	const uint32_t *w = h->hash->d_buf;
	size_t sz = h->hash->d_size;
	bool found = false, hidden;
	uint32_t hash = 5381;
	GElf_Sym cand;

	for (; *p; p++)
		hash = hash * 33 + *p;

	/* nbuckets, sym_idx, bloom_size, bloom_shift, bloom[bloom_size], buckets[nbuckets], chain[] */
	if (sz < 16 || w[0] == 0 || w[2] == 0)
		return false;

	uint32_t nbuckets = w[0], sym_idx = w[1], bloom_size = w[2], bloom_shift = w[3];
	size_t bloom_bits = h->wide_bloom ? 64 : 32;
	size_t buckets_off = 16 + bloom_size * bloom_bits / 8;
	if (buckets_off + (size_t)nbuckets * 4 > sz)
		return false;

	const char *base = h->hash->d_buf;
	size_t bloom_idx = (hash / bloom_bits) % bloom_size;
	uint64_t bloom = h->wide_bloom ? ((const uint64_t *)(base + 16))[bloom_idx]
				       : ((const uint32_t *)(base + 16))[bloom_idx];
	uint64_t mask = (1ULL << (hash % bloom_bits)) | (1ULL << ((hash >> bloom_shift) % bloom_bits));
	if ((bloom & mask) != mask)
		return false;

	const uint32_t *buckets = (const uint32_t *)(base + buckets_off);
	const uint32_t *chain = buckets + nbuckets;
	size_t chain_cnt = (sz - buckets_off) / 4 - nbuckets;
	uint32_t idx = buckets[hash % nbuckets];
	if (idx < sym_idx)
		return false;

	for (; idx - sym_idx < chain_cnt; idx++) {
		uint32_t chain_hash = chain[idx - sym_idx];

		if ((chain_hash | 1) == (hash | 1) &&
		    elf_dynsym_match(h, elf, idx, name, st_type, &cand, &hidden)) {
			*sym = cand;
			found = true;
			if (!hidden)
				break;
		}
		if (chain_hash & 1)
			break;
	}
	return found;
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

static int elf_copy_sym_value(Elf *elf, const GElf_Sym *sym, void *buf, size_t buf_sz)
{
	Elf_Scn *scn = elf_getscn(elf, sym->st_shndx);
	if (!scn)
		return -ENOENT;

	GElf_Shdr shdr;
	if (!gelf_getshdr(scn, &shdr))
		return -ENOENT;

	Elf_Data *data = elf_getdata(scn, NULL);
	if (!data || !data->d_buf)
		return -ENOENT;

	size_t offset = sym->st_value - shdr.sh_addr;
	if (offset + buf_sz > data->d_size)
		return -ENOENT;

	memcpy(buf, (char *)data->d_buf + offset, buf_sz);
	return 0;
}

int elf_read_sym_value(const char *binary_path, const char *sym_name,
		       int st_type, void *buf, size_t buf_sz)
{
	int sh_types[2] = { SHT_DYNSYM, SHT_SYMTAB };
	struct elf_dynsym_hash dh;
	struct elf_fd elf_fd;
	bool has_dynsym_hash;
	GElf_Sym hsym;
	int err;

	err = elf_open(binary_path, &elf_fd);
	if (err)
		return err;

	/* with a hash table, .dynsym needs no scanning, only .symtab might */
	has_dynsym_hash = elf_dynsym_hash_init(elf_fd.elf, &dh) == 0;
	if (!has_dynsym_hash)
		goto scan;

	if (elf_dynsym_hash_lookup(&dh, elf_fd.elf, sym_name, st_type, &hsym) &&
	    elf_copy_sym_value(elf_fd.elf, &hsym, buf, buf_sz) == 0) {
		elf_close(&elf_fd);
		return 0;
	}

scan:
	for (int i = 0; i < ARRAY_SIZE(sh_types); i++) {
		struct elf_sym *sym;

		if (has_dynsym_hash && sh_types[i] == SHT_DYNSYM)
			continue;

		wprof_for_each(elf_sym, sym, elf_fd.elf, binary_path, sh_types[i], st_type) {
			if (strcmp(sym->name, sym_name) != 0)
				continue;
			if (elf_copy_sym_value(elf_fd.elf, &sym->sym, buf, buf_sz) != 0)
				continue;

			elf_close(&elf_fd);
			return 0;
		}
	}

	elf_close(&elf_fd);
	return -ENOENT;
}

bool elf_has_dynsym(const char *binary_path, const char *sym_name, int st_type)
{
	struct elf_dynsym_hash dh;
	struct elf_fd elf_fd;
	struct elf_sym *sym;
	GElf_Sym hsym;
	bool found = false;

	if (elf_open(binary_path, &elf_fd))
		return false;

	if (elf_dynsym_hash_init(elf_fd.elf, &dh) == 0) {
		found = elf_dynsym_hash_lookup(&dh, elf_fd.elf, sym_name, st_type, &hsym);
	} else {
		wprof_for_each(elf_sym, sym, elf_fd.elf, binary_path, SHT_DYNSYM, st_type) {
			if (strcmp(sym->name, sym_name) == 0) {
				found = true;
				break;
			}
		}
	}

	elf_close(&elf_fd);
	return found;
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
	struct elf_dynsym_hash dh;
	bool has_dynsym_hash;
	bool hashed[cnt];
	int cnt_done = 0;
	struct elf_fd elf_fd;
	int err;

	err = elf_open(binary_path, &elf_fd);
	if (err)
		return err;

	memset(file_offs, 0, sizeof(*file_offs) * cnt);
	memset(hashed, 0, sizeof(hashed));

	/* with a hash table, .dynsym needs no scanning, only .symtab might */
	has_dynsym_hash = elf_dynsym_hash_init(elf_fd.elf, &dh) == 0;
	if (!has_dynsym_hash)
		goto scan;

	for (int i = 0; i < cnt; i++) {
		Elf_Scn *scn;
		GElf_Shdr sh;
		GElf_Sym sym;

		if (!elf_dynsym_hash_lookup(&dh, elf_fd.elf, syms[i], st_type, &sym))
			continue;
		scn = elf_getscn(elf_fd.elf, sym.st_shndx);
		if (!scn || !gelf_getshdr(scn, &sh))
			continue;
		file_offs[i] = sym.st_value - sh.sh_addr + sh.sh_offset;
		hashed[i] = true;
		cnt_done++;
	}

scan:
	for (int ti = 0; ti < ARRAY_SIZE(sh_types) && cnt_done < cnt; ti++) {
		struct elf_sym *sym;

		if (has_dynsym_hash && sh_types[ti] == SHT_DYNSYM)
			continue;

		wprof_for_each(elf_sym, sym, elf_fd.elf, binary_path, sh_types[ti], st_type) {
			int bind = GELF_ST_BIND(sym->sym.st_info);

			for (int i = 0; i < cnt; i++) {
				if (strcmp(syms[i], sym->name) != 0)
					continue;
				if (hashed[i])
					break;
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
	struct elf_dynsym_hash dh;
	bool has_dynsym_hash;
	int cnt_done = 0;
	bool hashed[cnt];
	char path[128];
	struct elf_fd ef;
	long base = -ENOENT;
	int err;

	memset(st_values, 0, sizeof(st_values));
	memset(hashed, 0, sizeof(hashed));

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

	/* resolve symbol st_values; with a hash table, .dynsym needs no scanning */
	has_dynsym_hash = elf_dynsym_hash_init(ef.elf, &dh) == 0;
	if (!has_dynsym_hash)
		goto scan;

	for (int i = 0; i < cnt; i++) {
		GElf_Sym sym;

		if (!elf_dynsym_hash_lookup(&dh, ef.elf, syms[i], st_type, &sym))
			continue;
		st_values[i] = sym.st_value;
		hashed[i] = true;
		cnt_done++;
	}

scan:
	for (int ti = 0; ti < ARRAY_SIZE(sh_types) && cnt_done < cnt; ti++) {
		struct elf_sym *sym;

		if (has_dynsym_hash && sh_types[ti] == SHT_DYNSYM)
			continue;

		wprof_for_each(elf_sym, sym, ef.elf, path, sh_types[ti], st_type) {
			int bind = GELF_ST_BIND(sym->sym.st_info);

			for (int i = 0; i < cnt; i++) {
				if (strcmp(syms[i], sym->name) != 0)
					continue;
				if (hashed[i])
					break;
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

bool elf_has_sec(const char *binary_path, const char *sec_name)
{
	struct elf_fd elf_fd;
	bool found;

	if (elf_open(binary_path, &elf_fd))
		return false;
	found = elf_find_sec_by_name(elf_fd.elf, sec_name, NULL) != NULL;
	elf_close(&elf_fd);
	return found;
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

	/* -ESRCH tells the caller the binary itself is unusable, not that it lacks the USDT */
	err = elf_open(binary_path, &ef);
	if (err)
		return -ESRCH;

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

static bool build_id_from_notes(const void *notes, size_t notes_sz, char *buf, size_t buf_sz)
{
	static const char hex[] = "0123456789abcdef";
	const unsigned char *p = notes, *end = p + notes_sz;

	while (p + sizeof(Elf64_Nhdr) <= end) {
		const Elf64_Nhdr *nh = (const void *)p;
		const unsigned char *name = p + sizeof(*nh);
		const unsigned char *desc = name + ((nh->n_namesz + 3) & ~3u);
		const unsigned char *next = desc + ((nh->n_descsz + 3) & ~3u);

		if (next > end)
			break;
		if (nh->n_type == NT_GNU_BUILD_ID && nh->n_namesz == 4 &&
		    memcmp(name, "GNU", 4) == 0 && nh->n_descsz > 0 &&
		    (size_t)nh->n_descsz * 2 + 1 <= buf_sz) {
			for (uint32_t i = 0; i < nh->n_descsz; i++) {
				buf[i * 2] = hex[desc[i] >> 4];
				buf[i * 2 + 1] = hex[desc[i] & 0xf];
			}
			buf[nh->n_descsz * 2] = '\0';
			return true;
		}
		p = next;
	}
	return false;
}

const char *elf_image_build_id(const void *mem, size_t sz, char *buf, size_t buf_sz)
{
	const Elf64_Ehdr *eh = mem;

	if (sz < sizeof(*eh) || memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0)
		return "unknown";

	const Elf64_Phdr *ph = (const void *)((const char *)mem + eh->e_phoff);
	for (unsigned i = 0; i < eh->e_phnum; i++) {
		if (ph[i].p_type != PT_NOTE || ph[i].p_offset + ph[i].p_filesz > sz)
			continue;
		if (build_id_from_notes((const char *)mem + ph[i].p_offset, ph[i].p_filesz, buf, buf_sz))
			return buf;
	}
	return "unknown";
}

struct self_build_id_ctx {
	char *buf;
	size_t buf_sz;
	bool found;
};

static int self_build_id_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	struct self_build_id_ctx *ctx = data;

	for (unsigned i = 0; i < info->dlpi_phnum; i++) {
		const Elf64_Phdr *ph = &info->dlpi_phdr[i];

		if (ph->p_type != PT_NOTE)
			continue;
		if (build_id_from_notes((const void *)(info->dlpi_addr + ph->p_vaddr),
					ph->p_memsz, ctx->buf, ctx->buf_sz)) {
			ctx->found = true;
			break;
		}
	}
	return 1; /* only the main executable, which is the first object */
}

const char *elf_self_build_id(void)
{
	static char buf[2 * 64 + 1];
	static bool done;

	if (!done) {
		struct self_build_id_ctx ctx = { .buf = buf, .buf_sz = sizeof(buf) };

		dl_iterate_phdr(self_build_id_cb, &ctx);
		done = true;
	}
	return buf[0] ? buf : "unknown";
}
