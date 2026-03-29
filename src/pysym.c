// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Meta Platforms, Inc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/uio.h>
#include <bpf/bpf.h>

#include "pysym.h"
#include "pyline.h"
#include "pydisc.h"
#include "utils.h"

/* matches strobelight-libs BPF_LIB_DEFAULT_MAP_SIZE */
#define PYSYM_MAX_ENTRIES 1024

#define PYSYM_FILE_NAME_LEN 192
#define PYSYM_QUAL_NAME_LEN 224

#define PYSYM_MAX_LINETABLE_SIZE (1 * 1024 * 1024)

struct pysym_entry {
	char filename[PYSYM_FILE_NAME_LEN];
	char qualname[PYSYM_QUAL_NAME_LEN];
};

struct pysym_linetable {
	uint8_t *data;
	uint32_t data_len;
	uint32_t first_line;
	int py_minor;
};

static struct pysym_entry *pysym_entries;
static struct pysym_linetable *pysym_linetables;
static uint32_t pysym_cnt;

/*
 * BPF map key: struct pystacks_symbol { read_file_name (200), read_qualified_name (232), pid_t (4) }
 * BPF map value: symbol_id_t (uint32_t)
 *
 * We iterate the map and build an array indexed by symbol_id.
 */
int pysym_init(int symbols_map_fd, int linetables_map_fd)
{
	/* pystacks_symbol key layout from strobelight-libs */
	struct {
		char filename[PYSYM_FILE_NAME_LEN];
		uintptr_t filename_fault_addr;
		char qualname[PYSYM_QUAL_NAME_LEN];
		uintptr_t qualname_fault_addr;
		int fault_pid;
	} key, next_key;

	uint32_t symbol_id;
	int err;

	pysym_entries = calloc(PYSYM_MAX_ENTRIES, sizeof(*pysym_entries));
	if (!pysym_entries)
		return -ENOMEM;

	pysym_linetables = calloc(PYSYM_MAX_ENTRIES, sizeof(*pysym_linetables));
	if (!pysym_linetables) {
		free(pysym_entries);
		pysym_entries = NULL;
		return -ENOMEM;
	}

	pysym_cnt = 0;

	memset(&key, 0, sizeof(key));
	err = bpf_map_get_next_key(symbols_map_fd, NULL, &next_key);
	while (err == 0) {
		key = next_key;

		if (bpf_map_lookup_elem(symbols_map_fd, &key, &symbol_id) == 0) {
			if (symbol_id < PYSYM_MAX_ENTRIES) {
				struct pysym_entry *e = &pysym_entries[symbol_id];

				snprintf(e->filename, sizeof(e->filename), "%s", key.filename);
				snprintf(e->qualname, sizeof(e->qualname), "%s", key.qualname);

				if (symbol_id >= pysym_cnt)
					pysym_cnt = symbol_id + 1;
			}
		}

		err = bpf_map_get_next_key(symbols_map_fd, &key, &next_key);
	}

	/*
	 * Read line tables from the pystacks_linetables BPF map.
	 * Key = symbol_id_t (u32), Value = pystacks_line_table { first_line, length, addr, pid }
	 */
	struct {
		uint32_t first_line;
		uint32_t length;
		uintptr_t addr;
		int pid;
	} lt_val;

	uint32_t lt_key, lt_next_key;
	uint32_t lt_loaded = 0;

	err = bpf_map_get_next_key(linetables_map_fd, NULL, &lt_next_key);
	while (err == 0) {
		lt_key = lt_next_key;

		if (bpf_map_lookup_elem(linetables_map_fd, &lt_key, &lt_val) == 0 &&
		    lt_key < PYSYM_MAX_ENTRIES && lt_val.length > 0 &&
		    lt_val.length <= PYSYM_MAX_LINETABLE_SIZE && lt_val.addr != 0) {
			uint8_t *buf = malloc(lt_val.length);
			if (buf) {
				struct iovec local = { .iov_base = buf, .iov_len = lt_val.length };
				struct iovec remote = { .iov_base = (void *)lt_val.addr, .iov_len = lt_val.length };

				ssize_t n = process_vm_readv(lt_val.pid, &local, 1, &remote, 1, 0);
				if (n == (ssize_t)lt_val.length) {
					struct pysym_linetable *lt = &pysym_linetables[lt_key];
					lt->data = buf;
					lt->data_len = lt_val.length;
					lt->first_line = lt_val.first_line;
					lt->py_minor = pydisc_py_minor(lt_val.pid);
					lt_loaded++;
				} else {
					free(buf);
				}
			}
		}

		err = bpf_map_get_next_key(linetables_map_fd, &lt_key, &lt_next_key);
	}

	vprintf("Loaded %u Python symbols and %u line tables from BPF maps.\n", pysym_cnt, lt_loaded);
	return 0;
}

void pysym_free(void)
{
	if (pysym_linetables) {
		for (uint32_t i = 0; i < PYSYM_MAX_ENTRIES; i++)
			free(pysym_linetables[i].data);
		free(pysym_linetables);
		pysym_linetables = NULL;
	}
	free(pysym_entries);
	pysym_entries = NULL;
	pysym_cnt = 0;
}

const char *pysym_filename(uint32_t id)
{
	if (!pysym_entries || id >= pysym_cnt)
		return NULL;
	return pysym_entries[id].filename[0] ? pysym_entries[id].filename : NULL;
}

const char *pysym_qualname(uint32_t id)
{
	if (!pysym_entries || id >= pysym_cnt)
		return NULL;
	return pysym_entries[id].qualname[0] ? pysym_entries[id].qualname : NULL;
}

uint32_t pysym_line_number(uint32_t symbol_id, int32_t inst_idx)
{
	if (!pysym_linetables || symbol_id >= PYSYM_MAX_ENTRIES)
		return 0;

	struct pysym_linetable *lt = &pysym_linetables[symbol_id];
	if (!lt->data)
		return 0;

	return pyline_resolve(lt->data, lt->data_len, lt->first_line, inst_idx, lt->py_minor);
}
