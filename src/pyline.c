// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Meta Platforms, Inc. */

/*
 * CPython line table parsers.
 *
 * Ported from strobelight-libs PyLineTable.cpp. Supports:
 *   - Python 3.10: lnotab format (pairs of uint8 offset_delta, int8 line_delta)
 *   - Python 3.11+: location table format (varint-encoded entries)
 *
 * Reference:
 *   3.10 lnotab: https://github.com/python/cpython/blob/3.10/Objects/lnotab_notes.txt
 *   3.11+ locations: https://github.com/python/cpython/blob/3.11/Objects/locations.md
 */
#include "pyline.h"

#define PY_CODEUNIT_SIZE 2

/* Python 3.10 lnotab format */
static uint32_t pyline_resolve_310(const uint8_t *data, size_t data_len,
				   uint32_t first_line, int32_t inst_idx)
{
	if (inst_idx < 0)
		return first_line;

	uint32_t offset = (uint32_t)inst_idx * PY_CODEUNIT_SIZE;
	int line = (int)first_line;
	uint32_t start, end = 0;
	size_t entry_cnt = data_len / 2;

	for (size_t i = 0; i < entry_cnt; i++) {
		uint8_t offset_delta = data[i * 2];
		int8_t line_delta = (int8_t)data[i * 2 + 1];

		if (line_delta == 0) {
			end += offset_delta;
			continue;
		}
		start = end;
		end = start + offset_delta;

		/* -128 means no valid line number */
		if (line_delta == -128)
			continue;

		line += line_delta;

		if (end == start)
			continue;

		if (start <= offset && offset < end)
			return (uint32_t)line;
	}

	return 0;
}

/* Varint helpers for Python 3.11+ location table */
struct pyline_reader {
	const uint8_t *data;
	size_t len;
	size_t pos;
};

static inline int pyline_read(struct pyline_reader *r)
{
	if (r->pos >= r->len)
		return -1;
	return r->data[r->pos++];
}

static inline int pyline_read_varint(struct pyline_reader *r)
{
	int b = pyline_read(r);
	if (b < 0)
		return -1;

	unsigned int val = b & 63;
	unsigned int shift = 0;
	while (b & 64) {
		b = pyline_read(r);
		if (b < 0)
			return -1;
		shift += 6;
		val += (unsigned int)(b & 63) << shift;
	}
	return (int)val;
}

static inline int pyline_read_signed_varint(struct pyline_reader *r)
{
	int uval = pyline_read_varint(r);
	if (uval < 0)
		return 0;
	if (uval & 1)
		return -(uval >> 1);
	return uval >> 1;
}

/* Python 3.11+ location table format */
static uint32_t pyline_resolve_default(const uint8_t *data, size_t data_len,
				       uint32_t first_line, int32_t inst_idx)
{
	if (inst_idx < 0)
		return first_line;

	uint32_t offset = (uint32_t)inst_idx * PY_CODEUNIT_SIZE;
	int line_number = (int)first_line;
	int32_t addr = 0;

	struct pyline_reader r = { .data = data, .len = data_len, .pos = 0 };

	while (r.pos < r.len) {
		int byte = pyline_read(&r);
		if (byte < 0)
			break;

		int32_t delta = (byte & 7) + 1;
		uint8_t code = (byte >> 3) & 15;

		int line_delta;
		if (code == 15) {
			line_delta = 0;
		} else if (code == 14) {
			line_delta = pyline_read_signed_varint(&r);
			pyline_read_varint(&r); /* end line */
			pyline_read_varint(&r); /* start column */
			pyline_read_varint(&r); /* end column */
		} else if (code == 13) {
			line_delta = pyline_read_signed_varint(&r);
		} else if (code >= 10 && code <= 12) {
			line_delta = code - 10;
			pyline_read(&r); /* start column */
			pyline_read(&r); /* end column */
		} else {
			line_delta = 0;
			pyline_read(&r); /* column */
		}
		line_number += line_delta;

		int32_t end_addr = addr + delta * PY_CODEUNIT_SIZE;
		if (offset >= (uint32_t)addr && offset < (uint32_t)end_addr)
			return (uint32_t)line_number;
		if ((uint32_t)end_addr > offset)
			break;
		addr = end_addr;
	}

	return 0;
}

uint32_t pyline_resolve(const uint8_t *data, size_t data_len,
			uint32_t first_line, int32_t inst_idx, int py_minor)
{
	if (!data || data_len == 0)
		return 0;

	if (py_minor <= 10)
		return pyline_resolve_310(data, data_len, first_line, inst_idx);
	return pyline_resolve_default(data, data_len, first_line, inst_idx);
}
