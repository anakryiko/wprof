/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __PYLINE_H_
#define __PYLINE_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Resolve a bytecode instruction index to a source line number
 * using a CPython line table.
 *
 * @data:       raw line table bytes (read from process memory)
 * @data_len:   length of line table data in bytes
 * @first_line: co_firstlineno of the code object
 * @inst_idx:   bytecode instruction index (lasti)
 * @py_minor:   CPython minor version (10 = 3.10, 11 = 3.11, etc.)
 *
 * Returns resolved line number, or 0 if resolution fails.
 */
uint32_t pyline_resolve(const uint8_t *data, size_t data_len,
			uint32_t first_line, int32_t inst_idx, int py_minor);

#endif /* __PYLINE_H_ */
