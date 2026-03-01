/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 Meta Platforms, Inc. */
#ifndef __PYOFFSETS_H_
#define __PYOFFSETS_H_

/*
 * Pre-computed CPython struct field offsets for Python 3.10 through 3.13.
 *
 * Each version function sets only the fields relevant to that version;
 * all other fields remain at BPF_LIB_DEFAULT_FIELD_OFFSET (9999) sentinel,
 * meaning "field doesn't exist in this version."
 *
 * These offsets are for x86_64 Linux. They encode struct layouts from
 * upstream CPython and may differ on other architectures.
 */

#include "strobelight/bpf_lib/python/include/OffsetConfig.h"

#define _D BPF_LIB_DEFAULT_FIELD_OFFSET

#define PYOFFSETS_DEFAULTS			\
	.PyObject_type = _D,			\
	.PyTypeObject_name = _D,		\
	.PyThreadState_frame = _D,		\
	.PyThreadState_cframe = _D,		\
	.PyThreadState_thread = _D,		\
	.PyThreadState_interp = _D,		\
	.PyInterpreterState_modules = _D,	\
	._PyCFrame_current_frame = _D,		\
	.PyFrameObject_back = _D,		\
	.PyFrameObject_code = _D,		\
	.PyFrameObject_lasti = _D,		\
	.PyFrameObject_localsplus = _D,		\
	.PyFrameObject_gen = _D,		\
	.PyInterpreterFrame_code = _D,		\
	.PyInterpreterFrame_previous = _D,	\
	.PyInterpreterFrame_localsplus = _D,	\
	.PyInterpreterFrame_prev_instr = _D,	\
	.PyCodeObject_co_flags = _D,		\
	.PyCodeObject_filename = _D,		\
	.PyCodeObject_name = _D,		\
	.PyCodeObject_varnames = _D,		\
	.PyCodeObject_firstlineno = _D,		\
	.PyCodeObject_linetable = _D,		\
	.PyCodeObject_code_adaptive = _D,	\
	.PyTupleObject_item = _D,		\
	.PyCodeObject_qualname = _D,		\
	.PyCoroObject_cr_awaiter = _D,		\
	.String_data = _D,			\
	.TLSKey_offset = _D,			\
	.TCurrentState_offset = _D,		\
	.PyGIL_offset = _D,			\
	.PyGIL_last_holder = _D,		\
	.PyBytesObject_data = _D,		\
	.PyVarObject_size = _D,			\
	.PyFrameObject_owner = _D,		\
	.PyGenObject_iframe = _D,		\
	.PyVersion_major = 0,			\
	.PyVersion_minor = 0,			\
	.PyVersion_micro = 0

/*
 * CPython 3.10 offsets.
 * Uses traditional PyFrameObject (old-style _frame).
 */
static inline void pyoffsets_v3_10(OffsetConfig *c)
{
	*c = (OffsetConfig){
		PYOFFSETS_DEFAULTS,
		.PyObject_type = 8,
		.PyTypeObject_name = 24,
		.PyVarObject_size = 16,
		.PyTupleObject_item = 24,
		.PyBytesObject_data = 32,
		.String_data = 48,
		.PyThreadState_frame = 24,
		.PyThreadState_thread = 176,
		.PyThreadState_interp = 16,
		.PyFrameObject_back = 24,
		.PyFrameObject_code = 32,
		.PyFrameObject_lasti = 96,
		.PyFrameObject_localsplus = 352,
		.PyFrameObject_gen = 88,
		.PyCodeObject_co_flags = 36,
		.PyCodeObject_filename = 104,
		.PyCodeObject_name = 112,
		.PyCodeObject_varnames = 72,
		.PyCodeObject_firstlineno = 40,
		.PyCodeObject_linetable = 120,
		.TLSKey_offset = 588,
		.TCurrentState_offset = 568,
		.PyGIL_offset = 368,
		.PyGIL_last_holder = 360,
		.PyInterpreterState_modules = 856,
		.PyVersion_major = 3,
		.PyVersion_minor = 10,
	};
}

/*
 * CPython 3.11 offsets.
 * Introduces _PyCFrame and _PyInterpreterFrame (replaces old PyFrameObject).
 */
static inline void pyoffsets_v3_11(OffsetConfig *c)
{
	*c = (OffsetConfig){
		PYOFFSETS_DEFAULTS,
		.PyObject_type = 8,
		.PyTypeObject_name = 24,
		.PyVarObject_size = 16,
		.PyTupleObject_item = 24,
		.PyBytesObject_data = 32,
		.String_data = 48,
		.PyThreadState_cframe = 56,
		.PyThreadState_thread = 152,
		._PyCFrame_current_frame = 8,
		.PyInterpreterFrame_code = 32,
		.PyInterpreterFrame_previous = 48,
		.PyInterpreterFrame_localsplus = 72,
		.PyInterpreterFrame_prev_instr = 56,
		.PyCodeObject_co_flags = 48,
		.PyCodeObject_filename = 112,
		.PyCodeObject_name = 120,
		.PyCodeObject_qualname = 128,
		.PyCodeObject_linetable = 136,
		.PyCodeObject_firstlineno = 72,
		.TLSKey_offset = 596,
		.TCurrentState_offset = 576,
		.PyGIL_offset = 376,
		.PyGIL_last_holder = 368,
		.PyVersion_major = 3,
		.PyVersion_minor = 11,
	};
}

/*
 * CPython 3.12 offsets.
 * CFrame current_frame offset changes to 0. PyASCIIObject shrinks to 40.
 * GIL moves to per-interpreter state (TCurrentState_offset no longer used,
 * use TLS instead). Adds code_adaptive, generator/coroutine offsets.
 */
static inline void pyoffsets_v3_12(OffsetConfig *c)
{
	*c = (OffsetConfig){
		PYOFFSETS_DEFAULTS,
		.PyObject_type = 8,
		.PyTypeObject_name = 24,
		.PyVarObject_size = 16,
		.PyTupleObject_item = 24,
		.PyBytesObject_data = 32,
		.String_data = 40,
		.PyThreadState_cframe = 56,
		.PyThreadState_thread = 136,
		.PyThreadState_interp = 16,
		._PyCFrame_current_frame = 0,
		.PyInterpreterFrame_code = 0,
		.PyInterpreterFrame_previous = 8,
		.PyInterpreterFrame_localsplus = 72,
		.PyInterpreterFrame_prev_instr = 56,
		.PyCodeObject_co_flags = 48,
		.PyCodeObject_filename = 112,
		.PyCodeObject_name = 120,
		.PyCodeObject_qualname = 128,
		.PyCodeObject_linetable = 136,
		.PyCodeObject_firstlineno = 68,
		.PyCodeObject_code_adaptive = 192,
		.PyCoroObject_cr_awaiter = 56,
		.PyGenObject_iframe = 72,
		.PyFrameObject_owner = 70,
		.TLSKey_offset = 1548,
		.PyInterpreterState_modules = 944,
		.PyVersion_major = 3,
		.PyVersion_minor = 12,
	};
}

/*
 * CPython 3.13 offsets.
 * Removes _PyCFrame indirection: current_frame is directly on PyThreadState
 * at offset 72. We store this in PyThreadState_cframe and leave
 * _PyCFrame_current_frame at sentinel (no second dereference).
 * code_adaptive offset shifts to 200.
 */
static inline void pyoffsets_v3_13(OffsetConfig *c)
{
	*c = (OffsetConfig){
		PYOFFSETS_DEFAULTS,
		.PyObject_type = 8,
		.PyTypeObject_name = 24,
		.PyVarObject_size = 16,
		.PyTupleObject_item = 24,
		.PyBytesObject_data = 32,
		.String_data = 40,
		.PyThreadState_cframe = 72,
		.PyThreadState_thread = 152,
		.PyThreadState_interp = 16,
		.PyInterpreterFrame_code = 0,
		.PyInterpreterFrame_previous = 8,
		.PyInterpreterFrame_localsplus = 72,
		.PyInterpreterFrame_prev_instr = 56,
		.PyCodeObject_co_flags = 48,
		.PyCodeObject_filename = 112,
		.PyCodeObject_name = 120,
		.PyCodeObject_qualname = 128,
		.PyCodeObject_linetable = 136,
		.PyCodeObject_firstlineno = 68,
		.PyCodeObject_code_adaptive = 200,
		.PyCoroObject_cr_awaiter = 56,
		.PyGenObject_iframe = 72,
		.PyFrameObject_owner = 70,
		.TLSKey_offset = 2164,
		.PyInterpreterState_modules = 7656,
		.PyVersion_major = 3,
		.PyVersion_minor = 13,
	};
}

#undef _D

/*
 * Returns 0 on success, -1 if version is unsupported.
 * Falls back to 3.13 for unknown minor versions > 13.
 */
static inline int pyoffsets_for_version(int major, int minor, OffsetConfig *c)
{
	if (major != 3)
		return -1;

	switch (minor) {
	case 10: pyoffsets_v3_10(c); return 0;
	case 11: pyoffsets_v3_11(c); return 0;
	case 12: pyoffsets_v3_12(c); return 0;
	case 13: pyoffsets_v3_13(c); return 0;
	default:
		if (minor > 13) {
			pyoffsets_v3_13(c); /* fallback to latest known */
			return 0;
		}
		return -1;
	}
}

#endif /* __PYOFFSETS_H_ */
