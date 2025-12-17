/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef DEMANGLE_H
#define DEMANGLE_H

#include <stddef.h>
#include <sys/types.h>

/**
 * demangle_symbol - Demangle a C++ symbol name
 * @mangled: NUL-terminated mangled symbol name
 * @out_buf: Output buffer for demangled name (will be NUL-terminated)
 * @buf_len: Size of output buffer in bytes
 *
 * Returns: Length of demangled string (excluding NUL) on success,
 *          -EINVAL if arguments are invalid (NULL pointers, zero size, bad UTF-8),
 *          -ENOENT if the symbol is not a valid mangled C++ name,
 *          -E2BIG if the buffer is too small for the demangled name.
 */
ssize_t demangle_symbol(const char *mangled, char *out_buf, size_t buf_len);

#endif /* DEMANGLE_H */
