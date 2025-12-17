// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//! C-compatible symbol demangling for C++ symbols.
//!
//! Provides a zero-allocation API that writes demangled names directly
//! into caller-provided buffers.

use std::ffi::CStr;
use std::fmt::Write;
use std::os::raw::c_char;

const EINVAL: isize = 22;
const ENOENT: isize = 2;
const E2BIG: isize = 7;

/// A fixed-capacity buffer that implements fmt::Write for zero-allocation demangling.
struct FixedBuf<'a> {
    buf: &'a mut [u8],
    pos: usize,
    overflow: bool,
}

impl<'a> FixedBuf<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0, overflow: false }
    }
}

impl Write for FixedBuf<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let bytes = s.as_bytes();
        let remaining = self.buf.len() - self.pos;
        if bytes.len() > remaining {
            self.overflow = true;
            return Err(std::fmt::Error);
        }
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        Ok(())
    }
}

/// Demangle a C++ symbol name into a caller-provided buffer.
///
/// # Arguments
/// * `mangled` - NUL-terminated mangled symbol name
/// * `out_buf` - Output buffer for demangled name (will be NUL-terminated)
/// * `buf_len` - Size of output buffer in bytes
///
/// # Returns
/// * Length of demangled string (excluding NUL terminator) on success
/// * -EINVAL if arguments are invalid (NULL pointers, zero buffer size, invalid UTF-8)
/// * -ENOENT if the symbol is not a valid mangled C++ name
/// * -E2BIG if the buffer is too small for the demangled name
///
/// # Safety
/// * `mangled` must be a valid NUL-terminated string
/// * `out_buf` must point to a buffer of at least `buf_len` bytes
#[no_mangle]
pub unsafe extern "C" fn demangle_symbol(
    mangled: *const c_char,
    out_buf: *mut c_char,
    buf_len: usize,
) -> isize {
    if mangled.is_null() || out_buf.is_null() || buf_len == 0 {
        return -EINVAL;
    }

    let Ok(name) = CStr::from_ptr(mangled).to_str() else {
        return -EINVAL;
    };

    // Leave room for NUL terminator
    let buf = std::slice::from_raw_parts_mut(out_buf as *mut u8, buf_len - 1);
    let mut writer = FixedBuf::new(buf);

    // Try C++ demangling
    let Ok(sym) = cpp_demangle::Symbol::new(name) else {
        return -ENOENT;
    };

    let opts = cpp_demangle::DemangleOptions::default();
    if sym.structured_demangle(&mut writer, &opts).is_err() {
        return if writer.overflow { -E2BIG } else { -ENOENT };
    }

    // NUL-terminate
    *out_buf.add(writer.pos) = 0;
    writer.pos as isize
}
