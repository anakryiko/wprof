use std::ffi::{c_char, c_int};
use std::fmt;

extern "C" {
    fn log_printf(verbosity: c_int, fmt: *const c_char, ...);
}

pub(crate) fn vprintf(args: fmt::Arguments<'_>) {
    let msg = args.to_string();
    unsafe {
        log_printf(
            1,
            c"%.*s".as_ptr(),
            msg.len() as c_int,
            msg.as_ptr().cast::<c_char>(),
        );
    }
}
