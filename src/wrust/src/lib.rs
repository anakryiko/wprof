//! libwrust: a single static library exposing Rust standard-library data
//! structures and helpers to wprof's C code over a stable C ABI.
//!
//! Each capability lives in its own module and declares its own `extern "C"`
//! entry points (collected into `libwrust_c.a`). Add new modules here as the
//! need for more Rust-backed interfaces comes up.

mod pq;
mod sort;
