//! Min priority queue over `(key, value)` pairs, backed by the standard
//! library's `BinaryHeap`.
//!
//! `BinaryHeap` is a max-heap, so elements are wrapped in `Reverse` to make it
//! a min-heap. Ordering is ascending and lexicographic on `(key, value)`, so
//! `value` breaks ties on `key` deterministically. The merge phase uses this
//! with `key = timestamp` and `value = stream index`, which reproduces the
//! lowest-index-wins behavior of the old linear scan.

use core::ffi::c_void;
use std::cmp::Reverse;
use std::collections::BinaryHeap;

pub struct WPq {
    inner: BinaryHeap<Reverse<(u64, u32)>>,
}

#[no_mangle]
pub extern "C" fn wpq_new(cap: usize) -> *mut WPq {
    Box::into_raw(Box::new(WPq {
        inner: BinaryHeap::with_capacity(cap),
    }))
}

#[no_mangle]
pub extern "C" fn wpq_free(pq: *mut WPq) {
    if !pq.is_null() {
        drop(unsafe { Box::from_raw(pq) });
    }
}

#[no_mangle]
pub extern "C" fn wpq_push(pq: *mut WPq, key: u64, val: u32) {
    let pq = unsafe { &mut *pq };
    pq.inner.push(Reverse((key, val)));
}

#[no_mangle]
pub extern "C" fn wpq_empty(pq: *const WPq) -> bool {
    let pq = unsafe { &*pq };
    pq.inner.is_empty()
}

#[no_mangle]
pub extern "C" fn wpq_peek(pq: *const WPq, key: *mut u64, val: *mut u32) {
    let pq = unsafe { &*pq };
    let Reverse((k, v)) = pq.inner.peek().expect("wpq_peek on empty queue");
    unsafe {
        *key = *k;
        *val = *v;
    }
}

/// Replace the current minimum with `(key, val)` and restore heap order.
///
/// Uses `peek_mut`, whose `Drop` sifts the modified root down once, so this is
/// a single O(log n) operation rather than a pop followed by a push.
#[no_mangle]
pub extern "C" fn wpq_replace_min(pq: *mut WPq, key: u64, val: u32) {
    let pq = unsafe { &mut *pq };
    let mut top = pq.inner.peek_mut().expect("wpq_replace_min on empty queue");
    *top = Reverse((key, val));
}

#[no_mangle]
pub extern "C" fn wpq_pop(pq: *mut WPq) {
    let pq = unsafe { &mut *pq };
    pq.inner.pop();
}

/// Sibling of `WPq` whose value is a pointer rather than a `u32`. The pointer
/// is stored as `usize` so the heap stays free of raw-pointer auto-trait
/// friction; the queue is used by a single thread at a time. The flight
/// recorder uses this with `key = chunk end_ts` and the value pointing at a
/// heap-allocated chunk, so the oldest chunk can be popped and freed.
pub struct WPpq {
    inner: BinaryHeap<Reverse<(u64, usize)>>,
}

#[no_mangle]
pub extern "C" fn wppq_new(cap: usize) -> *mut WPpq {
    Box::into_raw(Box::new(WPpq {
        inner: BinaryHeap::with_capacity(cap),
    }))
}

#[no_mangle]
pub extern "C" fn wppq_free(pq: *mut WPpq) {
    if !pq.is_null() {
        drop(unsafe { Box::from_raw(pq) });
    }
}

#[no_mangle]
pub extern "C" fn wppq_push(pq: *mut WPpq, key: u64, val: *mut c_void) {
    let pq = unsafe { &mut *pq };
    pq.inner.push(Reverse((key, val as usize)));
}

#[no_mangle]
pub extern "C" fn wppq_empty(pq: *const WPpq) -> bool {
    let pq = unsafe { &*pq };
    pq.inner.is_empty()
}

#[no_mangle]
pub extern "C" fn wppq_len(pq: *const WPpq) -> usize {
    let pq = unsafe { &*pq };
    pq.inner.len()
}

#[no_mangle]
pub extern "C" fn wppq_peek_key(pq: *const WPpq) -> u64 {
    let pq = unsafe { &*pq };
    let Reverse((k, _)) = pq.inner.peek().expect("wppq_peek_key on empty queue");
    *k
}

#[no_mangle]
pub extern "C" fn wppq_pop(pq: *mut WPpq) -> *mut c_void {
    let pq = unsafe { &mut *pq };
    match pq.inner.pop() {
        Some(Reverse((_, v))) => v as *mut c_void,
        None => core::ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wppq_min_order() {
        let pq = wppq_new(4);

        // Push (key, fake-pointer) pairs out of order.
        wppq_push(pq, 30, 30usize as *mut c_void);
        wppq_push(pq, 10, 10usize as *mut c_void);
        wppq_push(pq, 20, 20usize as *mut c_void);

        assert_eq!(wppq_len(pq), 3);
        assert!(!wppq_empty(pq));
        assert_eq!(wppq_peek_key(pq), 10);

        // Pop returns values in ascending-key order with matching pointer bits.
        assert_eq!(wppq_pop(pq) as usize, 10);
        assert_eq!(wppq_peek_key(pq), 20);
        assert_eq!(wppq_pop(pq) as usize, 20);
        assert_eq!(wppq_pop(pq) as usize, 30);

        assert!(wppq_empty(pq));
        assert_eq!(wppq_len(pq), 0);
        assert!(wppq_pop(pq).is_null());

        wppq_free(pq);
    }
}
