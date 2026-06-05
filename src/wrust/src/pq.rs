//! Min priority queue over `(key, value)` pairs, backed by the standard
//! library's `BinaryHeap`.
//!
//! `BinaryHeap` is a max-heap, so elements are wrapped in `Reverse` to make it
//! a min-heap. Ordering is ascending and lexicographic on `(key, value)`, so
//! `value` breaks ties on `key` deterministically. The merge phase uses this
//! with `key = timestamp` and `value = stream index`, which reproduces the
//! lowest-index-wins behavior of the old linear scan.

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
