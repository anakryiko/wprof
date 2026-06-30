//! In-place sort of (timestamp, event pointer) pairs by timestamp.
//!
//! Each element carries the event's `u64` timestamp inline next to a pointer to
//! the event, so the sort compares timestamps without ever dereferencing the
//! pointer (no pointer-chasing into the events during comparisons). The merge
//! phase uses this to re-sort each stream's events into timestamp order.
//!
//! Uses the standard library's stable sort (driftsort): it is adaptive on the
//! nearly-sorted merge input, and stable, so equal-timestamp events keep their
//! capture order (which keeps py-scope entry-before-exit nesting intact).

/// `(timestamp, event pointer)` pair; layout matches `struct wrust_ts_ptr` in C.
#[repr(C)]
pub struct TsPtr {
    ts: u64,
    ptr: *const u8,
}

/// Sort `cnt` `(ts, ptr)` pairs in `items` in place, ascending by `ts`.
///
/// # Safety
/// `items` must point to `cnt` initialized `TsPtr` values.
#[no_mangle]
pub unsafe extern "C" fn wrust_sort_events_by_ts(items: *mut TsPtr, cnt: usize) {
    if items.is_null() || cnt < 2 {
        return;
    }

    let s = std::slice::from_raw_parts_mut(items, cnt);
    // wraparound-safe, matching C ts_cmp(): sign of the signed delta
    s.sort_by(|a, b| (a.ts.wrapping_sub(b.ts) as i64).cmp(&0));
}
