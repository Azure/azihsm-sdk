// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pre-allocated IO buffer pool with async bitmap allocation.
//!
//! The buffer pool owns [`MAX_IO_SLOTS`] pairs of buffers:
//! - **Fast buffers** (2KB each) — small per-IO scratch space
//! - **Large buffers** (8KB each) — larger per-IO data buffers
//!
//! Slot allocation is O(1) via `trailing_zeros` on a `u64` free bitmap.
//! When all slots are in use, [`alloc`](BufferPool::alloc) suspends and
//! is woken by [`free`](BufferPool::free) via `WakerRegistration`.
//!
//! # Thread safety
//!
//! The pool is only accessed from the single-threaded Embassy executor.
//! Interior mutability uses `Cell`/`RefCell` — no locks needed.

use core::cell::Cell;
use core::cell::RefCell;
use core::future::poll_fn;
use core::task::Poll;
use std::cell::UnsafeCell;

use embassy_sync::waitqueue::WakerRegistration;

/// Maximum concurrent IO slots.
pub const MAX_IO_SLOTS: usize = 32;

/// Size of each fast buffer in bytes.
const FAST_BUF_SIZE: usize = 2048;

/// Size of each large buffer in bytes.
const LARGE_BUF_SIZE: usize = 8192;

/// Pre-allocated buffer pool with async bitmap allocation.
///
/// All buffers are heap-allocated once at construction. Individual slots
/// are handed out via [`alloc`](Self::alloc) and returned via
/// [`free`](Self::free).
pub struct BufferPool {
    /// 2KB fast buffers, one per slot.
    fast_bufs: Box<[UnsafeCell<[u8; FAST_BUF_SIZE]>; MAX_IO_SLOTS]>,

    /// 8KB large buffers, one per slot.
    large_bufs: Box<[UnsafeCell<[u8; LARGE_BUF_SIZE]>; MAX_IO_SLOTS]>,

    /// Bitmap of free slots. Bit set = slot available.
    free_mask: Cell<u64>,

    /// Waker registered by a pending `alloc()` call.
    waker: RefCell<WakerRegistration>,
}

impl BufferPool {
    /// Create a new buffer pool with all slots free.
    ///
    /// Allocates `MAX_IO_SLOTS × (2KB + 8KB)` = 320KB on the heap.
    pub fn new() -> Self {
        let fast_bufs = Box::new(core::array::from_fn::<_, MAX_IO_SLOTS, _>(|_| {
            UnsafeCell::new([0u8; FAST_BUF_SIZE])
        }));
        let large_bufs = Box::new(core::array::from_fn::<_, MAX_IO_SLOTS, _>(|_| {
            UnsafeCell::new([0u8; LARGE_BUF_SIZE])
        }));
        let free_mask = if MAX_IO_SLOTS >= 64 {
            u64::MAX
        } else {
            (1u64 << MAX_IO_SLOTS) - 1
        };
        Self {
            fast_bufs,
            large_bufs,
            free_mask: Cell::new(free_mask),
            waker: RefCell::new(WakerRegistration::new()),
        }
    }

    /// Allocate a buffer slot. O(1) via `trailing_zeros`.
    ///
    /// If all slots are in use, suspends the caller until
    /// [`free`](Self::free) returns a slot and wakes this future.
    pub async fn alloc(&self) -> u16 {
        poll_fn(|cx| {
            let mask = self.free_mask.get();
            if mask == 0 {
                self.waker.borrow_mut().register(cx.waker());
                return Poll::Pending;
            }
            let idx = mask.trailing_zeros() as u16;
            self.free_mask.set(mask & !(1u64 << idx));
            Poll::Ready(idx)
        })
        .await
    }

    /// Free a buffer slot back to the pool.
    ///
    /// Sets the slot's bit in the free bitmap and wakes any task
    /// suspended in [`alloc`](Self::alloc).
    pub fn free(&self, idx: u16) {
        self.free_mask.set(self.free_mask.get() | (1u64 << idx));
        self.waker.borrow_mut().wake();
    }

    /// Get a mutable reference to the fast buffer (2KB) at `idx`.
    ///
    /// # Safety
    ///
    /// Caller must ensure exclusive access — only one IO holds a
    /// given index at a time (enforced by the alloc/free protocol).
    #[allow(clippy::mut_from_ref)]
    pub fn fast_buf(&self, idx: u16) -> &mut [u8] {
        unsafe { &mut *self.fast_bufs[idx as usize].get() }
    }

    /// Get a mutable reference to the large buffer (8KB) at `idx`.
    ///
    /// # Safety
    ///
    /// Same exclusivity requirement as [`fast_buf`](Self::fast_buf).
    #[allow(clippy::mut_from_ref)]
    pub fn large_buf(&self, idx: u16) -> &mut [u8] {
        unsafe { &mut *self.large_bufs[idx as usize].get() }
    }
}

// SAFETY: BufferPool is only accessed from the single-threaded Embassy executor.
unsafe impl Send for BufferPool {}
unsafe impl Sync for BufferPool {}
