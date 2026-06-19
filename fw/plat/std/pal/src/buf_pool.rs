// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pre-allocated IO buffer pool with async bitmap allocation.
//!
//! The buffer pool owns [`MAX_IO_SLOTS`] pairs of buffers:
//! - **NonDma (fast) buffers** ([`NONDMA_BUF_SIZE`] bytes each) — small per-IO
//!   scratch space (analogue of DTCM on hardware).
//! - **Dma (large) buffers** ([`DMA_BUF_SIZE`] bytes each) — larger per-IO
//!   data buffers (analogue of SRAM on hardware).
//!
//! Slot allocation is O(1) via `trailing_zeros` on a `u64` free bitmap.
//! When all slots are in use, [`alloc`](BufferPool::alloc) suspends and
//! is woken by [`free`](BufferPool::free) via `WakerRegistration`.
//!
//! ## Bump-allocator backing
//!
//! Each slot also owns two `Cell<usize>` watermarks (one per heap)
//! that serve the [`HsmAlloc`](azihsm_fw_hsm_pal_traits::HsmAlloc)
//! trait implementation in [`crate::alloc`].  `alloc()` resets both
//! watermarks to zero when handing out a fresh slot, and the
//! allocator advances them as it bumps out new sub-slices.
//!
//! ## Aliasing model
//!
//! Buffer storage is exposed as *raw pointers + capacity*
//! ([`nondma_ptr`](Self::nondma_ptr) / [`dma_ptr`](Self::dma_ptr)).
//! The bump allocator is the only consumer; it constructs
//! `&mut [u8]` views over the freshly bumped (disjoint) range, so no
//! two outstanding borrows ever overlap.  Callers must NOT obtain a
//! `&mut [u8]` over the whole slab while bump allocations are live.
//!
//! ## Thread safety
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

/// Size of each NonDma (fast / DTCM-equivalent) buffer in bytes.
pub const NONDMA_BUF_SIZE: usize = 2048;

/// Size of each Dma (large / SRAM-equivalent) buffer in bytes.
pub const DMA_BUF_SIZE: usize = 8192;

/// Pre-allocated buffer pool with async bitmap allocation.
///
/// All buffers are heap-allocated once at construction. Individual slots
/// are handed out via [`alloc`](Self::alloc) and returned via
/// [`free`](Self::free).
pub struct BufferPool {
    /// NonDma (fast / DTCM) buffers, one per slot.
    nondma_bufs: Box<[UnsafeCell<[u8; NONDMA_BUF_SIZE]>; MAX_IO_SLOTS]>,

    /// Dma (large / SRAM) buffers, one per slot.
    dma_bufs: Box<[UnsafeCell<[u8; DMA_BUF_SIZE]>; MAX_IO_SLOTS]>,

    /// Per-slot bump-allocator watermark for the NonDma heap.
    ///
    /// Reset to zero by [`alloc`](Self::alloc) before the slot is
    /// returned, advanced by the bump allocator, and snapshotted /
    /// restored by `StdScopedAlloc`.
    nondma_marks: Box<[Cell<usize>; MAX_IO_SLOTS]>,

    /// Per-slot bump-allocator watermark for the Dma heap.
    dma_marks: Box<[Cell<usize>; MAX_IO_SLOTS]>,

    /// Bitmap of free slots. Bit set = slot available.
    free_mask: Cell<u64>,

    /// Waker registered by a pending `alloc()` call.
    waker: RefCell<WakerRegistration>,
}

impl BufferPool {
    /// Create a new buffer pool with all slots free.
    ///
    /// Allocates `MAX_IO_SLOTS × (NONDMA_BUF_SIZE + DMA_BUF_SIZE)` on
    /// the heap.  All bump watermarks start at zero.
    pub fn new() -> Self {
        let nondma_bufs = Box::new(core::array::from_fn::<_, MAX_IO_SLOTS, _>(|_| {
            UnsafeCell::new([0u8; NONDMA_BUF_SIZE])
        }));
        let dma_bufs = Box::new(core::array::from_fn::<_, MAX_IO_SLOTS, _>(|_| {
            UnsafeCell::new([0u8; DMA_BUF_SIZE])
        }));
        let nondma_marks = Box::new(core::array::from_fn::<_, MAX_IO_SLOTS, _>(|_| Cell::new(0)));
        let dma_marks = Box::new(core::array::from_fn::<_, MAX_IO_SLOTS, _>(|_| Cell::new(0)));
        let free_mask = if MAX_IO_SLOTS >= 64 {
            u64::MAX
        } else {
            (1u64 << MAX_IO_SLOTS) - 1
        };
        Self {
            nondma_bufs,
            dma_bufs,
            nondma_marks,
            dma_marks,
            free_mask: Cell::new(free_mask),
            waker: RefCell::new(WakerRegistration::new()),
        }
    }

    /// Allocate a buffer slot. O(1) via `trailing_zeros`.
    ///
    /// Resets both bump watermarks for the slot to zero before
    /// returning, so the bump allocator starts from a clean slate on
    /// every IO.
    ///
    /// If all slots are in use, suspends the caller until
    /// [`free`](Self::free) returns a slot and wakes this future.
    pub async fn alloc(&self) -> u16 {
        let idx = poll_fn(|cx| {
            let mask = self.free_mask.get();
            if mask == 0 {
                self.waker.borrow_mut().register(cx.waker());
                return Poll::Pending;
            }
            let i = mask.trailing_zeros() as u16;
            self.free_mask.set(mask & !(1u64 << i));
            Poll::Ready(i)
        })
        .await;
        self.reset_marks(idx);
        idx
    }

    /// Free a buffer slot back to the pool.
    ///
    /// Zeroes the regions of the slot's NonDma and Dma buffers that
    /// this IO actually touched (using the bump watermarks as
    /// high-water marks) before clearing the free bit.  This
    /// preserves the invariant that every fresh `dma_alloc` /
    /// `nondma_alloc` returns zeroed memory, which is required by
    /// zero-on-entry contracts (e.g. `key_masking::cbc::mask`'s
    /// `out[..total_len] must be zero on entry`) and prevents stale
    /// crypto material from outliving an IO.  Watermarks are then
    /// reset on the next
    /// [`alloc`](Self::alloc).
    ///
    /// Sets the slot's bit in the free bitmap and wakes any task
    /// suspended in [`alloc`](Self::alloc).
    ///
    /// # Safety
    ///
    /// Callers must guarantee that no outstanding `&mut [u8]` views
    /// into this slot's buffers exist — i.e. `free` is invoked only
    /// after the owning IO's handler has returned and its [`HsmIo`]
    /// has been consumed.  This is the same exclusivity discipline
    /// the bump allocator relies on; the Embassy executor is
    /// single-threaded, so once the handler returns no aliasing
    /// borrow can outlive it.
    pub fn free(&self, idx: u16) {
        let i = idx as usize;
        let nondma_hi = self.nondma_marks[i].get().min(NONDMA_BUF_SIZE);
        let dma_hi = self.dma_marks[i].get().min(DMA_BUF_SIZE);
        // SAFETY: no outstanding borrows — see method-level Safety.
        unsafe {
            let nondma = &mut *self.nondma_bufs[i].get();
            nondma[..nondma_hi].fill(0);
            let dma = &mut *self.dma_bufs[i].get();
            dma[..dma_hi].fill(0);
        }
        self.free_mask.set(self.free_mask.get() | (1u64 << idx));
        self.waker.borrow_mut().wake();
    }

    /// Reset both bump watermarks for the given slot to zero.
    pub fn reset_marks(&self, idx: u16) {
        self.nondma_marks[idx as usize].set(0);
        self.dma_marks[idx as usize].set(0);
    }

    /// Returns a raw pointer to the start of the NonDma buffer for
    /// `idx`.
    ///
    /// # Safety
    ///
    /// Caller must ensure exclusive access — only one IO holds a
    /// given slot at a time (enforced by the alloc/free protocol),
    /// and only the bump allocator may construct `&mut [u8]` views
    /// over disjoint sub-ranges of this region.
    pub fn nondma_ptr(&self, idx: u16) -> *mut u8 {
        self.nondma_bufs[idx as usize].get() as *mut u8
    }

    /// Returns a raw pointer to the start of the Dma buffer for `idx`.
    ///
    /// # Safety
    ///
    /// Same exclusivity requirement as
    /// [`nondma_ptr`](Self::nondma_ptr).
    pub fn dma_ptr(&self, idx: u16) -> *mut u8 {
        self.dma_bufs[idx as usize].get() as *mut u8
    }

    /// Returns the watermark cell for the NonDma heap of slot `idx`.
    pub fn nondma_mark(&self, idx: u16) -> &Cell<usize> {
        &self.nondma_marks[idx as usize]
    }

    /// Returns the watermark cell for the Dma heap of slot `idx`.
    pub fn dma_mark(&self, idx: u16) -> &Cell<usize> {
        &self.dma_marks[idx as usize]
    }
}

// SAFETY: BufferPool is only accessed from the single-threaded Embassy executor.
unsafe impl Send for BufferPool {}
unsafe impl Sync for BufferPool {}
