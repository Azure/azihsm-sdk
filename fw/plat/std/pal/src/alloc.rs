// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmAlloc`] implementation for the standard PAL.
//!
//! Per-IO bump allocator over the [`BufferPool`]'s pre-allocated
//! NonDma (`NONDMA_BUF_SIZE`) and Dma (`DMA_BUF_SIZE`) buffers.  One
//! watermark per (slot, heap) pair lives in the pool itself; the
//! allocator only advances them.
//!
//! ## Aliasing
//!
//! [`BufferPool`] exposes raw pointers + capacity (no whole-slab
//! `&mut` views).  Each bump allocation constructs a `&mut [u8]`
//! covering only the freshly allocated, disjoint range, so successive
//! allocations from the same `&self` never alias.
//!
//! ## Lifetime gotcha
//!
//! Allocations made *directly* on the PAL inside an
//! [`HsmAlloc::alloc_scoped`] / [`HsmAlloc::alloc_scoped_async`]
//! closure will be silently freed when the scope's watermark is
//! restored on drop.  Direct PAL allocations should be made before the
//! scope opens or after it closes.
//!
//! No atomics — single-threaded Embassy executor with cooperative
//! scheduling.

use core::cell::Cell;
use core::mem;
use core::ops::AsyncFnOnce;

use azihsm_fw_hsm_pal_traits::*;

use crate::buf_pool::BufferPool;
use crate::buf_pool::DMA_BUF_SIZE;
use crate::buf_pool::NONDMA_BUF_SIZE;
use crate::StdHsmPal;

// ── Heap identifiers (PAL-internal) ───────────────────────────────

#[derive(Copy, Clone)]
enum Heap {
    NonDma,
    Dma,
}

impl Heap {
    #[inline(always)]
    fn capacity(self) -> usize {
        match self {
            Heap::NonDma => NONDMA_BUF_SIZE,
            Heap::Dma => DMA_BUF_SIZE,
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────

#[inline(always)]
fn ptr_for(pool: &BufferPool, slot: u16, heap: Heap) -> *mut u8 {
    match heap {
        Heap::NonDma => pool.nondma_ptr(slot),
        Heap::Dma => pool.dma_ptr(slot),
    }
}

#[inline(always)]
fn mark_for(pool: &BufferPool, slot: u16, heap: Heap) -> &Cell<usize> {
    match heap {
        Heap::NonDma => pool.nondma_mark(slot),
        Heap::Dma => pool.dma_mark(slot),
    }
}

/// Bump-allocate `size` bytes with the given alignment from `(slot,
/// heap)`. Returns the new `&mut [u8]` view over the freshly
/// allocated region (disjoint from any prior allocation).
#[allow(clippy::needless_lifetimes, clippy::mut_from_ref)]
fn bump<'a>(
    pool: &'a BufferPool,
    slot: u16,
    heap: Heap,
    size: usize,
    align: usize,
) -> HsmResult<&'a mut [u8]> {
    let cap = heap.capacity();
    let mark_cell = mark_for(pool, slot, heap);
    let mark = mark_cell.get().min(cap);

    let base = ptr_for(pool, slot, heap) as usize;
    let aligned = (base + mark + align - 1) & !(align - 1);
    let start = aligned - base;
    let end = start.checked_add(size).ok_or(HsmError::NotEnoughSpace)?;

    if end > cap {
        return Err(HsmError::NotEnoughSpace);
    }

    mark_cell.set(end);

    // SAFETY: the BufferPool gives the caller exclusive access to its slot's
    // raw pointer for the lifetime of the allocated IO. The bump watermark
    // ensures every returned slice covers a disjoint range, and the pool only
    // reuses the slot after the IO completes (which freezes any prior
    // borrows). The returned `&mut [u8]` therefore aliases nothing.
    let ptr = unsafe { ptr_for(pool, slot, heap).add(start) };
    Ok(unsafe { core::slice::from_raw_parts_mut(ptr, size) })
}

// ── Scoped allocator handle ───────────────────────────────────────

/// Scoped allocator handle for the standard PAL.
///
/// Snapshots both per-slot watermarks on construction and restores
/// them on drop, freeing every allocation made through the handle in
/// LIFO order.
pub struct StdScopedAlloc<'a> {
    pool: &'a BufferPool,
    slot: u16,
    nondma_mark: usize,
    dma_mark: usize,
}

impl HsmScopedAlloc for StdScopedAlloc<'_> {
    #[inline(always)]
    fn alloc(&self, size: usize) -> HsmResult<&mut [u8]> {
        bump(self.pool, self.slot, Heap::NonDma, size, 4)
    }

    #[inline(always)]
    fn alloc_zeroed(&self, size: usize) -> HsmResult<&mut [u8]> {
        let s = self.alloc(size)?;
        s.fill(0);
        Ok(s)
    }

    #[inline(always)]
    fn alloc_val<T: Sized>(&self, value: T) -> HsmResult<&mut T> {
        let s = bump(
            self.pool,
            self.slot,
            Heap::NonDma,
            mem::size_of::<T>(),
            mem::align_of::<T>().max(1),
        )?;
        let ptr = s.as_mut_ptr().cast::<T>();
        // SAFETY: bump() reserved exactly size_of::<T>() bytes with
        // align_of::<T>() alignment. The pointer is non-null and writable.
        unsafe {
            ptr.write(value);
            Ok(&mut *ptr)
        }
    }

    #[inline(always)]
    fn dma_alloc(&self, size: usize) -> HsmResult<&mut DmaBuf> {
        let s = bump(self.pool, self.slot, Heap::Dma, size, 4)?;
        // SAFETY: the Dma heap is DMA-accessible by construction.
        Ok(unsafe { DmaBuf::from_raw_mut(s) })
    }

    #[inline(always)]
    fn dma_alloc_zeroed(&self, size: usize) -> HsmResult<&mut DmaBuf> {
        let s = self.dma_alloc(size)?;
        s.fill(0);
        Ok(s)
    }
}

impl Drop for StdScopedAlloc<'_> {
    fn drop(&mut self) {
        self.pool.nondma_mark(self.slot).set(self.nondma_mark);
        self.pool.dma_mark(self.slot).set(self.dma_mark);
    }
}

// ── HsmAlloc impl ─────────────────────────────────────────────────

impl HsmAlloc for StdHsmPal {
    type Scoped<'a> = StdScopedAlloc<'a>;

    #[inline(always)]
    fn alloc(&self, io: &impl HsmIo, size: usize) -> HsmResult<&mut [u8]> {
        bump(self.iic.pool(), io.index(), Heap::NonDma, size, 4)
    }

    #[inline(always)]
    fn alloc_zeroed(&self, io: &impl HsmIo, size: usize) -> HsmResult<&mut [u8]> {
        let s = self.alloc(io, size)?;
        s.fill(0);
        Ok(s)
    }

    #[inline(always)]
    fn alloc_val<T: Sized>(&self, io: &impl HsmIo, value: T) -> HsmResult<&mut T> {
        let s = bump(
            self.iic.pool(),
            io.index(),
            Heap::NonDma,
            mem::size_of::<T>(),
            mem::align_of::<T>().max(1),
        )?;
        let ptr = s.as_mut_ptr().cast::<T>();
        // SAFETY: see StdScopedAlloc::alloc_val.
        unsafe {
            ptr.write(value);
            Ok(&mut *ptr)
        }
    }

    #[inline(always)]
    fn dma_alloc(&self, io: &impl HsmIo, size: usize) -> HsmResult<&mut DmaBuf> {
        let s = bump(self.iic.pool(), io.index(), Heap::Dma, size, 4)?;
        // SAFETY: the Dma heap is DMA-accessible by construction.
        Ok(unsafe { DmaBuf::from_raw_mut(s) })
    }

    #[inline(always)]
    fn dma_alloc_zeroed(&self, io: &impl HsmIo, size: usize) -> HsmResult<&mut DmaBuf> {
        let s = self.dma_alloc(io, size)?;
        s.fill(0);
        Ok(s)
    }

    fn dma_alloc_var<F>(&self, io: &impl HsmIo, f: F) -> HsmResult<&mut DmaBuf>
    where
        F: FnOnce(&mut [u8]) -> HsmResult<usize>,
    {
        let pool = self.iic.pool();
        let slot = io.index();
        let cap = Heap::Dma.capacity();
        let mark_cell = pool.dma_mark(slot);
        let saved_mark = mark_cell.get().min(cap);
        let aligned = (saved_mark + 3) & !3;
        if aligned >= cap {
            return Err(HsmError::NotEnoughSpace);
        }
        let buf = bump(pool, slot, Heap::Dma, cap - aligned, 4)?;
        match f(buf) {
            Ok(len) => {
                if len > buf.len() {
                    // Closure overran the buffer it was handed; refuse to
                    // expose a longer slice than we actually own.
                    mark_cell.set(saved_mark);
                    return Err(HsmError::InvalidArg);
                }
                let final_end = aligned + len;
                mark_cell.set(final_end);
                // SAFETY: the Dma heap is DMA-accessible by construction.
                Ok(unsafe { DmaBuf::from_raw_mut(&mut buf[..len]) })
            }
            Err(e) => {
                mark_cell.set(saved_mark);
                Err(e)
            }
        }
    }

    fn dma_alloc_var_with<F, T>(&self, io: &impl HsmIo, f: F) -> HsmResult<(&mut DmaBuf, T)>
    where
        F: FnOnce(&mut [u8]) -> HsmResult<(usize, T)>,
    {
        let pool = self.iic.pool();
        let slot = io.index();
        let cap = Heap::Dma.capacity();
        let mark_cell = pool.dma_mark(slot);
        let saved_mark = mark_cell.get().min(cap);
        let aligned = (saved_mark + 3) & !3;
        if aligned >= cap {
            return Err(HsmError::NotEnoughSpace);
        }
        let buf = bump(pool, slot, Heap::Dma, cap - aligned, 4)?;
        match f(buf) {
            Ok((len, extra)) => {
                if len > buf.len() {
                    mark_cell.set(saved_mark);
                    return Err(HsmError::InvalidArg);
                }
                let final_end = aligned + len;
                mark_cell.set(final_end);
                // SAFETY: the Dma heap is DMA-accessible by construction.
                Ok((unsafe { DmaBuf::from_raw_mut(&mut buf[..len]) }, extra))
            }
            Err(e) => {
                mark_cell.set(saved_mark);
                Err(e)
            }
        }
    }

    #[inline]
    fn alloc_scoped<R>(&self, io: &impl HsmIo, f: impl FnOnce(&Self::Scoped<'_>) -> R) -> R {
        let pool = self.iic.pool();
        let slot = io.index();
        let scope = StdScopedAlloc {
            pool,
            slot,
            nondma_mark: pool.nondma_mark(slot).get(),
            dma_mark: pool.dma_mark(slot).get(),
        };
        f(&scope)
    }

    async fn alloc_scoped_async<R, F>(&self, io: &impl HsmIo, f: F) -> R
    where
        F: for<'a> AsyncFnOnce(&'a Self::Scoped<'a>) -> R,
    {
        let pool = self.iic.pool();
        let slot = io.index();
        let scope = StdScopedAlloc {
            pool,
            slot,
            nondma_mark: pool.nondma_mark(slot).get(),
            dma_mark: pool.dma_mark(slot).get(),
        };
        f(&scope).await
    }
}
