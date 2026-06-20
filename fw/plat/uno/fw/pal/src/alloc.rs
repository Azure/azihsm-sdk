// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HsmAlloc implementation for the Uno PAL.
//!
//! Bump allocator over per-IO DTCM (NonDma) and SRAM (Dma) regions.
//! One watermark per (IO slot, heap) pair lives in the PAL struct.
//!
//! No atomics — single-core Cortex-M7 with cooperative scheduling.

use core::mem;
use core::ops::AsyncFnOnce;

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_single_cell::SingleCell;
use azihsm_fw_uno_reg_soc::io_gsram::IO_GSRAM_BASE;
use azihsm_fw_uno_reg_soc::io_gsram::SRAM_IO_BUF_COUNT;
use azihsm_fw_uno_reg_soc::io_gsram::SRAM_IO_BUF_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::SRAM_IO_BUF_STRIDE;

use crate::UnoHsmPal;

// ── Heap identifiers (PAL-internal) ───────────────────────────────

const NONDMA: usize = 0;
const DMA: usize = 1;
const HEAPS: usize = 2;

pub(crate) const IO_SLOTS: usize = SRAM_IO_BUF_COUNT as usize;

// DTCM IO buffer region — per-IO NonDma scratch in upper DTCM.
// See dtcm_map.rdl: DTCM_IO_BUF[32] @ offset 0x2F400 from DTCM base.
const DTCM_IO_BUF_BASE: u32 = azihsm_fw_uno_reg_soc::hsm_dtcm::HSM_DTCM_BASE
    + azihsm_fw_uno_reg_soc::hsm_dtcm::DTCM_IO_BUF_OFFSET;
const DTCM_IO_BUF_STRIDE: u32 = azihsm_fw_uno_reg_soc::hsm_dtcm::DTCM_IO_BUF_STRIDE;
const DTCM_IO_BUF_SIZE: u32 = azihsm_fw_uno_reg_soc::hsm_dtcm::DTCM_IO_BUF_SIZE;

/// Per-IO × per-heap bump watermarks, stored in the PAL.
pub(crate) type IoAllocTable = [[SingleCell<usize>; HEAPS]; IO_SLOTS];

#[allow(clippy::declare_interior_mutable_const)]
pub(crate) const IO_ALLOC_INIT: IoAllocTable =
    [const { [const { SingleCell::new(0) }; HEAPS] }; IO_SLOTS];

/// Scoped allocator implementation for [`UnoHsmPal`].
#[derive(Debug)]
pub struct UnoScopedAlloc<'a> {
    pal: &'a UnoHsmPal,
    io_index: u16,
    marks: [usize; 2],
}

/// Reset both heaps for the given IO slot.
pub(crate) fn reset_io_alloc(pal: &UnoHsmPal, index: u16) {
    for cell in &pal.io_alloc[index as usize] {
        cell.with(|v| *v = 0);
    }
}

// ── Helpers ───────────────────────────────────────────────────────

/// Returns the base pointer and capacity for a given heap region.
/// Uses raw pointers to avoid creating aliasing `&mut` references.
#[inline(always)]
fn heap_base_cap(io_index: u16, heap: usize) -> (*mut u8, usize) {
    let index = io_index as usize;
    if heap == NONDMA {
        let addr = DTCM_IO_BUF_BASE as usize + index * DTCM_IO_BUF_STRIDE as usize;
        (addr as *mut u8, DTCM_IO_BUF_SIZE as usize)
    } else {
        let addr = IO_GSRAM_BASE as usize
            + SRAM_IO_BUF_OFFSET as usize
            + index * SRAM_IO_BUF_STRIDE as usize;
        (addr as *mut u8, SRAM_IO_BUF_STRIDE as usize)
    }
}

#[inline(always)]
fn wm(pal: &UnoHsmPal, io_index: u16, heap: usize) -> &SingleCell<usize> {
    &pal.io_alloc[io_index as usize][heap]
}

/// Bump-allocate `size` bytes with given alignment, return (start_offset, slice).
#[inline(always)]
fn bump(
    pal: &UnoHsmPal,
    io_index: u16,
    heap: usize,
    size: usize,
    align: usize,
) -> HsmResult<(usize, &'static mut [u8])> {
    let (base_ptr, cap) = heap_base_cap(io_index, heap);
    let w = wm(pal, io_index, heap);
    let mark = w.with(|v| *v).min(cap);

    let base = base_ptr as usize;
    let aligned = (base + mark + align - 1) & !(align - 1);
    let start = aligned - base;
    let end = start.checked_add(size).ok_or(HsmError::NotEnoughSpace)?;

    if end > cap {
        return Err(HsmError::NotEnoughSpace);
    }

    w.with(|v| *v = end);
    // SAFETY: start..end is within bounds and does not overlap any prior
    // live allocation (the watermark only advances within a scope).
    Ok((start, unsafe {
        core::slice::from_raw_parts_mut(base_ptr.add(start), size)
    }))
}

impl HsmScopedAlloc for UnoScopedAlloc<'_> {
    #[inline(always)]
    fn alloc(&self, size: usize) -> HsmResult<&mut [u8]> {
        bump(self.pal, self.io_index, NONDMA, size, 4).map(|(_, s)| s)
    }

    #[inline(always)]
    fn alloc_zeroed(&self, size: usize) -> HsmResult<&mut [u8]> {
        let s = self.alloc(size)?;
        s.fill(0);
        Ok(s)
    }

    #[inline(always)]
    fn alloc_val<T: Sized>(&self, value: T) -> HsmResult<&mut T> {
        let (_, s) = bump(
            self.pal,
            self.io_index,
            NONDMA,
            mem::size_of::<T>(),
            mem::align_of::<T>(),
        )?;
        let ptr = s.as_mut_ptr() as *mut T;
        // SAFETY: `s` reserves enough space for `T` with the required alignment.
        unsafe {
            ptr.write(value);
            Ok(&mut *ptr)
        }
    }

    #[inline(always)]
    fn dma_alloc(&self, size: usize) -> HsmResult<&mut DmaBuf> {
        let s = bump(self.pal, self.io_index, DMA, size, 4).map(|(_, s)| s)?;
        // SAFETY: SRAM region returned by `bump` is DMA-accessible.
        Ok(unsafe { DmaBuf::from_raw_mut(s) })
    }

    #[inline(always)]
    fn dma_alloc_zeroed(&self, size: usize) -> HsmResult<&mut DmaBuf> {
        let s = self.dma_alloc(size)?;
        s.fill(0);
        Ok(s)
    }
}

impl Drop for UnoScopedAlloc<'_> {
    fn drop(&mut self) {
        wm(self.pal, self.io_index, DMA).with(|v| *v = self.marks[1]);
        wm(self.pal, self.io_index, NONDMA).with(|v| *v = self.marks[0]);
    }
}

// ── HsmAlloc impl ─────────────────────────────────────────────────

impl HsmAlloc for UnoHsmPal {
    type Scoped<'a> = UnoScopedAlloc<'a>;

    #[inline(always)]
    fn alloc(&self, io: &impl HsmIo, size: usize) -> HsmResult<&mut [u8]> {
        bump(self, io.index(), NONDMA, size, 4).map(|(_, s)| s)
    }

    #[inline(always)]
    fn alloc_zeroed(&self, io: &impl HsmIo, size: usize) -> HsmResult<&mut [u8]> {
        let s = self.alloc(io, size)?;
        s.fill(0);
        Ok(s)
    }

    #[inline(always)]
    fn alloc_val<T: Sized>(&self, io: &impl HsmIo, value: T) -> HsmResult<&mut T> {
        let (_, s) = bump(
            self,
            io.index(),
            NONDMA,
            mem::size_of::<T>(),
            mem::align_of::<T>(),
        )?;
        let ptr = s.as_mut_ptr() as *mut T;
        // SAFETY: `s` reserves enough space for `T` with the required alignment.
        unsafe {
            ptr.write(value);
            Ok(&mut *ptr)
        }
    }

    #[inline(always)]
    fn dma_alloc(&self, io: &impl HsmIo, size: usize) -> HsmResult<&mut DmaBuf> {
        let s = bump(self, io.index(), DMA, size, 4).map(|(_, s)| s)?;
        // SAFETY: SRAM region returned by `bump` is DMA-accessible.
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
        let io_index = io.index();
        let (_, cap) = heap_base_cap(io_index, DMA);
        let w = wm(self, io_index, DMA);
        let mark = w.with(|v| *v).min(cap);
        let aligned = (mark + 3) & !3;
        if aligned >= cap {
            return Err(HsmError::NotEnoughSpace);
        }
        let (start, buf) = bump(self, io_index, DMA, cap - aligned, 4)?;
        match f(buf) {
            Ok(len) => {
                w.with(|v| *v = start + len.min(buf.len()));
                // SAFETY: `buf` came from the SRAM Dma pool.
                Ok(unsafe { DmaBuf::from_raw_mut(&mut buf[..len]) })
            }
            Err(e) => {
                w.with(|v| *v = start);
                Err(e)
            }
        }
    }

    fn dma_alloc_var_with<F, T>(&self, io: &impl HsmIo, f: F) -> HsmResult<(&mut DmaBuf, T)>
    where
        F: FnOnce(&mut [u8]) -> HsmResult<(usize, T)>,
    {
        let io_index = io.index();
        let (_, cap) = heap_base_cap(io_index, DMA);
        let w = wm(self, io_index, DMA);
        let mark = w.with(|v| *v).min(cap);
        let aligned = (mark + 3) & !3;
        if aligned >= cap {
            return Err(HsmError::NotEnoughSpace);
        }
        let (start, buf) = bump(self, io_index, DMA, cap - aligned, 4)?;
        match f(buf) {
            Ok((len, extra)) => {
                w.with(|v| *v = start + len.min(buf.len()));
                // SAFETY: `buf` came from the SRAM Dma pool.
                Ok((unsafe { DmaBuf::from_raw_mut(&mut buf[..len]) }, extra))
            }
            Err(e) => {
                w.with(|v| *v = start);
                Err(e)
            }
        }
    }

    #[inline]
    fn alloc_scoped<R>(&self, io: &impl HsmIo, f: impl FnOnce(&Self::Scoped<'_>) -> R) -> R {
        let scope = UnoScopedAlloc {
            pal: self,
            io_index: io.index(),
            marks: [
                wm(self, io.index(), NONDMA).with(|v| *v),
                wm(self, io.index(), DMA).with(|v| *v),
            ],
        };
        f(&scope)
    }

    async fn alloc_scoped_async<R, F>(&self, io: &impl HsmIo, f: F) -> R
    where
        F: for<'a> AsyncFnOnce(&'a Self::Scoped<'a>) -> R,
    {
        let scope = UnoScopedAlloc {
            pal: self,
            io_index: io.index(),
            marks: [
                wm(self, io.index(), NONDMA).with(|v| *v),
                wm(self, io.index(), DMA).with(|v| *v),
            ],
        };
        f(&scope).await
    }
}

// ── Public test/utility hooks ─────────────────────────────────────

impl UnoHsmPal {
    /// Snapshot the current DMA-heap watermark for the given IO slot.
    ///
    /// Intended for short-lived RAII scopes (e.g. the test harness
    /// `dma!` macro) that allocate a batch of DMA buffers, use them
    /// for a single statement, and reset the heap so the next
    /// statement starts from the same baseline.
    #[inline]
    pub fn dma_mark(&self, io_index: u16) -> usize {
        wm(self, io_index, DMA).with(|v| *v)
    }

    /// Restore a previously-captured DMA-heap watermark.
    ///
    /// All buffers allocated after the watermark was captured are
    /// logically freed by this call; callers must ensure no live
    /// references to them remain.
    #[inline]
    pub fn dma_restore(&self, io_index: u16, mark: usize) {
        wm(self, io_index, DMA).with(|v| *v = mark);
    }
}
