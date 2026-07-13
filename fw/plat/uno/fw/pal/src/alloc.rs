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

/// Dedicated admin/internal IO slot.
///
/// IIC only hands out the host slots `0..ADMIN_IO_INDEX` (the first
/// 32 slots); the PAL reserves this slot for internal provisioning
/// crypto (partition identity and enable-time keygen), so its bump
/// heaps never collide with a concurrent host IO. It has full DMA
/// (`SRAM_IO_BUF`) and NonDma (`DTCM_IO_BUF`) backing, like any host
/// slot.
pub(crate) const ADMIN_IO_INDEX: u16 = (IO_SLOTS - 2) as u16;

/// Dedicated self-test (CAST) IO slot — the last of [`IO_SLOTS`].
///
/// Reserved for the pre-operational and periodic cryptographic
/// algorithm self-tests, separate from [`ADMIN_IO_INDEX`] so the
/// periodic self-test never races partition provisioning over a
/// shared bump heap.
///
/// Unlike host and admin slots, this slot is **DMA-only**: it has
/// `SRAM_IO_BUF` (Dma) backing but no `DTCM_IO_BUF` (NonDma) entry —
/// `DTCM_IO_BUF` covers only the 33 host+admin slots (see
/// `dtcm_map.rdl`). NonDma allocations against this slot are rejected
/// by the bump allocator so an accidental one cannot address past the
/// `DTCM_IO_BUF` region into the crashdump/status area.
pub(crate) const SELF_TEST_IO_INDEX: u16 = (IO_SLOTS - 1) as u16;

// DTCM IO buffer region — per-IO NonDma scratch in upper DTCM.
// See dtcm_map.rdl: DTCM_IO_BUF[33] @ offset 0x2EC00 from DTCM base.
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
pub struct UnoScopedAlloc<'a> {
    pal: &'a UnoHsmPal,
    io_index: u16,
    marks: [usize; 2],
}

impl<'a> UnoScopedAlloc<'a> {
    /// Scoped allocator over the dedicated admin IO slot
    /// ([`ADMIN_IO_INDEX`]).
    ///
    /// Rewinds the slot's watermarks so each internal provisioning sequence
    /// starts from a clean DMA heap. Drops restore the (zero) baseline.
    pub(crate) fn for_admin(pal: &'a UnoHsmPal) -> Self {
        reset_io_alloc(pal, ADMIN_IO_INDEX);
        Self {
            pal,
            io_index: ADMIN_IO_INDEX,
            marks: [0, 0],
        }
    }
}

/// Reset both heaps for the given IO slot.
///
/// # Parameters
/// - `pal`: PAL instance whose per-IO allocator table will be mutated.
/// - `index`: IO slot index to reset. Must refer to a valid slot in `pal.io_alloc`.
///
/// # Returns
/// Returns `()`.
///
/// # Side Effects
/// Sets both NonDma and Dma watermarks for `index` to `0`.
pub(crate) fn reset_io_alloc(pal: &UnoHsmPal, index: u16) {
    for cell in &pal.io_alloc[index as usize] {
        cell.with(|v| *v = 0);
    }
}

// ── Public test/utility hooks ─────────────────────────────────────

impl UnoHsmPal {
    /// Snapshot the current DMA-heap watermark for the given IO slot.
    ///
    /// Intended for short-lived RAII scopes (for example, the test harness
    /// `dma!` macro) that allocate a batch of DMA buffers, use them for one
    /// statement, and then restore the heap baseline.
    ///
    /// # Parameters
    /// - `io_index`: IO slot to inspect in the per-IO DMA heap table.
    ///
    /// # Returns
    /// Current DMA watermark offset (bytes from the slot-local DMA heap base).
    pub fn dma_mark(&self, io_index: u16) -> usize {
        wm(self, io_index, DMA).with(|v| *v)
    }

    /// Restore a previously captured DMA-heap watermark.
    ///
    /// # Parameters
    /// - `io_index`: IO slot whose DMA watermark should be rewound.
    /// - `mark`: Previously captured watermark (typically from [`Self::dma_mark`]).
    ///
    /// # Returns
    /// Returns `()`.
    ///
    /// # Side Effects
    /// Logically frees all DMA allocations made after `mark` for `io_index`.
    /// Callers must ensure no live references to those buffers remain.
    pub fn dma_restore(&self, io_index: u16, mark: usize) {
        wm(self, io_index, DMA).with(|v| *v = mark);
    }
}

// ── Helpers ───────────────────────────────────────────────────────

/// Returns the base pointer and capacity for a given heap region.
/// Uses raw pointers to avoid creating aliasing `&mut` references.
///
/// # Parameters
/// - `io_index`: IO slot index selecting the per-IO buffer region.
/// - `heap`: Heap selector (`NONDMA` or `DMA`).
///
/// # Returns
/// Tuple `(base_ptr, cap)` where:
/// - `base_ptr`: start address of the slot-local heap.
/// - `cap`: total capacity in bytes for that heap.
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

/// Access the watermark cell for one `(io_index, heap)` pair.
///
/// # Parameters
/// - `pal`: PAL instance owning the allocator table.
/// - `io_index`: IO slot index.
/// - `heap`: Heap selector (`NONDMA` or `DMA`).
///
/// # Returns
/// Shared reference to the corresponding [`SingleCell`] watermark.
#[inline(always)]
fn wm(pal: &UnoHsmPal, io_index: u16, heap: usize) -> &SingleCell<usize> {
    &pal.io_alloc[io_index as usize][heap]
}

/// Bump-allocate `size` bytes with given alignment, return (start_offset, slice).
///
/// # Parameters
/// - `pal`: PAL instance owning heap watermarks.
/// - `io_index`: IO slot to allocate within.
/// - `heap`: Heap selector (`NONDMA` or `DMA`).
/// - `size`: Requested allocation length in bytes.
/// - `align`: Required power-of-two alignment.
///
/// # Returns
/// On success, returns `(start_offset, slice)`:
/// - `start_offset`: byte offset from heap base where allocation begins.
/// - `slice`: mutable view over the newly allocated region.
///
/// Returns [`HsmError::NotEnoughSpace`] if aligned allocation would exceed heap capacity.
#[inline(always)]
fn bump(
    pal: &UnoHsmPal,
    io_index: u16,
    heap: usize,
    size: usize,
    align: usize,
) -> HsmResult<(usize, &'static mut [u8])> {
    // The self-test slot is DMA-only: it has SRAM_IO_BUF (Dma) backing but no
    // DTCM_IO_BUF (NonDma) entry. Reject NonDma allocations rather than
    // computing a DTCM address past the buffer region, which would overlap the
    // crashdump/status area.
    if heap == NONDMA && io_index == SELF_TEST_IO_INDEX {
        return Err(HsmError::InvalidArg);
    }

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
    /// Allocate `size` bytes from the scoped NonDma heap.
    ///
    /// # Parameters
    /// - `size`: Number of bytes to allocate.
    ///
    /// # Returns
    /// Mutable slice to allocated bytes, or [`HsmError::NotEnoughSpace`].
    fn alloc(&self, size: usize) -> HsmResult<&mut [u8]> {
        bump(self.pal, self.io_index, NONDMA, size, 4).map(|(_, s)| s)
    }

    #[inline(always)]
    /// Allocate and zero-initialize `size` bytes from the scoped NonDma heap.
    ///
    /// # Parameters
    /// - `size`: Number of bytes to allocate.
    ///
    /// # Returns
    /// Mutable zeroed slice, or [`HsmError::NotEnoughSpace`].
    fn alloc_zeroed(&self, size: usize) -> HsmResult<&mut [u8]> {
        let s = self.alloc(size)?;
        s.fill(0);
        Ok(s)
    }

    #[inline(always)]
    /// Allocate space for one value of type `T` and move `value` into it.
    ///
    /// # Parameters
    /// - `value`: Value to place in scoped NonDma memory.
    ///
    /// # Returns
    /// Mutable reference to stored value, or [`HsmError::NotEnoughSpace`].
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
    /// Allocate `size` bytes from the scoped DMA heap.
    ///
    /// # Parameters
    /// - `size`: Number of DMA-visible bytes to allocate.
    ///
    /// # Returns
    /// Mutable [`DmaBuf`] view, or [`HsmError::NotEnoughSpace`].
    fn dma_alloc(&self, size: usize) -> HsmResult<&mut DmaBuf> {
        let s = bump(self.pal, self.io_index, DMA, size, 4).map(|(_, s)| s)?;
        // SAFETY: SRAM region returned by `bump` is DMA-accessible.
        Ok(unsafe { DmaBuf::from_raw_mut(s) })
    }

    #[inline(always)]
    /// Allocate and zero-initialize `size` bytes from the scoped DMA heap.
    ///
    /// # Parameters
    /// - `size`: Number of DMA-visible bytes to allocate.
    ///
    /// # Returns
    /// Mutable zeroed [`DmaBuf`], or [`HsmError::NotEnoughSpace`].
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
    /// Allocate `size` bytes from the slot-local NonDma heap.
    ///
    /// # Parameters
    /// - `io`: IO token whose slot selects allocator state.
    /// - `size`: Number of bytes to allocate.
    ///
    /// # Returns
    /// Mutable byte slice, or [`HsmError::NotEnoughSpace`].
    fn alloc(&self, io: &impl HsmIo, size: usize) -> HsmResult<&mut [u8]> {
        bump(self, io.index(), NONDMA, size, 4).map(|(_, s)| s)
    }

    #[inline(always)]
    /// Allocate and zero-initialize `size` bytes from NonDma heap.
    ///
    /// # Parameters
    /// - `io`: IO token whose slot selects allocator state.
    /// - `size`: Number of bytes to allocate.
    ///
    /// # Returns
    /// Mutable zeroed byte slice, or [`HsmError::NotEnoughSpace`].
    fn alloc_zeroed(&self, io: &impl HsmIo, size: usize) -> HsmResult<&mut [u8]> {
        let s = self.alloc(io, size)?;
        s.fill(0);
        Ok(s)
    }

    #[inline(always)]
    /// Allocate aligned storage for one value of type `T` in NonDma heap.
    ///
    /// # Parameters
    /// - `io`: IO token whose slot selects allocator state.
    /// - `value`: Value to store in allocator-owned memory.
    ///
    /// # Returns
    /// Mutable reference to stored value, or [`HsmError::NotEnoughSpace`].
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
    /// Allocate `size` bytes from slot-local DMA heap.
    ///
    /// # Parameters
    /// - `io`: IO token whose slot selects allocator state.
    /// - `size`: Number of DMA-visible bytes to allocate.
    ///
    /// # Returns
    /// Mutable [`DmaBuf`], or [`HsmError::NotEnoughSpace`].
    fn dma_alloc(&self, io: &impl HsmIo, size: usize) -> HsmResult<&mut DmaBuf> {
        let s = bump(self, io.index(), DMA, size, 4).map(|(_, s)| s)?;
        // SAFETY: SRAM region returned by `bump` is DMA-accessible.
        Ok(unsafe { DmaBuf::from_raw_mut(s) })
    }

    #[inline(always)]
    /// Allocate and zero-initialize `size` bytes from slot-local DMA heap.
    ///
    /// # Parameters
    /// - `io`: IO token whose slot selects allocator state.
    /// - `size`: Number of DMA-visible bytes to allocate.
    ///
    /// # Returns
    /// Mutable zeroed [`DmaBuf`], or [`HsmError::NotEnoughSpace`].
    fn dma_alloc_zeroed(&self, io: &impl HsmIo, size: usize) -> HsmResult<&mut DmaBuf> {
        let s = self.dma_alloc(io, size)?;
        s.fill(0);
        Ok(s)
    }

    /// Reserve remaining aligned DMA space and let `f` choose final used length.
    ///
    /// # Parameters
    /// - `io`: IO token whose slot selects allocator state.
    /// - `f`: Callback receiving a temporary writable slice spanning remaining
    ///   DMA capacity from current aligned watermark. It returns the number of
    ///   bytes logically consumed.
    ///
    /// # Returns
    /// Mutable [`DmaBuf`] of length selected by `f`, or error from `f`/allocator.
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

    /// Like [`Self::dma_alloc_var`], but allows callback to return extra metadata.
    ///
    /// # Parameters
    /// - `io`: IO token whose slot selects allocator state.
    /// - `f`: Callback receiving temporary writable remaining DMA span and
    ///   returning `(len, extra)` where `len` is consumed bytes.
    ///
    /// # Returns
    /// Tuple `(&mut DmaBuf, T)` on success, or error from `f`/allocator.
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
    /// Execute `f` within a scoped allocator frame that auto-restores watermarks.
    ///
    /// # Parameters
    /// - `io`: IO token whose slot defines scoped allocator context.
    /// - `f`: Closure executed with a scoped allocator reference.
    ///
    /// # Returns
    /// Returns whatever value `f` returns.
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

    /// Async variant of [`Self::alloc_scoped`] with auto-restored watermarks.
    ///
    /// # Parameters
    /// - `io`: IO token whose slot defines scoped allocator context.
    /// - `f`: Async closure executed with a scoped allocator reference.
    ///
    /// # Returns
    /// Resolves to whatever value `f` returns.
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
