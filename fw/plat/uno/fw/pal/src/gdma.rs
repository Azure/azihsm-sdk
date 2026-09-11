// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Uno GDMA controller implementation.
//!
//! Bridges the platform-agnostic [`HsmGdmaController`] trait to the
//! low-level [`GdmaDriver`](azihsm_fw_uno_drivers_gdma::GdmaDriver)
//! by converting buffer addresses and [`HsmDmaAddr`] values into
//! [`DriverDmaBuf`] and [`MemInterface`] parameters.
//!
//! # Address model
//!
//! The Uno HSM is a Cortex-M core with a 32-bit address space, so
//! device-local pointers always fit in a single [`DmaAddr`] with
//! `hi = 0`. Host-side addresses arrive as [`HsmDmaAddr`] (a full
//! 64-bit address split into `hi`/`lo` halves) and are wrapped in a
//! [`DriverDmaBuf::Prp`] or [`DriverDmaBuf::Sgl`] depending on the caller's
//! `prp` flag.
//!
//! # Transfer direction helpers
//!
//! | Helper               | Source interface | Destination interface |
//! |----------------------|------------------|-----------------------|
//! | `copy_mem`           | Device           | Device                |
//! | `copy_mem_from_host` | Host             | Device                |
//! | `copy_mem_to_host`   | Device           | Host                  |

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmDmaAddr;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmGdmaController;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPartId;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_uno_drivers_gdma::GdmaAddr;
use azihsm_fw_uno_drivers_gdma::GdmaBuf;
use azihsm_fw_uno_drivers_gdma::MemInterface;
use azihsm_fw_uno_reg_soc::zero::ZERO_BASE;
use azihsm_fw_uno_reg_soc::zero::ZERO_SIZE;
use azihsm_fw_uno_trace::tracing::*;
use zeroize::Zeroize;

use crate::UnoHsmPal;

/// Converts an [`HsmDmaAddr`] (the trait-level 64-bit address) into a
/// [`GdmaBuf`] suitable for a host-side DMA operand.
///
/// The `prp` flag selects the descriptor format written to the GDMA
/// submission queue:
///
/// - `true`  → [`GdmaBuf::Prp`] — Physical Region Page descriptor pair.
///   `prp0` holds the address; `prp1` is zeroed (single-page transfer).
/// - `false` → [`GdmaBuf::Sgl`] — Scatter-Gather List descriptor pair.
///   `sgl0` holds the address; `sgl1` is zeroed (inline data block).
#[inline(always)]
fn host_dma_buf(addr: HsmDmaAddr, prp: bool) -> GdmaBuf {
    let addr = GdmaAddr {
        lo: addr.lo,
        hi: addr.hi,
    };
    if prp {
        GdmaBuf::Prp {
            prp0: addr,
            prp1: GdmaAddr::ZERO,
        }
    } else {
        GdmaBuf::Sgl {
            sgl0: addr,
            sgl1: GdmaAddr::ZERO,
        }
    }
}

/// Converts a device-local (DTCM / SRAM) raw pointer and length into
/// an SGL [`GdmaBuf`].
///
/// SGL Data Block descriptor: `sgl0` = address, `sgl1.lo` = length,
/// `sgl1.hi[31:24]` = type/subtype (0x00 = inline data block).
/// No 4K page-crossing restriction unlike PRP.
#[inline(always)]
fn device_dma_buf(ptr: *const u8, len: u32) -> GdmaBuf {
    GdmaBuf::Sgl {
        sgl0: GdmaAddr::from_u32(ptr as usize as u32),
        sgl1: GdmaAddr { lo: len, hi: 0 },
    }
}

/// Converts a raw 16-byte NVMe SGL Data Block descriptor into an SGL
/// [`GdmaBuf`] for a host-side DMA source.
///
/// The descriptor's two little-endian 8-byte dwords map directly onto
/// the GDMA SGL source pair: `desc[0..8]` → `sgl0` (address),
/// `desc[8..16]` → `sgl1` (the block's embedded length + type).
#[inline(always)]
fn sgl_desc_buf(desc: &[u8; 16]) -> GdmaBuf {
    GdmaBuf::Sgl {
        sgl0: GdmaAddr {
            lo: u32::from_le_bytes([desc[0], desc[1], desc[2], desc[3]]),
            hi: u32::from_le_bytes([desc[4], desc[5], desc[6], desc[7]]),
        },
        sgl1: GdmaAddr {
            lo: u32::from_le_bytes([desc[8], desc[9], desc[10], desc[11]]),
            hi: u32::from_le_bytes([desc[12], desc[13], desc[14], desc[15]]),
        },
    }
}

/// Maps a partition ID to a GDMA host interface selector.
///
/// Controller ID = `part_id + 1` because GDMA `IFC_SLCT` uses 0 for
/// device memory, so host interfaces start at 1.
#[inline(always)]
fn host_interface(part_id: HsmPartId) -> HsmResult<MemInterface> {
    let ctrl_id = u8::from(part_id)
        .checked_add(1)
        .ok_or(HsmError::InvalidArg)?;
    Ok(MemInterface::Host { ctrl_id })
}

/// Uno platform implementation of [`HsmGdmaController`].
impl HsmGdmaController for UnoHsmPal {
    async fn copy_mem(&self, _io: &impl HsmIo, src: &DmaBuf, dst: &mut DmaBuf) -> HsmResult<()> {
        let src_addr = device_dma_buf(src.as_ptr(), src.len() as u32);
        let dst_addr = device_dma_buf(dst.as_mut_ptr(), dst.len() as u32);
        self.gdma
            .copy_mem(
                src_addr,
                MemInterface::Device,
                src.len() as u32,
                dst_addr,
                MemInterface::Device,
                dst.len() as u32,
            )?
            .await
    }

    /// Zero an HSM-local buffer.
    ///
    /// Wipes off-CPU with the GDMA engine via
    /// [`gdma_zero_region`](UnoHsmPal::gdma_zero_region), which copies from
    /// the read-as-zero `ZERO` window — GDMA has no fill/memset opcode,
    /// so a wipe is a device-to-device copy out of that region. Every
    /// [`DmaBuf`] is GSRAM-backed by construction (the DTCM heap hands out
    /// plain `&mut [u8]`, never a `DmaBuf`), so the destination is always
    /// GDMA-reachable.
    ///
    /// Falls back to [`DmaBuf::zeroize`] if the engine has no free tag or the
    /// transfer fails, so the buffer is scrubbed either way; both paths use
    /// writes that cannot be optimized away.
    async fn zeroize_mem(&self, _io: &impl HsmIo, dst: &mut DmaBuf) -> HsmResult<()> {
        let len = dst.len();
        if len == 0 {
            return Ok(());
        }
        if self.gdma_zero_region(dst.as_mut_ptr(), len).await.is_err() {
            dst.zeroize();
        }
        Ok(())
    }

    async fn copy_mem_from_host(
        &self,
        io: &impl HsmIo,
        src: HsmDmaAddr,
        dst: &mut DmaBuf,
        prp: bool,
    ) -> HsmResult<()> {
        let len = dst.len() as u32;
        let src_addr = host_dma_buf(src, prp);
        let dst_addr = device_dma_buf(dst.as_mut_ptr(), len);
        self.gdma
            .copy_mem(
                src_addr,
                host_interface(io.pid())?,
                len,
                dst_addr,
                MemInterface::Device,
                len,
            )?
            .await
    }

    async fn copy_mem_from_host_raw(
        &self,
        io: &impl HsmIo,
        desc: &[u8; 16],
        dst: &mut DmaBuf,
        prp: bool,
    ) -> HsmResult<()> {
        // Only inline SGL Data Block descriptors are supported here; the
        // GDMA hardware consumes the descriptor and interprets its SGL
        // format.
        if prp {
            return Err(HsmError::UnsupportedCmd);
        }
        // Transfer length is the descriptor's embedded length; it must
        // match the destination exactly.
        let len = u32::from_le_bytes([desc[8], desc[9], desc[10], desc[11]]);
        if len as usize != dst.len() {
            return Err(HsmError::InvalidArg);
        }
        let src_addr = sgl_desc_buf(desc);
        let dst_addr = device_dma_buf(dst.as_mut_ptr(), len);
        self.gdma
            .copy_mem(
                src_addr,
                host_interface(io.pid())?,
                len,
                dst_addr,
                MemInterface::Device,
                len,
            )?
            .await
    }

    async fn copy_mem_to_host(
        &self,
        io: &impl HsmIo,
        src: &DmaBuf,
        dst: HsmDmaAddr,
        prp: bool,
    ) -> HsmResult<()> {
        let len = src.len() as u32;
        let src_addr = device_dma_buf(src.as_ptr(), len);
        let dst_addr = host_dma_buf(dst, prp);
        self.gdma
            .copy_mem(
                src_addr,
                MemInterface::Device,
                len,
                dst_addr,
                host_interface(io.pid())?,
                len,
            )?
            .await
    }
}

impl UnoHsmPal {
    /// GDMA-zero a GDMA-reachable device region `[dst_ptr, dst_ptr + len)`.
    ///
    /// Copies zeros from the [`ZERO_BASE`] window, chunked to its
    /// [`ZERO_SIZE`] so an arbitrarily large region can be wiped with a
    /// fixed 16 KiB zero source. Both operands use the device
    /// interface. Only valid for GDMA-reachable memory (GSRAM); the M7 TCM
    /// is not on the GDMA fabric and must be wiped by the CPU.
    async fn gdma_zero_region(&self, dst_ptr: *mut u8, len: usize) -> HsmResult<()> {
        let mut off = 0usize;
        while off < len {
            let chunk = core::cmp::min(len - off, ZERO_SIZE as usize);
            let src = device_dma_buf(ZERO_BASE as *const u8, chunk as u32);
            // SAFETY: `off < len`, so `dst_ptr + off` stays within the
            // caller-provided `[dst_ptr, dst_ptr + len)` region.
            let dst = device_dma_buf(unsafe { dst_ptr.add(off) }, chunk as u32);
            self.gdma
                .copy_mem(
                    src,
                    MemInterface::Device,
                    chunk as u32,
                    dst,
                    MemInterface::Device,
                    chunk as u32,
                )?
                .await?;
            off += chunk;
        }
        Ok(())
    }

    /// Securely scrub both per-IO scratch buffers for `io_index`.
    ///
    /// Called on IO teardown so no key material from one IO survives into
    /// the next IO that reuses the slot. On Uno every crypto operand lives
    /// in these bump-allocated buffers (no heap), so wiping them is what
    /// protects private keys / plaintext — the CPU-visible arena is the
    /// only place they exist.
    ///
    /// The SRAM (DMA) buffer is wiped off-CPU with the GDMA engine; the DTCM
    /// (NonDma) buffer sits in the M7 TCM, which GDMA cannot reach, so it is
    /// wiped by the CPU. If the GDMA wipe fails (e.g. no free tags under
    /// heavy concurrency), the SRAM buffer is scrubbed by the CPU as a
    /// fallback so secrets are never left resident.
    ///
    /// Only each heap's *high-water* region is wiped, not its full capacity.
    /// The bump watermark rewinds on every scope exit, but the peak bounds
    /// every byte written since the previous scrub, and everything past it is
    /// already zero from that scrub. Measured over ~1.7k host IOs the DMA peak
    /// averaged ~933 B of the 16 KiB slot (max ~3.3 KiB). The slot is sized to
    /// `ZERO`, so even a full-capacity wipe is a single GDMA transfer.
    /// A heap that was never touched is skipped entirely.
    pub(crate) async fn scrub_io_slot(&self, io_index: u16) {
        let (dma_ptr, dma_len) = crate::alloc::io_slot_dma_dirty(self, io_index);
        if dma_len != 0 && self.gdma_zero_region(dma_ptr, dma_len).await.is_err() {
            // Surface the fallback: a persistent GDMA fault would otherwise
            // silently degrade every wipe into a CPU loop with no signal.
            // Logged via the trace facade (as the iic/oic drivers do for
            // unexpected conditions); compiled out when no trace backend is
            // selected. Correctness is unaffected — the CPU wipe below still
            // fully scrubs the buffer.
            warn!(
                "gdma",
                "SRAM scrub for slot {} fell back to CPU (GDMA wipe failed)", io_index
            );
            // SAFETY: `(dma_ptr, dma_len)` is a prefix of the slot's SRAM
            // buffer, valid for writes over its whole length.
            unsafe { cpu_zeroize(dma_ptr, dma_len) };
        }
        // DTCM (NonDma) heap — not GDMA-reachable, so wipe with the CPU.
        let (nd_ptr, nd_len) = crate::alloc::io_slot_nondma_dirty(self, io_index);
        // SAFETY: `(nd_ptr, nd_len)` is a prefix of the slot's DTCM buffer,
        // valid for writes over its whole length.
        unsafe { cpu_zeroize(nd_ptr, nd_len) };

        // Both heaps are now zero up to their peaks; drop the high-water marks
        // so the next scrub covers only writes made after this point.
        crate::alloc::clear_io_peak(self, io_index);
    }
}

/// Volatile CPU zeroization of `[ptr, ptr + len)` that the optimizer cannot
/// elide, via the vetted [`zeroize`] crate. Used for the M7 TCM (which GDMA
/// cannot reach) and as the GDMA-failure fallback for SRAM.
///
/// Zeroes the widest naturally-aligned element the region supports: an
/// 8-byte-aligned `u64` (QWORD) body, framed by a byte-wise head/tail for
/// any unaligned edges. `[u64]::zeroize()` lowers to 64-bit volatile stores
/// (a single `STRD`/64-bit AXI transfer on Cortex-M7), so it issues half as
/// many stores as a 32-bit wipe and a quarter of a byte-wise one.
///
/// The **head** is normally empty: callers pass a per-IO region base, and
/// both regions are 8-byte aligned (`DTCM_IO_BUF` 0x600, `SRAM_IO_BUF`
/// 0x4000). The **tail** is not — `len` is the heap's dirty high-water
/// mark, not the region size, and the bump allocator aligns to each
/// value's `align_of`, so a watermark that is not a multiple of 8 is the
/// normal case and the tail path runs routinely.
///
/// `zeroize` emits the volatile writes plus a compiler+atomic fence, so
/// the wipe cannot be elided.
///
/// # Safety
///
/// `ptr` must be valid for writes of `len` bytes.
#[inline]
unsafe fn cpu_zeroize(ptr: *mut u8, len: usize) {
    // Byte-wise head up to the first 8-byte boundary (empty when the
    // caller passes an 8-aligned region base, which is the normal case).
    let head = ((8 - (ptr as usize & 7)) & 7).min(len);
    if head != 0 {
        // SAFETY: `head <= len`, so this stays within the caller's region.
        unsafe { core::slice::from_raw_parts_mut(ptr, head) }.zeroize();
    }
    // QWORD body: a whole number of `u64`s at an 8-byte-aligned address.
    let body_len = (len - head) & !7usize;
    if body_len != 0 {
        // SAFETY: `ptr + head` is 8-byte aligned by construction and
        // `body_len` is a `u64` multiple within the region, so the cast and
        // slice are valid for writes.
        let body_ptr = unsafe { ptr.add(head) } as *mut u64;
        let body = unsafe { core::slice::from_raw_parts_mut(body_ptr, body_len / 8) };
        body.zeroize();
    }
    // Byte-wise tail (sub-`u64` remainder). Unlike the head this is
    // common: `len` is the dirty high-water mark, not the region size.
    let tail_off = head + body_len;
    if tail_off < len {
        // SAFETY: `tail_off < len`, so `ptr + tail_off` is within the region.
        unsafe { core::slice::from_raw_parts_mut(ptr.add(tail_off), len - tail_off) }.zeroize();
    }
}
