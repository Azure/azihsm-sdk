// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Out-of-band (OOB) side-band item transfer over NVMe SGL descriptors.
//!
//! Some TBOR commands carry bulk evidence — DER certificate chains and
//! COSE_Sign1 attestation reports — **out of band** rather than inside
//! the 4 KiB request buffer. The SQE's `oob_prp` points at a host page
//! of 16-byte **NVMe SGL Data Block descriptors**; a TBOR message
//! references an item by its **index** into that array. [`copy_oob`]
//! locates the indexed descriptor and forwards it **verbatim** to the
//! GDMA ([`HsmGdmaController::copy_mem_from_host_raw`]), which interprets
//! the descriptor and copies the item into a caller-allocated
//! [`DmaBuf`]. This layer does **no** SGL parsing itself — it only
//! bounds the index and computes the descriptor's address.
//!
//! The Uno GDMA does not walk PRP lists; each transfer is a single SGL
//! Data Block (arbitrary address, no page-alignment constraint), so OOB
//! items are copied one at a time by index.

#![no_std]

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmDmaAddr;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmGdmaController;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;

/// Size of one NVMe SGL Data Block descriptor on the wire.
pub const SGL_ENTRY_LEN: usize = 16;

/// Reference to the OOB SGL descriptor array carried by the SQE
/// (`oob_prp` + `oob_len`).
#[derive(Debug, Clone, Copy)]
pub struct OobPtr {
    /// Host pointer to the 16-byte-per-entry SGL descriptor array.
    pub prp: HsmDmaAddr,
    /// Byte length of the descriptor array (`num_entries * 16`).
    pub len: u32,
}

impl OobPtr {
    /// Number of SGL descriptors in the array.
    #[inline]
    pub fn entry_count(&self) -> usize {
        self.len as usize / SGL_ENTRY_LEN
    }
}

/// Byte-offset an [`HsmDmaAddr`], rejecting 64-bit overflow.
fn addr_offset(base: HsmDmaAddr, off: u64) -> HsmResult<HsmDmaAddr> {
    let v = ((u64::from(base.hi) << 32) | u64::from(base.lo))
        .checked_add(off)
        .ok_or(HsmError::InvalidArg)?;
    Ok(HsmDmaAddr {
        lo: v as u32,
        hi: (v >> 32) as u32,
    })
}

/// Host address of the SGL Data Block descriptor at `index`, bounds-checked
/// against the descriptor array length.
///
/// This is the only interpretation the OOB layer does — locating the
/// 16-byte descriptor.  The descriptor's contents (address / length /
/// type) are consumed by the GDMA layer
/// ([`HsmGdmaController::copy_mem_from_host_raw`]), not here.
///
/// # Errors
/// * [`HsmError::InvalidArg`] — `index` is out of bounds for `oob.len`,
///   or the descriptor address overflows.
pub fn entry_addr(oob: &OobPtr, index: usize) -> HsmResult<HsmDmaAddr> {
    let entry_off = index
        .checked_mul(SGL_ENTRY_LEN)
        .ok_or(HsmError::InvalidArg)?;
    let entry_end = entry_off
        .checked_add(SGL_ENTRY_LEN)
        .ok_or(HsmError::InvalidArg)?;
    if entry_end > oob.len as usize {
        return Err(HsmError::InvalidArg);
    }
    addr_offset(oob.prp, entry_off as u64)
}

/// Copy OOB item `index` into the caller-allocated `dst`.
///
/// Locates the 16-byte SGL Data Block descriptor at `oob.prp + index*16`,
/// reads it, and forwards it **verbatim** to the GDMA
/// ([`HsmGdmaController::copy_mem_from_host_raw`]), which interprets the
/// descriptor (address / length / type) and copies the item into `dst`.
/// The OOB layer does no SGL parsing itself.
///
/// The GDMA enforces that the descriptor's `length` equals `dst.len()`,
/// so the caller must size `dst` to the item's length (from the TBOR
/// descriptor, which must agree with the OOB descriptor).
///
/// # Errors
/// * [`HsmError::InvalidArg`] — `index` out of bounds, or the descriptor
///   `length` does not equal `dst.len()` (from the GDMA).
/// * [`HsmError`] — propagated from the GDMA / allocator.
pub async fn copy_oob<P>(
    pal: &P,
    io: &impl HsmIo,
    oob: &OobPtr,
    index: usize,
    dst: &mut DmaBuf,
) -> HsmResult<()>
where
    P: HsmGdmaController + HsmAlloc,
{
    let entry_addr = entry_addr(oob, index)?;

    pal.alloc_scoped_async(io, async |scoped| {
        // Read the 16-byte SGL Data Block descriptor (unaligned address
        // is fine for an SGL read).
        let entry = scoped.dma_alloc(SGL_ENTRY_LEN)?;
        pal.copy_mem_from_host(io, entry_addr, entry, false).await?;

        // Borrow the descriptor bytes directly as a fixed array (no
        // copy) — `entry` derefs to a 16-byte `[u8]`.
        let bytes: &[u8] = entry;
        let raw: &[u8; SGL_ENTRY_LEN] = bytes.try_into().map_err(|_| HsmError::InternalError)?;

        // Forward the raw descriptor to the GDMA, which interprets it and
        // copies the item into `dst` (validating `length == dst.len()`).
        pal.copy_mem_from_host_raw(io, raw, dst, false).await?;
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn entry_count_divides_by_16() {
        let oob = OobPtr {
            prp: HsmDmaAddr { lo: 0x1000, hi: 0 },
            len: 48,
        };
        assert_eq!(oob.entry_count(), 3);
    }

    #[test]
    fn entry_addr_computes_indexed_offset() {
        let oob = OobPtr {
            prp: HsmDmaAddr { lo: 0x1000, hi: 0 },
            len: 48,
        };
        assert_eq!(
            entry_addr(&oob, 0).unwrap(),
            HsmDmaAddr { lo: 0x1000, hi: 0 }
        );
        assert_eq!(
            entry_addr(&oob, 2).unwrap(),
            HsmDmaAddr { lo: 0x1020, hi: 0 }
        );
    }

    #[test]
    fn entry_addr_rejects_out_of_bounds_index() {
        let oob = OobPtr {
            prp: HsmDmaAddr { lo: 0x1000, hi: 0 },
            len: 48, // 3 entries → valid indices 0..=2
        };
        assert_eq!(entry_addr(&oob, 3), Err(HsmError::InvalidArg));
        assert_eq!(entry_addr(&oob, usize::MAX), Err(HsmError::InvalidArg));
    }

    #[test]
    fn entry_addr_crosses_32bit_boundary() {
        let oob = OobPtr {
            prp: HsmDmaAddr {
                lo: 0xFFFF_FFF0,
                hi: 0,
            },
            len: 32,
        };
        // Entry 1 at +16 wraps `lo` into `hi`.
        assert_eq!(entry_addr(&oob, 1).unwrap(), HsmDmaAddr { lo: 0, hi: 1 });
    }

    #[test]
    fn addr_offset_rejects_overflow() {
        assert_eq!(
            addr_offset(
                HsmDmaAddr {
                    lo: 0xFFFF_FFFF,
                    hi: 0xFFFF_FFFF
                },
                1
            ),
            Err(HsmError::InvalidArg)
        );
    }
}
