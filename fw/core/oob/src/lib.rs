// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Out-of-band (OOB) side-band item transfer over NVMe SGL descriptors.
//!
//! Some TBOR commands carry bulk evidence — DER certificate chains and
//! COSE_Sign1 attestation reports — **out of band** rather than inside
//! the 4 KiB request buffer. The SQE's `oob_prp` points at a host page
//! of 16-byte **NVMe SGL Data Block descriptors**; a TBOR message
//! references an item by its **index** into that array. [`copy_oob`]
//! locates and validates the indexed descriptor (via
//! [`parse_sgl_data_block`]), then forwards it to the GDMA
//! ([`HsmGdmaController::copy_mem_from_host_raw`]), which copies the item
//! into a caller-allocated [`DmaBuf`].
//!
//! Descriptor validation (type/reserved bytes, null-address guard) belongs
//! here in the OOB/core layer — not in PAL traits — because it is
//! protocol/wire logic, not a platform capability. The PAL's
//! `copy_mem_from_host_raw` is a raw transport primitive that receives an
//! already-validated descriptor.
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

/// Parse and validate a 16-byte NVMe SGL Data Block descriptor, returning
/// the `(address, length)` it encodes.
///
/// The descriptor layout is `address(8, LE) ‖ length(4, LE) ‖
/// reserved(3) ‖ SGL-identifier(1)`.  Only an **address-based Data Block**
/// descriptor is accepted: the SGL-identifier byte encodes the descriptor
/// type (bits 7:4) and sub-type (bits 3:0), both of which are `0h` for an
/// address-based Data Block, and the three reserved bytes must be zero.
///
/// This is a core/OOB domain function — descriptor format validation is
/// protocol/wire logic, not a platform capability, so it lives here rather
/// than in the PAL traits boundary.
///
/// # Errors
///
/// - [`HsmError::InvalidArg`] — a non-zero reserved or SGL-identifier byte
///   (i.e. not an address-based Data Block descriptor), or a null source
///   address paired with a non-zero `length`.
pub fn parse_sgl_data_block(desc: &[u8; 16]) -> HsmResult<(HsmDmaAddr, u32)> {
    // Bytes 12-14 (reserved) and byte 15 (SGL identifier: type nibble 0h
    // = Data Block, sub-type nibble 0h = address) must all be zero.
    if desc[12] != 0 || desc[13] != 0 || desc[14] != 0 || desc[15] != 0 {
        return Err(HsmError::InvalidArg);
    }
    let addr = HsmDmaAddr {
        lo: u32::from_le_bytes([desc[0], desc[1], desc[2], desc[3]]),
        hi: u32::from_le_bytes([desc[4], desc[5], desc[6], desc[7]]),
    };
    let len = u32::from_le_bytes([desc[8], desc[9], desc[10], desc[11]]);
    // A non-empty transfer must name a non-null source address.
    if len != 0 && addr.is_null() {
        return Err(HsmError::InvalidArg);
    }
    Ok((addr, len))
}

/// Copy OOB item `index` into the caller-allocated `dst`.
///
/// Locates the 16-byte SGL Data Block descriptor at `oob.prp + index*16`,
/// reads it from host memory, validates it via [`parse_sgl_data_block`]
/// (type/reserved bytes and null-address guard), then forwards the
/// already-validated descriptor to the GDMA
/// ([`HsmGdmaController::copy_mem_from_host_raw`]) as a raw transport
/// primitive. The GDMA copies the item into `dst`.
///
/// The caller must size `dst` to the item's length (from the TBOR
/// descriptor): `dst.len()` must equal the OOB descriptor's embedded
/// `length` field, or the call returns [`HsmError::InvalidArg`].
///
/// # Errors
/// * [`HsmError::InvalidArg`] — `index` out of bounds; invalid descriptor
///   type/reserved bytes or null source; descriptor `length` ≠ `dst.len()`.
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

        // Validate descriptor type/reserved bytes and null-address guard.
        // This is protocol/wire logic that belongs in the OOB core layer,
        // not in the PAL transport primitive.
        let (_addr, len) = parse_sgl_data_block(raw)?;
        if len as usize != dst.len() {
            return Err(HsmError::InvalidArg);
        }

        // Forward the validated descriptor to the GDMA as a raw copy.
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

    #[test]
    fn parse_sgl_data_block_validates_type_reserved_and_null() {
        // Build a valid descriptor pointing at a local buffer.
        let src = [0u8; 16];
        let addr = src.as_ptr() as u64;
        let mut desc = [0u8; 16];
        desc[..8].copy_from_slice(&addr.to_le_bytes());
        desc[8..12].copy_from_slice(&(src.len() as u32).to_le_bytes());

        let (parsed_addr, len) = parse_sgl_data_block(&desc).expect("valid descriptor");
        assert!(!parsed_addr.is_null());
        assert_eq!(len, 16);

        // A non-zero SGL-identifier byte (a non-Data-Block type) is rejected.
        let mut bad_type = desc;
        bad_type[15] = 0x20;
        assert_eq!(parse_sgl_data_block(&bad_type), Err(HsmError::InvalidArg));

        // A non-zero reserved byte is rejected.
        let mut bad_rsvd = desc;
        bad_rsvd[12] = 0x01;
        assert_eq!(parse_sgl_data_block(&bad_rsvd), Err(HsmError::InvalidArg));

        // A null source address with a non-empty length is rejected.
        let mut null_src = [0u8; 16];
        null_src[8..12].copy_from_slice(&16u32.to_le_bytes());
        assert_eq!(parse_sgl_data_block(&null_src), Err(HsmError::InvalidArg));

        // A null source address with length 0 is a permitted empty item.
        let (parsed_addr, len) = parse_sgl_data_block(&[0u8; 16]).expect("empty descriptor");
        assert!(parsed_addr.is_null());
        assert_eq!(len, 0);
    }
}
