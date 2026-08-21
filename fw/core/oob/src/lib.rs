// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Out-of-band (OOB) side-band item transfer via the host **Metadata
//! Page**.
//!
//! Some TBOR commands carry bulk evidence — DER certificate chains and
//! COSE_Sign1 attestation reports — **out of band** rather than inside
//! the 4 KiB request buffer. The SQE's `oob_prp` (DW13-14) points at a
//! single 4 KiB host page, the *Metadata Page*, and a TBOR message
//! references an item by its **index** into that page.
//!
//! Layout (mirrors `azihsm_hsm_data_xfer_metadata` in the Linux driver,
//! `drivers/linux/drvsrc/azihsm_hsm_cmd.h`):
//!
//! ```text
//! offset 0            buffer_count : u32          (1 ..= MAX_OOB_ITEMS)
//! offset 4 + 16*i     xfer_length      : u32      bytes of item i
//!                     rsvd             : u32
//!                     hw_sgl_mem_paddr : u64      -> item i's SGL segment
//! offset 260..4095    rsvd
//! ```
//!
//! Each `hw_sgl_mem_paddr` is **not** the data: it points at a per-item
//! **NVMe SGL segment**, a page of 16-byte SGL Data Block descriptors
//! (`addr(8) ‖ length(4) ‖ rsvd(3) ‖ type(1)`), one per physically
//! contiguous chunk of the host buffer. [`copy_oob`] walks that segment
//! and forwards each descriptor **verbatim** to the GDMA
//! ([`HsmGdmaController::copy_mem_from_host_raw`]), which interprets it
//! and copies the chunk into the matching sub-range of a caller-allocated
//! [`DmaBuf`].
//!
//! The Uno GDMA does not walk PRP lists or SGL chains itself; each
//! transfer is a single SGL Data Block, so this layer drives the walk one
//! descriptor at a time.
//!
//! Note the SQE's `oob_len` (DW15) is **not** used: the driver leaves it
//! reserved, and the Metadata Page is self-describing via `buffer_count`.
//! Presence of OOB data is signalled by a non-null `oob_prp`.

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

/// Size of one Metadata Page entry (`xfer_length ‖ rsvd ‖ paddr`).
pub const METADATA_ENTRY_LEN: usize = 16;

/// Byte offset of the first entry, past the `buffer_count` header.
pub const METADATA_ENTRY_OFF: usize = 4;

/// Maximum number of OOB items the device accepts, matching the driver's
/// `AZIHSM_MAX_DATA_XFER_DEVICE_BUFFERS`.
pub const MAX_OOB_ITEMS: usize = 16;

/// A per-item SGL segment is read in chunks of this size rather than in
/// one 4 KiB read, to keep the scratch allocation small. The driver
/// allocates each segment as `seg_cnt * PAGE_SIZE` (so at least one full
/// page) and rejects items needing more than one segment, hence the
/// walk is bounded by the page rather than by a fixed descriptor count.
const SEG_CHUNK_LEN: usize = 256;
const SEG_CHUNK_DESCRIPTORS: usize = SEG_CHUNK_LEN / SGL_ENTRY_LEN;
const SEG_PAGE_LEN: usize = 4096;
const SEG_CHUNKS: usize = SEG_PAGE_LEN / SEG_CHUNK_LEN;

/// Size of the Metadata Page (`METADATA_SIZE` in the driver UAPI).
const METADATA_PAGE_LEN: usize = 4096;

/// Granularity that Metadata Page prefix reads are rounded up to. The
/// GDMA faults on very small transfers, so the header/entry fetch is
/// padded rather than issued as a 4- or 16-byte read.
const PREFIX_GRAIN: usize = 32;

/// Reference to the OOB Metadata Page carried by the SQE (`oob_prp`).
#[derive(Debug, Clone, Copy)]
pub struct OobPtr {
    /// Host pointer to the 4 KiB Metadata Page.
    pub prp: HsmDmaAddr,
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

/// Host address of the Metadata Page entry for `index`.
///
/// Entries start at [`METADATA_ENTRY_OFF`] (past the `buffer_count`
/// header) and are [`METADATA_ENTRY_LEN`] bytes each. The index is
/// bounded by [`MAX_OOB_ITEMS`] here; it is additionally checked against
/// the page's own `buffer_count` in [`copy_oob`].
///
/// # Errors
/// * [`HsmError::InvalidArg`] — `index` >= [`MAX_OOB_ITEMS`], or the
///   address overflows.
pub fn entry_addr(oob: &OobPtr, index: usize) -> HsmResult<HsmDmaAddr> {
    if index >= MAX_OOB_ITEMS {
        return Err(HsmError::InvalidArg);
    }
    let off = index
        .checked_mul(METADATA_ENTRY_LEN)
        .and_then(|v| v.checked_add(METADATA_ENTRY_OFF))
        .ok_or(HsmError::InvalidArg)?;
    addr_offset(oob.prp, off as u64)
}

/// Read a little-endian `u32` from `bytes[off..off + 4]`.
fn le_u32(bytes: &[u8], off: usize) -> HsmResult<u32> {
    let raw: [u8; 4] = bytes
        .get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .ok_or(HsmError::InternalError)?;
    Ok(u32::from_le_bytes(raw))
}

/// Read a little-endian `u64` from `bytes[off..off + 8]` as an
/// [`HsmDmaAddr`].
fn le_addr(bytes: &[u8], off: usize) -> HsmResult<HsmDmaAddr> {
    Ok(HsmDmaAddr {
        lo: le_u32(bytes, off)?,
        hi: le_u32(bytes, off + 4)?,
    })
}

/// Copy OOB item `index` into the caller-allocated `dst`.
///
/// Reads the Metadata Page header and the item's entry, then walks the
/// item's NVMe SGL segment, forwarding each 16-byte Data Block descriptor
/// to the GDMA so its chunk lands at the running offset in `dst`.
///
/// `dst.len()` must equal the entry's `xfer_length`, and the segment's
/// descriptor lengths must sum to exactly that — a short or over-long
/// segment is rejected rather than silently truncating.
///
/// # Errors
/// * [`HsmError::InvalidArg`] — `index` out of range for the page's
///   `buffer_count`, a `buffer_count` above [`MAX_OOB_ITEMS`],
///   `xfer_length != dst.len()`, or a segment whose chunks do not sum to
///   `xfer_length`.
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
    // Bounds the index before any DMA; the page's own `buffer_count`
    // is checked once the prefix has been read.
    if index >= MAX_OOB_ITEMS {
        return Err(HsmError::InvalidArg);
    }

    pal.alloc_scoped_async(io, async |scoped| {
        // ── Metadata Page prefix: header + entries up to `index` ─────
        //
        // Read the header and the wanted entry in a single transfer.
        // Two separate 4- and 16-byte reads are avoided deliberately:
        // the GDMA faults on very small transfers, and one read is
        // cheaper anyway. The prefix is rounded up to `PREFIX_GRAIN` and
        // always stays inside the 4 KiB page.
        let want = METADATA_ENTRY_OFF + METADATA_ENTRY_LEN * (index + 1);
        let prefix_len = want.next_multiple_of(PREFIX_GRAIN).min(METADATA_PAGE_LEN);
        let hdr = scoped.dma_alloc(prefix_len)?;
        // `prp = true`: the Metadata Page is a plain contiguous host
        // buffer, so the address goes in a PRP and the length is passed
        // separately. The SGL form would put the length in the
        // descriptor's second word, which this call site leaves zero —
        // a zero-length SGL read that the GDMA rejects.
        pal.copy_mem_from_host(io, oob.prp, hdr, true).await?;

        let buffer_count = le_u32(hdr, 0)? as usize;
        if buffer_count == 0 || buffer_count > MAX_OOB_ITEMS || index >= buffer_count {
            return Err(HsmError::InvalidArg);
        }

        // ── The item's entry: `xfer_length ‖ rsvd ‖ hw_sgl_mem_paddr` ──
        let entry_off = METADATA_ENTRY_OFF + METADATA_ENTRY_LEN * index;
        let xfer_length = le_u32(hdr, entry_off)? as usize;
        let seg_addr = le_addr(hdr, entry_off + 8)?;

        // The caller sizes `dst` from the TBOR descriptor; the two must
        // agree or we would copy a different item than was requested.
        if xfer_length != dst.len() {
            return Err(HsmError::InvalidArg);
        }
        if seg_addr.is_null() {
            return Err(HsmError::InvalidArg);
        }

        // ── Walk the item's SGL segment, chunk by chunk ──────────────
        //
        // The segment is read in `SEG_CHUNK_LEN` slices rather than one
        // descriptor at a time: 16-byte reads hit the same GDMA
        // small-transfer fault as the header. The walk spans the whole
        // segment page, so an item split across many descriptors is
        // handled; the driver allocates at least one full page per
        // segment and rejects items needing more than one segment.
        let seg = scoped.dma_alloc(SEG_CHUNK_LEN)?;
        let mut copied = 0usize;
        let mut tail: &mut DmaBuf = dst;

        'outer: for chunk_idx in 0..SEG_CHUNKS {
            if copied == xfer_length {
                break;
            }
            let chunk_addr = addr_offset(seg_addr, (chunk_idx * SEG_CHUNK_LEN) as u64)?;
            // Plain contiguous host memory — read via PRP, as above.
            pal.copy_mem_from_host(io, chunk_addr, seg, true).await?;

            for i in 0..SEG_CHUNK_DESCRIPTORS {
                if copied == xfer_length {
                    break 'outer;
                }
                let off = i * SGL_ENTRY_LEN;

                // NVMe SGL Data Block: `addr(8) ‖ length(4) ‖ rsvd(3) ‖ type(1)`.
                let chunk = le_u32(seg, off + 8)? as usize;
                if chunk == 0 || copied + chunk > xfer_length {
                    return Err(HsmError::InvalidArg);
                }

                // Hand the GDMA exactly this chunk's destination window;
                // it validates the descriptor length against the slice.
                let (head, rest) = tail.split_at_mut(chunk);
                let raw: &[u8; SGL_ENTRY_LEN] = seg
                    .get(off..off + SGL_ENTRY_LEN)
                    .and_then(|s| s.try_into().ok())
                    .ok_or(HsmError::InternalError)?;
                pal.copy_mem_from_host_raw(io, raw, head, false).await?;

                copied += chunk;
                tail = rest;
            }
        }

        // A segment that never reached `xfer_length` is malformed.
        if copied != xfer_length {
            return Err(HsmError::InvalidArg);
        }
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn entry_addr_skips_the_buffer_count_header() {
        let oob = OobPtr {
            prp: HsmDmaAddr { lo: 0x1000, hi: 0 },
        };
        // Entry 0 sits immediately after the 4-byte header.
        assert_eq!(
            entry_addr(&oob, 0).unwrap(),
            HsmDmaAddr { lo: 0x1004, hi: 0 }
        );
        // Entry 2 is at 4 + 2*16 = 0x24.
        assert_eq!(
            entry_addr(&oob, 2).unwrap(),
            HsmDmaAddr { lo: 0x1024, hi: 0 }
        );
    }

    #[test]
    fn entry_addr_rejects_index_beyond_device_max() {
        let oob = OobPtr {
            prp: HsmDmaAddr { lo: 0x1000, hi: 0 },
        };
        assert_eq!(entry_addr(&oob, MAX_OOB_ITEMS), Err(HsmError::InvalidArg));
        assert_eq!(entry_addr(&oob, usize::MAX), Err(HsmError::InvalidArg));
    }

    #[test]
    fn entry_addr_crosses_32bit_boundary() {
        let oob = OobPtr {
            prp: HsmDmaAddr {
                lo: 0xFFFF_FFFC,
                hi: 0,
            },
        };
        // Entry 0 at +4 wraps `lo` into `hi`.
        assert_eq!(entry_addr(&oob, 0).unwrap(), HsmDmaAddr { lo: 0, hi: 1 });
    }

    #[test]
    fn addr_offset_rejects_overflow() {
        let base = HsmDmaAddr {
            lo: 0xFFFF_FFFF,
            hi: 0xFFFF_FFFF,
        };
        assert_eq!(addr_offset(base, 1), Err(HsmError::InvalidArg));
    }

    #[test]
    fn le_readers_decode_little_endian() {
        let bytes = [
            0x78, 0x56, 0x34, 0x12, 0x01, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0, 0, 1, 0, 0, 0,
        ];
        assert_eq!(le_u32(&bytes, 0).unwrap(), 0x1234_5678);
        assert_eq!(
            le_addr(&bytes, 8).unwrap(),
            HsmDmaAddr {
                lo: 0x0000_BEEF,
                hi: 1
            }
        );
    }

    #[test]
    fn le_readers_reject_short_input() {
        let bytes = [0u8; 3];
        assert_eq!(le_u32(&bytes, 0), Err(HsmError::InternalError));
    }
}
