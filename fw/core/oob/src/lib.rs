// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Out-of-band (OOB) side-band item transfer over NVMe SGL descriptors.
//!
//! Some TBOR commands carry bulk evidence — DER certificate chains and
//! COSE_Sign1 attestation reports — **out of band** rather than inside
//! the 4 KiB request buffer. The SQE's `oob_prp` points at a host page
//! of 16-byte **NVMe SGL descriptors** (the driver's *Metadata Page*)
//! and `oob_len` (its `metadata_size`) gives that array's byte size; a
//! TBOR message references an item by its **index** into the array.
//!
//! Each entry is the descriptor of the item's first SGL **segment**, a
//! run of Data Block descriptors (`addr(8) ‖ len(4) ‖ rsvd(3) ‖
//! sub_type:4|type:4`), one per physically contiguous chunk of the host
//! buffer:
//!
//! * `type == LAST_SEGMENT` — `len` is the exact byte count of Data
//!   Block descriptors (`16 * sg_cnt`); the item ends there.
//! * `type == SEGMENT` — the segment is a full page whose **final**
//!   descriptor chains to the next segment.
//!
//! [`copy_oob`] walks that chain and forwards each Data Block descriptor
//! **verbatim** to the GDMA
//! ([`HsmGdmaController::copy_mem_from_host_raw`]), which interprets it
//! and copies the chunk into the matching sub-range of a caller-allocated
//! [`DmaBuf`].
//!
//! The Uno GDMA does not walk PRP lists or SGL chains itself; each
//! transfer is a single SGL Data Block, so this layer drives the walk one
//! descriptor at a time.

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

/// NVMe SGL descriptor type, in the high nibble of the descriptor's last
/// byte (`sub_type` occupies the low nibble).
const SGL_TYPE_DATA_BLOCK: u8 = 0x0;
const SGL_TYPE_SEGMENT: u8 = 0x2;
const SGL_TYPE_LAST_SEGMENT: u8 = 0x3;

/// A segment is read in chunks of this size rather than one descriptor at
/// a time: 16-byte reads hit the GDMA's small-transfer fault.
const SEG_CHUNK_LEN: usize = 256;
const SEG_CHUNK_DESCRIPTORS: usize = SEG_CHUNK_LEN / SGL_ENTRY_LEN;

/// A chained (`SEGMENT`-type) segment is one host page.
const SEG_PAGE_LEN: usize = 4096;

/// Upper bound on chained segments walked for a single item, so a
/// malformed page cannot spin forever.
const MAX_SEGMENTS: usize = 16;

/// Bytes fetched when reading a single Metadata Page entry. The GDMA
/// faults on very small transfers, so the 16-byte entry read is padded.
const ENTRY_READ_LEN: usize = 32;

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
/// Reads the item's entry at `oob.prp + index*16` — the descriptor of its
/// first SGL segment — then walks that segment (and any chained
/// segments), forwarding each Data Block descriptor **verbatim** to the
/// GDMA ([`HsmGdmaController::copy_mem_from_host_raw`]) so its chunk
/// lands at the running offset in `dst`.
///
/// The item's payload length is not carried in the metadata: it is the
/// sum of the Data Block lengths, and must come to exactly `dst.len()`.
/// A short or over-long item is rejected rather than silently
/// truncating.
///
/// # Errors
/// * [`HsmError::InvalidArg`] — `index` out of bounds, a malformed entry
///   (null address, unexpected descriptor type, `len` not a multiple of
///   16), a chain longer than [`MAX_SEGMENTS`], or chunks that do not sum
///   to `dst.len()`.
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
    // Bounds-check `index` against `oob.len`. The address itself is
    // recomputed below, aligned down for the padded read.
    entry_addr(oob, index)?;

    pal.alloc_scoped_async(io, async |scoped| {
        // Read the item's 16-byte entry. Three hardware/safety
        // constraints apply, the first two invisible on the emulator
        // (which never models the GDMA descriptor):
        //
        // * `prp = true` — the Metadata Page is plain contiguous host
        //   memory, so the address goes in a PRP and the length is passed
        //   separately. The SGL form would take the length from the
        //   descriptor's second word, which this call site leaves zero,
        //   and the GDMA rejects the zero-length read with `dma_error(1)`
        //   (`0x08f08101`).
        // * the read is padded to `ENTRY_READ_LEN` — the GDMA faults on
        //   very small transfers.
        // * the padded read is *aligned down* to `ENTRY_READ_LEN` and the
        //   entry parsed at the offset within it. SQE validation allows
        //   `oob_len` up to a full page, so a naive padded read at a high
        //   index (entry 255 sits at 4080) would run past the end of the
        //   validated page. Aligning down keeps every read inside it,
        //   since `ENTRY_READ_LEN` divides the page size.
        let entry_off = index
            .checked_mul(SGL_ENTRY_LEN)
            .ok_or(HsmError::InvalidArg)?;
        let read_off = entry_off & !(ENTRY_READ_LEN - 1);
        let inner = entry_off - read_off;
        let read_addr = addr_offset(oob.prp, read_off as u64)?;

        let entry = scoped.dma_alloc(ENTRY_READ_LEN)?;
        pal.copy_mem_from_host(io, read_addr, entry, true).await?;

        let mut seg_addr = le_addr(entry, inner)?;
        let mut seg_len = le_u32(entry, inner + 8)? as usize;
        let mut seg_type = desc_type(entry, inner)?;

        let mut copied = 0usize;
        let total = dst.len();
        let mut tail: &mut DmaBuf = dst;

        // Walk the segment chain. A `LAST_SEGMENT` descriptor's `len` is
        // the exact byte count of Data Block descriptors; a `SEGMENT`
        // descriptor covers a full page whose final descriptor chains
        // onward rather than describing data.
        let seg = scoped.dma_alloc(SEG_CHUNK_LEN)?;

        for _ in 0..MAX_SEGMENTS {
            if seg_addr.is_null() {
                return Err(HsmError::InvalidArg);
            }
            let (descriptors, chained) =
                segment_shape(seg_len, seg_type).ok_or(HsmError::InvalidArg)?;

            let mut next: Option<(HsmDmaAddr, usize, u8)> = None;

            // Read the segment in `SEG_CHUNK_LEN` slices: 16-byte reads
            // hit the GDMA's small-transfer fault.
            for chunk_idx in 0..seg_len.div_ceil(SEG_CHUNK_LEN) {
                let chunk_addr = addr_offset(seg_addr, (chunk_idx * SEG_CHUNK_LEN) as u64)?;
                // Plain contiguous host memory — read via PRP; the SGL
                // form would put the length in the descriptor's second
                // word, which this call site leaves zero, and the GDMA
                // rejects a zero-length read.
                pal.copy_mem_from_host(io, chunk_addr, seg, true).await?;

                for i in 0..SEG_CHUNK_DESCRIPTORS {
                    let desc_idx = chunk_idx * SEG_CHUNK_DESCRIPTORS + i;
                    let off = i * SGL_ENTRY_LEN;

                    // Past the data descriptors: for a chained segment
                    // the next one is the segment pointer itself.
                    if desc_idx == descriptors {
                        if chained {
                            next = Some((
                                le_addr(seg, off)?,
                                le_u32(seg, off + 8)? as usize,
                                desc_type(seg, off)?,
                            ));
                        }
                        break;
                    }
                    if desc_idx > descriptors {
                        break;
                    }

                    if desc_type(seg, off)? != SGL_TYPE_DATA_BLOCK {
                        return Err(HsmError::InvalidArg);
                    }
                    let chunk = le_u32(seg, off + 8)? as usize;
                    if chunk == 0 || copied + chunk > total {
                        return Err(HsmError::InvalidArg);
                    }

                    // Hand the GDMA exactly this chunk's destination
                    // window; it validates the descriptor length against
                    // the slice.
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

            match next {
                Some((addr, len, ty)) => {
                    seg_addr = addr;
                    seg_len = len;
                    seg_type = ty;
                }
                None => break,
            }
        }

        // The chunks must account for the caller's buffer exactly.
        if copied != total {
            return Err(HsmError::InvalidArg);
        }
        Ok(())
    })
    .await
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

/// NVMe SGL descriptor type — the high nibble of the descriptor's last
/// byte. The low nibble is `sub_type`, always `SUBTYPE_ADDRESS` (0)
/// here, and is not inspected.
fn desc_type(bytes: &[u8], off: usize) -> HsmResult<u8> {
    let b = bytes
        .get(off + SGL_ENTRY_LEN - 1)
        .ok_or(HsmError::InternalError)?;
    Ok(b >> 4)
}

/// How many Data Block descriptors a segment contributes, and whether it
/// chains onward. `None` for a malformed or out-of-contract segment.
///
/// `seg_len` is host-controlled and drives both the read loop and the DMA
/// reads, so it is bounded for **every** descriptor type: an unbounded
/// `LAST_SEGMENT` length would spin the loop and read far past the
/// segment allocation. The driver backs every segment with whole pages
/// (`coh_mem_sz = seg_cnt * PAGE_SIZE`, `azihsm_dma_io.c`) and rejects
/// items needing more than one page of descriptors, so a segment can
/// never legitimately exceed [`SEG_PAGE_LEN`].
fn segment_shape(seg_len: usize, seg_type: u8) -> Option<(usize, bool)> {
    if seg_len == 0 || seg_len > SEG_PAGE_LEN || !seg_len.is_multiple_of(SGL_ENTRY_LEN) {
        return None;
    }
    match seg_type {
        SGL_TYPE_LAST_SEGMENT => Some((seg_len / SGL_ENTRY_LEN, false)),
        // The final descriptor chains to the next segment rather than
        // describing data, so a chained segment needs at least two.
        SGL_TYPE_SEGMENT if seg_len >= 2 * SGL_ENTRY_LEN => {
            Some((seg_len / SGL_ENTRY_LEN - 1, true))
        }
        _ => None,
    }
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

    /// The padded entry read must stay inside the Metadata Page even for
    /// the highest index SQE validation permits (a full page of entries).
    /// Aligning the read down to `ENTRY_READ_LEN` is what guarantees it.
    #[test]
    fn padded_entry_read_stays_within_the_page() {
        const PAGE: usize = 4096;
        assert!(PAGE.is_multiple_of(ENTRY_READ_LEN));
        for index in 0..PAGE / SGL_ENTRY_LEN {
            let entry_off = index * SGL_ENTRY_LEN;
            let read_off = entry_off & !(ENTRY_READ_LEN - 1);
            let inner = entry_off - read_off;
            // The whole padded read is inside the page ...
            assert!(read_off + ENTRY_READ_LEN <= PAGE, "index {index} overruns");
            // ... and the entry sits wholly inside the padded read.
            assert!(inner + SGL_ENTRY_LEN <= ENTRY_READ_LEN);
            // ... at the address the caller asked for.
            assert_eq!(read_off + inner, entry_off);
        }
    }

    /// A segment length is host-controlled, so it is bounded for every
    /// descriptor type — an unbounded `LAST_SEGMENT` would drive both an
    /// enormous read loop and DMA past the segment allocation.
    #[test]
    fn segment_length_is_bounded_for_every_type() {
        for ty in [SGL_TYPE_LAST_SEGMENT, SGL_TYPE_SEGMENT] {
            assert!(
                segment_shape(SEG_PAGE_LEN + SGL_ENTRY_LEN, ty).is_none(),
                "type {ty:#x} accepted an over-page segment"
            );
            assert!(segment_shape(0, ty).is_none());
            assert!(segment_shape(SGL_ENTRY_LEN + 1, ty).is_none());
            assert!(segment_shape(usize::MAX, ty).is_none());
        }
        // A single descriptor is a valid last segment, but a chained
        // segment needs a second one to hold the chain pointer.
        assert_eq!(
            segment_shape(SGL_ENTRY_LEN, SGL_TYPE_LAST_SEGMENT),
            Some((1, false))
        );
        assert!(segment_shape(SGL_ENTRY_LEN, SGL_TYPE_SEGMENT).is_none());
        assert_eq!(
            segment_shape(2 * SGL_ENTRY_LEN, SGL_TYPE_SEGMENT),
            Some((1, true))
        );
        // Unknown descriptor types are rejected outright.
        assert!(segment_shape(SEG_PAGE_LEN, SGL_TYPE_DATA_BLOCK).is_none());
    }

    #[test]
    fn desc_type_reads_the_high_nibble() {
        let mut desc = [0u8; SGL_ENTRY_LEN];
        assert_eq!(desc_type(&desc, 0).unwrap(), SGL_TYPE_DATA_BLOCK);
        desc[SGL_ENTRY_LEN - 1] = SGL_TYPE_LAST_SEGMENT << 4;
        assert_eq!(desc_type(&desc, 0).unwrap(), SGL_TYPE_LAST_SEGMENT);
        // A set sub_type nibble must not leak into the type.
        desc[SGL_ENTRY_LEN - 1] = (SGL_TYPE_SEGMENT << 4) | 0x0F;
        assert_eq!(desc_type(&desc, 0).unwrap(), SGL_TYPE_SEGMENT);
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
