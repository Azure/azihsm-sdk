// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std GDMA driver — performs memory copy operations.
//!
//! For device-local copies, performs plain `memcpy`. For host DMA,
//! interprets the [`HsmDmaAddr`] PRP as a raw host pointer and copies
//! directly from/to that address.

use azihsm_fw_hsm_pal_traits::*;

/// Std GDMA driver — memory copy via raw pointers.
///
/// Device-local copies are plain `memcpy`. Host copies interpret
/// the PRP address as a raw pointer to caller-owned memory.
pub struct StdGdma;

impl StdGdma {
    /// Create a new GDMA driver.
    pub fn new() -> Self {
        Self
    }

    /// Copy data between device-local buffers.
    ///
    /// Copies `min(src.len(), dst.len())` bytes from `src` to `dst`.
    pub fn copy_mem(&self, src: &[u8], dst: &mut [u8]) {
        let len = src.len().min(dst.len());
        dst[..len].copy_from_slice(&src[..len]);
    }

    /// Copy from host memory into an HSM buffer.
    ///
    /// # Safety
    ///
    /// The caller must ensure the PRP address points to a valid,
    /// readable buffer of at least `dst.len()` bytes.
    pub unsafe fn copy_mem_from_host(&self, src: HsmDmaAddr, dst: &mut [u8]) {
        let ptr = addr_to_ptr(src);
        let len = dst.len();
        core::ptr::copy_nonoverlapping(ptr, dst.as_mut_ptr(), len);
    }

    /// Copy from host memory into an HSM buffer, sourced from a raw
    /// 16-byte NVMe SGL Data Block descriptor.
    ///
    /// Interprets the descriptor's first dword (`desc[0..8]`, LE) as the
    /// raw host pointer and its `length` field (`desc[8..12]`, LE) as the
    /// number of bytes to copy — the NVMe SGL Data Block semantics — into
    /// `dst`.
    ///
    /// # Safety
    ///
    /// The caller must ensure the descriptor address points to a valid,
    /// readable buffer of at least the descriptor's `length` bytes, and
    /// that `dst` is at least that long (the trait wrapper enforces
    /// `length == dst.len()`).
    pub unsafe fn copy_mem_from_host_raw(&self, desc: &[u8; 16], dst: &mut [u8]) {
        // Emulate what the GDMA does with an NVMe SGL descriptor.
        //
        // A Data Block names the payload directly. A Segment / Last
        // Segment instead names a run of descriptors, which the engine
        // walks, gathering each Data Block into successive offsets of
        // the destination; a Segment's final descriptor chains to the
        // next segment rather than describing data.
        //
        // Firmware deliberately does none of this — it hands the
        // descriptor to the engine and lets the hardware gather. The std
        // PAL stands in for that engine, so the behaviour has to live
        // here or the emulator would model something the silicon does
        // not do.
        const T_DATA_BLOCK: u8 = 0x0;
        const T_SEGMENT: u8 = 0x2;
        const T_LAST_SEGMENT: u8 = 0x3;
        /// Bound on chained segments, so a malformed page cannot spin.
        const MAX_SEGMENTS: usize = 16;

        unsafe fn desc_at(base: *const u8, i: usize) -> [u8; 16] {
            let mut d = [0u8; 16];
            core::ptr::copy_nonoverlapping(base.add(i * 16), d.as_mut_ptr(), 16);
            d
        }
        unsafe fn block_of(d: &[u8; 16]) -> (*const u8, usize) {
            let src = HsmDmaAddr {
                lo: u32::from_le_bytes([d[0], d[1], d[2], d[3]]),
                hi: u32::from_le_bytes([d[4], d[5], d[6], d[7]]),
            };
            let len = u32::from_le_bytes([d[8], d[9], d[10], d[11]]) as usize;
            (addr_to_ptr(src) as *const u8, len)
        }

        let mut cur = *desc;
        let mut written = 0usize;

        for _ in 0..MAX_SEGMENTS {
            let ty = cur[15] >> 4;
            // SAFETY: descriptor addresses are raw host-process pointers
            // the caller guarantees valid; see the method's contract.
            let (ptr, len) = unsafe { block_of(&cur) };
            if len == 0 {
                return;
            }

            if ty == T_DATA_BLOCK {
                if written + len > dst.len() {
                    return;
                }
                // SAFETY: as above; bounds checked against `dst`.
                unsafe { core::ptr::copy_nonoverlapping(ptr, dst.as_mut_ptr().add(written), len) };
                return;
            }
            if ty != T_SEGMENT && ty != T_LAST_SEGMENT {
                return;
            }

            let count = len / 16;
            let data_count = if ty == T_LAST_SEGMENT {
                count
            } else {
                count.saturating_sub(1)
            };

            for i in 0..data_count {
                // SAFETY: the segment holds `count` descriptors.
                let d = unsafe { desc_at(ptr, i) };
                // SAFETY: as above.
                let (bptr, blen) = unsafe { block_of(&d) };
                if blen == 0 || written + blen > dst.len() {
                    return;
                }
                // SAFETY: as above; bounds checked against `dst`.
                unsafe {
                    core::ptr::copy_nonoverlapping(bptr, dst.as_mut_ptr().add(written), blen)
                };
                written += blen;
            }

            if ty == T_LAST_SEGMENT {
                return;
            }
            // SAFETY: the chain pointer is the segment's last descriptor.
            cur = unsafe { desc_at(ptr, count - 1) };
        }
    }

    /// Copy from an HSM buffer to host memory.
    ///
    /// # Safety
    ///
    /// The caller must ensure the PRP address points to a valid,
    /// writable buffer of at least `src.len()` bytes.
    pub unsafe fn copy_mem_to_host(&self, src: &[u8], dst: HsmDmaAddr) {
        let ptr = addr_to_ptr(dst);
        let len = src.len();
        core::ptr::copy_nonoverlapping(src.as_ptr(), ptr, len);
    }
}

/// Reassemble a 64-bit PRP address into a raw pointer.
#[inline]
fn addr_to_ptr(addr: HsmDmaAddr) -> *mut u8 {
    let full = (addr.hi as u64) << 32 | addr.lo as u64;
    full as *mut u8
}

/// Validate a raw 16-byte descriptor's length and source address for the
/// std PAL, which dereferences the source as a raw host-process pointer.
///
/// Unlike the uno PAL — where the GDMA hardware consumes the descriptor
/// and interprets its SGL format — the std PAL copies from the address
/// directly, so it must reject a source it cannot safely dereference.
/// Only the embedded length and the source address are checked; the
/// descriptor *format* (SGL type / sub-type, of which there are several
/// valid encodings) is deliberately not interpreted here.
///
/// # Errors
///
/// - [`HsmError::InvalidArg`] — the embedded length does not equal
///   `dst_len`, or a non-empty (`len > 0`) transfer names a null source
///   address.
pub(crate) fn validate_raw_src(desc: &[u8; 16], dst_len: usize) -> HsmResult<()> {
    let len = u32::from_le_bytes([desc[8], desc[9], desc[10], desc[11]]) as usize;
    // Only a Data Block's length describes the payload, so only it can be
    // checked against the destination. A Segment / Last Segment length
    // counts descriptor bytes; the payload size is whatever the walk
    // gathers, which the copy bounds against `dst` as it goes.
    if desc[15] >> 4 == 0 && len != dst_len {
        return Err(HsmError::InvalidArg);
    }
    // A non-empty transfer must name a non-null source address (bytes 0-7).
    if len != 0 && desc[..8].iter().all(|&b| b == 0) {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 16-byte NVMe SGL Data Block descriptor pointing at `src`.
    fn sgl_desc(src: &[u8]) -> [u8; 16] {
        let addr = src.as_ptr() as usize as u64;
        let mut d = [0u8; 16];
        d[..8].copy_from_slice(&addr.to_le_bytes());
        d[8..12].copy_from_slice(&(src.len() as u32).to_le_bytes());
        d
    }

    #[test]
    fn raw_copies_descriptor_length_from_descriptor_address() {
        let src = [0xA5u8; 40];
        let desc = sgl_desc(&src);
        let mut dst = [0u8; 40];
        // SAFETY: `desc` addresses the live `src` stack buffer, exactly
        // `src.len()` bytes; `dst` is at least that long.
        unsafe { StdGdma::new().copy_mem_from_host_raw(&desc, &mut dst) };
        assert_eq!(dst, src);
    }

    #[test]
    fn raw_honors_shorter_embedded_length_not_dst() {
        // Descriptor advertises only 8 bytes; the driver must copy 8
        // (the descriptor's length), not the full 32-byte dst.
        let src = [0x5Au8; 8];
        let desc = sgl_desc(&src);
        let mut dst = [0u8; 32];
        // SAFETY: descriptor length (8) ≤ dst.len(); address is `src`.
        unsafe { StdGdma::new().copy_mem_from_host_raw(&desc, &mut dst) };
        assert!(dst[..8].iter().all(|&b| b == 0x5A));
        assert!(dst[8..].iter().all(|&b| b == 0x00));
    }

    #[test]
    fn validate_raw_src_checks_length_and_null_source() {
        use azihsm_fw_hsm_pal_traits::HsmError;

        // A descriptor whose embedded length matches `dst_len` and names a
        // non-null source is accepted.  (Descriptor *format* bytes are not
        // interpreted, so any type/reserved bytes are irrelevant.)
        let src = [0u8; 16];
        let desc = sgl_desc(&src);
        assert!(validate_raw_src(&desc, 16).is_ok());

        // A length that does not match the destination is rejected.
        assert!(matches!(
            validate_raw_src(&desc, 8),
            Err(HsmError::InvalidArg)
        ));

        // A null source address with a non-empty length is rejected.
        let mut null_src = [0u8; 16];
        null_src[8..12].copy_from_slice(&16u32.to_le_bytes());
        assert!(matches!(
            validate_raw_src(&null_src, 16),
            Err(HsmError::InvalidArg)
        ));

        // A null source address with length 0 is a permitted empty item.
        assert!(validate_raw_src(&[0u8; 16], 0).is_ok());
    }
}
