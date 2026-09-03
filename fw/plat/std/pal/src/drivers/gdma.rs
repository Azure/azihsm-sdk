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
        let len = u32::from_le_bytes([desc[8], desc[9], desc[10], desc[11]]) as usize;
        // A zero-length transfer is a no-op; skip so a (permitted) null
        // source address on an empty descriptor is never dereferenced.
        if len == 0 {
            return;
        }
        let src = HsmDmaAddr {
            lo: u32::from_le_bytes([desc[0], desc[1], desc[2], desc[3]]),
            hi: u32::from_le_bytes([desc[4], desc[5], desc[6], desc[7]]),
        };
        core::ptr::copy_nonoverlapping(addr_to_ptr(src), dst.as_mut_ptr(), len);
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
    if len != dst_len {
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
