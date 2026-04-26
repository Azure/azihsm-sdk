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
