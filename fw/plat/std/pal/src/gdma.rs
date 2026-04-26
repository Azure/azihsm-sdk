// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmGdmaController`] implementation for the std PAL.
//!
//! Delegates to [`StdGdma`](crate::drivers::gdma::StdGdma) for all
//! GDMA operations.

use azihsm_fw_hsm_pal_traits::*;

use crate::StdHsmPal;

impl HsmGdmaController for StdHsmPal {
    /// Copy data between HSM-local buffers.
    async fn copy_mem(&self, src: &[u8], dst: &mut [u8]) -> HsmResult<()> {
        self.gdma.copy_mem(src, dst);
        Ok(())
    }

    /// Copy from host memory into an HSM buffer.
    ///
    /// Interprets the PRP address as a raw host pointer.
    async fn copy_mem_from_host(
        &self,
        _part_id: u8,
        src: HsmDmaAddr,
        dst: &mut [u8],
        _prp: bool,
    ) -> HsmResult<()> {
        // SAFETY: In the std platform, PRP addresses are raw host-process
        // pointers set up by the caller (test harness or integration test).
        // The caller is responsible for ensuring the address is valid and
        // the buffer remains alive for the duration of the copy.
        unsafe { self.gdma.copy_mem_from_host(src, dst) };
        Ok(())
    }

    /// Copy from an HSM buffer to host memory.
    ///
    /// Interprets the PRP address as a raw host pointer.
    async fn copy_mem_to_host(
        &self,
        _part_id: u8,
        src: &[u8],
        dst: HsmDmaAddr,
        _prp: bool,
    ) -> HsmResult<()> {
        // SAFETY: In the std platform, PRP addresses are raw host-process
        // pointers set up by the caller (test harness or integration test).
        // The caller is responsible for ensuring the address is valid and
        // the buffer remains alive for the duration of the copy.
        unsafe { self.gdma.copy_mem_to_host(src, dst) };
        Ok(())
    }
}
