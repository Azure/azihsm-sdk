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
    async fn copy_mem(&self, _io: &impl HsmIo, src: &DmaBuf, dst: &mut DmaBuf) -> HsmResult<()> {
        self.gdma.copy_mem(src, dst);
        Ok(())
    }

    /// Zero an HSM-local buffer (software volatile wipe on the std
    /// platform). [`DmaBuf::zeroize`] guarantees the writes are not
    /// optimized away so key material is actually scrubbed.
    async fn zeroize_mem(&self, _io: &impl HsmIo, dst: &mut DmaBuf) -> HsmResult<()> {
        dst.zeroize();
        Ok(())
    }

    /// Copy from host memory into an HSM buffer.
    ///
    /// Interprets the PRP address as a raw host pointer.
    async fn copy_mem_from_host(
        &self,
        _io: &impl HsmIo,
        src: HsmDmaAddr,
        dst: &mut DmaBuf,
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
        _io: &impl HsmIo,
        src: &DmaBuf,
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
