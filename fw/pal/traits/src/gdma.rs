// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

/// A 64-bit DMA address split into high and low 32-bit halves.
#[derive(Debug, Clone, Copy, Default)]
pub struct HsmDmaAddr {
    /// Lower 32 bits of the address.
    pub lo: u32,

    /// Upper 32 bits of the address.
    pub hi: u32,
}

impl HsmDmaAddr {
    /// Returns `true` if both halves are zero (null address).
    #[inline]
    pub fn is_null(&self) -> bool {
        self.lo == 0 && self.hi == 0
    }
}

/// Trait for performing DMA memory copy operations via the GDMA controller.
pub trait HsmGdmaController {
    /// Copies data from `src` to `dst` within HSM-local memory.
    async fn copy_mem(&self, src: &[u8], dst: &mut [u8]) -> HsmResult<()>;

    /// Copies data from the host at `src` into the HSM-local buffer `dst`.
    ///
    /// * `part_id` — Identifier of the host controller interface.
    /// * `src` — Host-side source DMA address.
    /// * `dst` — HSM-local destination buffer.
    /// * `prp` — If `true`, interpret `src` as a PRP address pair;
    ///   if `false`, interpret it as an SGL descriptor pair.
    async fn copy_mem_from_host(
        &self,
        part_id: HsmPartId,
        src: HsmDmaAddr,
        dst: &mut [u8],
        prp: bool,
    ) -> HsmResult<()>;

    /// Copies data from the HSM-local buffer `src` to the host at `dst`.
    ///
    /// * `part_id` — Partition identifier.
    /// * `src` — HSM-local source buffer.
    /// * `dst` — Host-side destination DMA address.
    /// * `prp` — If `true`, interpret `dst` as a PRP address pair;
    ///   if `false`, interpret it as an SGL descriptor pair.
    async fn copy_mem_to_host(
        &self,
        part_id: HsmPartId,
        src: &[u8],
        dst: HsmDmaAddr,
        prp: bool,
    ) -> HsmResult<()>;
}
