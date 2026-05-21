// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Internal helpers shared across HPKE submodules.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;

/// Allocate a DMA-accessible buffer and copy `src` into it.
///
/// Many HPKE callers pass plain `&[u8]` slices that originate from
/// the host wire (or from non-DMA stack buffers); the underlying
/// crypto traits now require `&DmaBuf` for any data touched by the
/// hardware engines. This helper centralizes the copy.
#[inline]
pub(crate) fn dma_copy_in<'a>(
    alloc: &'a impl HsmScopedAlloc,
    src: &[u8],
) -> HsmResult<&'a mut DmaBuf> {
    let buf = alloc.dma_alloc(src.len())?;
    buf.copy_from_slice(src);
    Ok(buf)
}
