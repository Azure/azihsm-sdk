// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Uno GDMA controller implementation.
//!
//! Bridges the platform-agnostic [`HsmGdmaController`] trait to the
//! low-level [`GdmaDriver`](azihsm_fw_uno_drivers_gdma::GdmaDriver)
//! by converting buffer addresses and [`HsmDmaAddr`] values into
//! [`DriverDmaBuf`] and [`MemInterface`] parameters.
//!
//! # Address model
//!
//! The Uno HSM is a Cortex-M core with a 32-bit address space, so
//! device-local pointers always fit in a single [`DmaAddr`] with
//! `hi = 0`. Host-side addresses arrive as [`HsmDmaAddr`] (a full
//! 64-bit address split into `hi`/`lo` halves) and are wrapped in a
//! [`DriverDmaBuf::Prp`] or [`DriverDmaBuf::Sgl`] depending on the caller's
//! `prp` flag.
//!
//! # Transfer direction helpers
//!
//! | Helper               | Source interface | Destination interface |
//! |----------------------|------------------|-----------------------|
//! | `copy_mem`           | Device           | Device                |
//! | `copy_mem_from_host` | Host             | Device                |
//! | `copy_mem_to_host`   | Device           | Host                  |

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmDmaAddr;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmGdmaController;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPartId;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_uno_drivers_gdma::GdmaAddr;
use azihsm_fw_uno_drivers_gdma::GdmaBuf;
use azihsm_fw_uno_drivers_gdma::MemInterface;

use crate::UnoHsmPal;

/// Converts an [`HsmDmaAddr`] (the trait-level 64-bit address) into a
/// [`GdmaBuf`] suitable for a host-side DMA operand.
///
/// The `prp` flag selects the descriptor format written to the GDMA
/// submission queue:
///
/// - `true`  → [`GdmaBuf::Prp`] — Physical Region Page descriptor pair.
///   `prp0` holds the address; `prp1` is zeroed (single-page transfer).
/// - `false` → [`GdmaBuf::Sgl`] — Scatter-Gather List descriptor pair.
///   `sgl0` holds the address; `sgl1` is zeroed (inline data block).
#[inline(always)]
fn host_dma_buf(addr: HsmDmaAddr, prp: bool) -> GdmaBuf {
    let addr = GdmaAddr {
        lo: addr.lo,
        hi: addr.hi,
    };
    if prp {
        GdmaBuf::Prp {
            prp0: addr,
            prp1: GdmaAddr::ZERO,
        }
    } else {
        GdmaBuf::Sgl {
            sgl0: addr,
            sgl1: GdmaAddr::ZERO,
        }
    }
}

/// Converts a device-local (DTCM / SRAM) raw pointer and length into
/// an SGL [`GdmaBuf`].
///
/// SGL Data Block descriptor: `sgl0` = address, `sgl1.lo` = length,
/// `sgl1.hi[31:24]` = type/subtype (0x00 = inline data block).
/// No 4K page-crossing restriction unlike PRP.
#[inline(always)]
fn device_dma_buf(ptr: *const u8, len: u32) -> GdmaBuf {
    GdmaBuf::Sgl {
        sgl0: GdmaAddr::from_u32(ptr as usize as u32),
        sgl1: GdmaAddr { lo: len, hi: 0 },
    }
}

/// Maps a partition ID to a GDMA host interface selector.
///
/// Controller ID = `part_id + 1` because GDMA `IFC_SLCT` uses 0 for
/// device memory, so host interfaces start at 1.
#[inline(always)]
fn host_interface(part_id: HsmPartId) -> HsmResult<MemInterface> {
    let ctrl_id = u8::from(part_id)
        .checked_add(1)
        .ok_or(HsmError::InvalidArg)?;
    Ok(MemInterface::Host { ctrl_id })
}

/// Uno platform implementation of [`HsmGdmaController`].
impl HsmGdmaController for UnoHsmPal {
    async fn copy_mem(&self, _io: &impl HsmIo, src: &DmaBuf, dst: &mut DmaBuf) -> HsmResult<()> {
        let src_addr = device_dma_buf(src.as_ptr(), src.len() as u32);
        let dst_addr = device_dma_buf(dst.as_mut_ptr(), dst.len() as u32);
        self.gdma
            .copy_mem(
                src_addr,
                MemInterface::Device,
                src.len() as u32,
                dst_addr,
                MemInterface::Device,
                dst.len() as u32,
            )?
            .await
    }

    /// Zero an HSM-local buffer.
    ///
    /// Software volatile wipe for now; a hardware GDMA memset will replace
    /// this on uno later (the async signature is kept so callers are
    /// unaffected). [`DmaBuf::zeroize`] guarantees the writes are not
    /// elided so key material is actually scrubbed.
    async fn zeroize_mem(&self, _io: &impl HsmIo, dst: &mut DmaBuf) -> HsmResult<()> {
        dst.zeroize();
        Ok(())
    }

    async fn copy_mem_from_host(
        &self,
        io: &impl HsmIo,
        src: HsmDmaAddr,
        dst: &mut DmaBuf,
        prp: bool,
    ) -> HsmResult<()> {
        let len = dst.len() as u32;
        let src_addr = host_dma_buf(src, prp);
        let dst_addr = device_dma_buf(dst.as_mut_ptr(), len);
        self.gdma
            .copy_mem(
                src_addr,
                host_interface(io.pid())?,
                len,
                dst_addr,
                MemInterface::Device,
                len,
            )?
            .await
    }

    async fn copy_mem_to_host(
        &self,
        io: &impl HsmIo,
        src: &DmaBuf,
        dst: HsmDmaAddr,
        prp: bool,
    ) -> HsmResult<()> {
        let len = src.len() as u32;
        let src_addr = device_dma_buf(src.as_ptr(), len);
        let dst_addr = host_dma_buf(dst, prp);
        self.gdma
            .copy_mem(
                src_addr,
                MemInterface::Device,
                len,
                dst_addr,
                host_interface(io.pid())?,
                len,
            )?
            .await
    }
}
