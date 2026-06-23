// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmCertStore`] stub for the Uno PAL.
//!
//! Certificate storage is not yet implemented on this platform. Every
//! method returns [`HsmError::UnsupportedCmd`] so the HSM core can
//! report the unsupported state to callers without panicking.

#![allow(clippy::unused_async)]

use azihsm_fw_hsm_pal_traits::CertChainInfo;
use azihsm_fw_hsm_pal_traits::HsmCertStore;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPartId;
use azihsm_fw_hsm_pal_traits::HsmResult;

use crate::UnoHsmPal;

impl HsmCertStore for UnoHsmPal {
    /// Not implemented.
    ///
    /// # Parameters
    /// * `_io` — operation-scoped I/O context (ignored).
    /// * `_part_id` — partition whose chain is queried (ignored).
    /// * `_slot_id` — chain slot identifier (ignored).
    ///
    /// # Returns
    /// * Always `Err(HsmError::UnsupportedCmd)`.
    async fn get_cert_chain_info(
        &self,
        _io: &impl HsmIo,
        _part_id: HsmPartId,
        _slot_id: u8,
    ) -> HsmResult<CertChainInfo> {
        Err(HsmError::UnsupportedCmd)
    }

    /// Not implemented.
    ///
    /// # Parameters
    /// * `_io` — operation-scoped I/O context (ignored).
    /// * `_part_id` — partition whose chain is queried (ignored).
    /// * `_slot_id` — chain slot identifier (ignored).
    /// * `_idx` — certificate index within the chain (ignored).
    /// * `_cert` — destination buffer; `None` would normally request the
    ///   required size (ignored).
    ///
    /// # Returns
    /// * Always `Err(HsmError::UnsupportedCmd)`.
    async fn get_cert(
        &self,
        _io: &impl HsmIo,
        _part_id: HsmPartId,
        _slot_id: u8,
        _idx: u8,
        _cert: Option<&mut [u8]>,
    ) -> HsmResult<usize> {
        Err(HsmError::UnsupportedCmd)
    }
}
