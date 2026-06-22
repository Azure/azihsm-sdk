// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmSessionManager`] stub for the Uno PAL.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmSessionManager;
use azihsm_fw_hsm_pal_traits::HsmSessionState;
use azihsm_fw_hsm_pal_traits::SessionRole;

use crate::UnoHsmPal;

impl HsmSessionManager for UnoHsmPal {
    fn session_limit_reached(&self, _io: &impl HsmIo) -> bool {
        true
    }

    fn session_create(
        &self,
        _io: &impl HsmIo,
        _api_rev: &[u8],
        _masking_key: &[u8],
        _id: Option<HsmSessId>,
    ) -> HsmResult<HsmSessId> {
        Err(HsmError::UnsupportedCmd)
    }

    fn session_destroy(&self, _io: &impl HsmIo, _id: HsmSessId) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    fn session_state(&self, _io: &impl HsmIo, _id: HsmSessId) -> HsmSessionState {
        HsmSessionState::Invalid
    }

    fn session_create_pending(
        &self,
        _io: &impl HsmIo,
        _role: SessionRole,
        _handshake_state: &[u8],
    ) -> HsmResult<HsmSessId> {
        Err(HsmError::UnsupportedCmd)
    }

    fn session_pending_state(
        &self,
        _io: &impl HsmIo,
        _id: HsmSessId,
        _out: Option<&mut [u8]>,
    ) -> HsmResult<usize> {
        Err(HsmError::UnsupportedCmd)
    }

    fn session_promote(
        &self,
        _io: &impl HsmIo,
        _id: HsmSessId,
        _api_rev: &[u8],
        _param_key: &[u8],
        _masking_key: &[u8],
        _mac_tx_key: Option<&[u8]>,
        _mac_rx_key: Option<&[u8]>,
    ) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }

    fn session_param_key(&self, _io: &impl HsmIo, _id: HsmSessId) -> HsmResult<&DmaBuf> {
        Err(HsmError::UnsupportedCmd)
    }

    fn session_try_consume_psk_change(&self, _io: &impl HsmIo, _id: HsmSessId) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }
}
