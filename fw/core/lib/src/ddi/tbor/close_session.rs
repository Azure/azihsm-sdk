// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `CloseSession` handler.
//!
//! Destroys the requested slot via
//! [`HsmSessionManager::session_destroy`](azihsm_fw_hsm_pal_traits::HsmSessionManager::session_destroy).
//! Authentication of the request is provided by the outer AEAD
//! framing layer once it is wired up — handlers do not currently
//! validate caller authority because the framing layer is not yet
//! implemented.

use azihsm_fw_ddi_tbor::RequestView;
use azihsm_fw_ddi_tbor_types::TborCloseSessionReq;
use azihsm_fw_ddi_tbor_types::TborCloseSessionResp;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSessId;

/// Handle a TBOR `CloseSession` request.
///
/// Routes through `pal.session_destroy` to free the slot and any
/// associated vault state.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    view: &RequestView<'_>,
) -> HsmResult<&'p DmaBuf> {
    let req = TborCloseSessionReq::decode(view.as_bytes())?;
    let session_id: u16 = req.session_id().into();
    let id = HsmSessId::from(session_id);
    pal.session_destroy(io, id)?;
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborCloseSessionResp::encode(buf, 0, false)?.finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
