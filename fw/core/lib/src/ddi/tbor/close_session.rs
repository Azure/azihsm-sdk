// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `CloseSession` handler.
//!
//! Destroys the requested slot via
//! [`HsmSessionManager::session_destroy`](azihsm_fw_hsm_pal_traits::HsmSessionManager::session_destroy).
//!
//! # Trust boundary — outer-framing requirement
//!
//! `CloseSession` is a destructive operation: a caller that can
//! submit a TBOR request with a guessed `session_id` can tear down
//! any Active or Pending slot owned by the same partition.  The
//! request body therefore **must** be wrapped in the outer
//! AEAD-authenticated framing layer (per the TBOR session-protocol
//! spec) so that the dispatcher rejects unauthenticated `CloseSession`
//! requests before they reach this handler.
//!
//! That outer framing is not yet enforced in the dispatcher (the
//! framing layer is the next planned milestone for the TBOR session
//! work).  Until then, callers of this handler are limited to the
//! same-partition trust domain as established by the SQE
//! `session_id` flag; cross-partition isolation is provided by the
//! per-partition session table, but same-partition DoS via guessed
//! slot ids is possible.  **Do not enable TBOR sessions in a
//! security-sensitive deployment until the outer framing layer is
//! in place** — track the gating issue in the PR description for
//! #425.

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
    req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborCloseSessionReq::decode(req_buf)?;
    let session_id: u16 = req.session_id().into();
    let id = HsmSessId::from(session_id);
    // SECURITY: This is a destructive operation gated only by
    // possession of a valid `session_id` in the same partition.  See
    // the module-level "Trust boundary" note: callers MUST wrap the
    // request in the outer AEAD-authenticated framing layer once it
    // lands; until then this is vulnerable to same-partition DoS by
    // a caller who guesses an active slot id.
    pal.session_destroy(io, id)?;
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborCloseSessionResp::encode(buf, 0, false)?.finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
