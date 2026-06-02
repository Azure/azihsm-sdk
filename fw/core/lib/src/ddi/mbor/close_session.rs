// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI CloseSession command handler.
//!
//! Tears down the session identified by `hdr.sess_id`: deletes any
//! session-scoped vault keys, removes the session masking blob, and
//! frees the session table slot.

use azihsm_fw_ddi_mbor_types::close_session::DdiCloseSessionReq;
use azihsm_fw_ddi_mbor_types::close_session::DdiCloseSessionResp;

use super::*;

/// Handle `DdiCloseSessionCmd`.
///
/// `hdr.sess_id` MUST be `Some` — the `SessionCtrl::Close` classification
/// in [`super::super::op::SessionCtrl`] guarantees this; the dispatcher
/// validates it before calling the handler.  We re-check defensively so
/// the partition state never sees `session_destroy` with a `None` id.
///
/// No `partition_lock` is needed: the only state mutation is the single
/// synchronous [`HsmSessionManager::session_destroy`] call, which is
/// atomic on the partition entry (no yield points), so there is no
/// read-then-mutate window that could race against a concurrent
/// handler on the same partition.
pub(crate) fn close_session<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let _body: DdiCloseSessionReq = decoder.decode_data()?;

    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    pal.session_destroy(io, HsmSessId::from(sess_id))?;

    // Echo the closed session id back in the response header so the
    // host can confirm which session was torn down.
    let resp = pal.dma_alloc_var(io, |buf| {
        super::encode_resp(
            &super::success_hdr_sess(hdr, DdiOp::CloseSession, sess_id),
            &DdiCloseSessionResp {},
            buf,
        )
    })?;
    Ok(resp)
}
