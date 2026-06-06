// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helper for the TBOR `CloseSession` command.
//!
//! Thin wrapper around [`TborCloseSessionReq`] — closes the session
//! identified by `session_id` against `dev`. The FW response is an
//! empty ack ([`TborCloseSessionResp`]); callers only care whether
//! it succeeded.

use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_types::TborCloseSessionReq;
use azihsm_ddi_tbor_types::TborCloseSessionResp;

/// Issue `CloseSession(session_id)` and return on success.
pub fn close_session(dev: &<AzihsmDdi as Ddi>::Dev, session_id: u16) -> Result<(), DdiError> {
    let req = TborCloseSessionReq { session_id };
    let mut cookie = None;
    let _resp: TborCloseSessionResp = dev.exec_op_tbor(&req, &mut cookie)?;
    Ok(())
}
