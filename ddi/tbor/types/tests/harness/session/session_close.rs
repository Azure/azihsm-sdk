// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helper for the TBOR `SessionClose` command.
//!
//! Thin wrapper around [`TborSessionCloseReq`] — closes the session
//! identified by `session_id` against `dev`. The FW response is an
//! empty ack ([`TborSessionCloseResp`]); callers only care whether
//! it succeeded.

use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_types::TborSessionCloseReq;
use azihsm_ddi_tbor_types::TborSessionCloseResp;

/// Issue `SessionClose(session_id)` against a specific `dev`.
///
/// Named with an `_on_dev` suffix to disambiguate from the
/// [`TestCtx::session_close`](crate::harness::TestCtx::session_close)
/// method which acts on the ctx's implicit fd.
pub fn session_close_on_dev(
    dev: &<AzihsmDdi as Ddi>::Dev,
    session_id: u16,
) -> Result<(), DdiError> {
    let req = TborSessionCloseReq { session_id };
    let mut cookie = None;
    let _resp: TborSessionCloseResp = dev.exec_op_tbor(&req, None, &mut cookie)?;
    Ok(())
}
