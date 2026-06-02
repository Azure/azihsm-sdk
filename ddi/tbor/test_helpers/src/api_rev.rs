// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helpers for the TBOR `GetApiRev` command.

use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_types::TborGetApiRevReq;
use azihsm_ddi_tbor_types::TborGetApiRevResp;

/// Issue a TBOR `GetApiRev` request against `dev` and return the
/// decoded response, or a [`DdiError`].
///
/// Backends that have not been wired to emit `OP_TBOR` SQEs will
/// return [`DdiError::UnsupportedEncoding`] (the default trait method).
pub fn helper_get_api_rev_tbor(
    dev: &<AzihsmDdi as Ddi>::Dev,
) -> Result<TborGetApiRevResp, DdiError> {
    let req = TborGetApiRevReq::new();
    let mut cookie = None;
    dev.exec_op_tbor(&req, &mut cookie)
}
