// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helpers for the TBOR `ApiRev` command.

use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_types::TborApiRevReq;
use azihsm_ddi_tbor_types::TborApiRevResp;

/// Issue a TBOR `ApiRev` request against `dev` and return the
/// decoded response, or a [`DdiError`].
///
/// Backends that have not been wired to emit `OP_TBOR` SQEs will
/// return [`DdiError::UnsupportedEncoding`] (the default trait method).
pub fn helper_api_rev_tbor(dev: &<AzihsmDdi as Ddi>::Dev) -> Result<TborApiRevResp, DdiError> {
    let req = TborApiRevReq::new();
    let mut cookie = None;
    dev.exec_op_tbor(&req, &mut cookie)
}
