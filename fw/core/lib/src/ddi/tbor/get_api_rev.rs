// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `GetApiRev` command handler.
//!
//! `GetApiRev` is the bootstrap TBOR command: it advertises the range
//! of TBOR wire-protocol versions this firmware understands. The
//! wire schema lives in [`azihsm_fw_ddi_tbor_types::get_api_rev`] —
//! the request body is empty (the derive emits a synthetic `none`
//! placeholder TOC entry), and the response carries `(min, max)`.

use azihsm_fw_ddi_tbor::RequestView;
use azihsm_fw_ddi_tbor_types::TborGetApiRevReq;
use azihsm_fw_ddi_tbor_types::TborGetApiRevResp;

use super::*;

/// Lowest TBOR wire-protocol version this firmware speaks.
pub(crate) const MIN_PROTOCOL_VERSION: u8 = 1;

/// Highest TBOR wire-protocol version this firmware speaks.
pub(crate) const MAX_PROTOCOL_VERSION: u8 = 1;

/// Handle a TBOR `GetApiRev` request.
///
/// Decodes the request through the shared schema (which enforces:
/// header parses, opcode matches, body is empty), then encodes the
/// `(MIN_PROTOCOL_VERSION, MAX_PROTOCOL_VERSION)` response.
pub(crate) fn handle(view: &RequestView<'_>, out: &mut [u8]) -> HsmResult<usize> {
    let _ = TborGetApiRevReq::decode(view.as_bytes())?;

    let frame = TborGetApiRevResp::encode(out, 0, false)?
        .min_protocol_version(MIN_PROTOCOL_VERSION)?
        .max_protocol_version(MAX_PROTOCOL_VERSION)?
        .finish();
    Ok(frame.as_bytes().len())
}
