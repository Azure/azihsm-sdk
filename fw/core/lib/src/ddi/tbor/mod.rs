// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR DDI command dispatch.
//!
//! TBOR commands are addressed by a single `u8` opcode carried in the
//! TBOR request header. Each handler decodes its typed request via
//! [`azihsm_fw_ddi_tbor::TborRequest::decode`] (or the generated
//! `XxxReq::decode` shortcut) and encodes its response via the matching
//! `XxxResp::encode` typestate builder.
//!
//! Handlers receive the parsed [`RequestView`] so the dispatcher can
//! avoid re-parsing the header, plus a destination buffer for the
//! encoded response.

pub(crate) mod get_api_rev;

use azihsm_fw_ddi_tbor::RequestView;
use azihsm_fw_ddi_tbor::ResponseEncoder;
use azihsm_fw_ddi_tbor::PROTOCOL_VERSION;

use super::*;

/// TBOR opcodes recognised by the firmware dispatcher.
///
/// The wire opcode is a single byte. Constants kept here (rather than in
/// the host-side `azihsm_ddi_tbor_types` crate) so that firmware can be
/// built `no_std` without host-side feature flags.
pub(crate) mod opcode {
    /// `GetApiRev` — bootstrap TBOR command. Reports the firmware's
    /// supported TBOR wire-protocol version range.
    pub(crate) const GET_API_REV: u8 = 0x01;
}

/// Dispatch a parsed TBOR request to its handler.
///
/// On success returns the number of bytes written to `out`. On
/// post-decode failure encodes a TBOR error response (header + single
/// `none` placeholder TOC entry with `status != 0`) into `out` and
/// returns its length.
pub(crate) fn dispatch(opcode: u8, view: &RequestView<'_>, out: &mut [u8]) -> HsmResult<usize> {
    match opcode {
        opcode::GET_API_REV => get_api_rev::handle(view, out),
        _ => encode_tbor_err(opcode, HsmError::UnsupportedCmd, out),
    }
}

/// Encode a TBOR error response: header with `status = err.0` and a
/// single `none` placeholder TOC entry (the wire format requires
/// `toc_count >= 1`).
///
/// `opcode` is included only in trace context — TBOR responses do not
/// carry the opcode (it's implicit from the request/response pairing).
pub(crate) fn encode_tbor_err(_opcode: u8, err: HsmError, out: &mut [u8]) -> HsmResult<usize> {
    let bytes = ResponseEncoder::new(out, PROTOCOL_VERSION, err.0, false)
        .none()?
        .finish()?;
    Ok(bytes.len())
}
