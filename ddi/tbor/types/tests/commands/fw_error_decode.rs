// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Unit tests for the FW-error surfacing path added by the host
//! `#[tbor]` derive: when the wire response header carries a non-zero
//! `status` (a `TborStatus` discriminant emitted by the FW dispatcher
//! via `encode_tbor_err`), `decode_response` must short-circuit with
//! [`codec::DecodeError::FwError`] *before* attempting schema decode.
//!
//! Two shapes are covered:
//!   * Empty-response (`TborSessionCloseResp`): without the gate, an
//!     error envelope would silently decode to `Ok(Self)` because the
//!     placeholder `None` TOC entry matches the empty schema.
//!   * Fields-response (`TborApiRevResp`): without the gate, the
//!     schema decoder would fail with a generic `UnexpectedTocType`
//!     and lose the FW status code.
//!
//! These tests touch only the codec and the derive-generated decoder;
//! they require no backend feature.

use azihsm_ddi_tbor_types::codec::DecodeError;
use azihsm_ddi_tbor_types::codec::ResponseEncoder;
use azihsm_ddi_tbor_types::codec::PROTOCOL_VERSION;
use azihsm_ddi_tbor_types::TborApiRevResp;
use azihsm_ddi_tbor_types::TborResp;
use azihsm_ddi_tbor_types::TborSessionCloseResp;

/// Build an FW error envelope: header with the given status and a
/// single placeholder `None` TOC entry (the wire format requires
/// `toc_count >= 1`). Mirrors `fw::ddi::tbor::encode_tbor_err`.
fn encode_err_envelope(status: u32, out: &mut [u8]) -> usize {
    let bytes = ResponseEncoder::new(out, PROTOCOL_VERSION, status, false)
        .none()
        .expect("encode none placeholder")
        .finish()
        .expect("finish error envelope");
    bytes.len()
}

const AEAD_ENVELOPE_AUTH_FAILED: u32 = 0x0870_00DD;
const SESSION_NOT_FOUND: u32 = 0x0870_0004;

#[test]
fn empty_response_surfaces_fw_status() {
    let mut buf = [0u8; 64];
    let len = encode_err_envelope(AEAD_ENVELOPE_AUTH_FAILED, &mut buf);

    let err = TborSessionCloseResp::decode_response(&buf[..len])
        .expect_err("non-zero status must not decode to Ok on empty-response types");
    assert_eq!(
        err,
        DecodeError::FwError(AEAD_ENVELOPE_AUTH_FAILED),
        "expected FwError surfacing the TborStatus discriminant",
    );
}

#[test]
fn fields_response_surfaces_fw_status_before_schema_decode() {
    let mut buf = [0u8; 64];
    let len = encode_err_envelope(SESSION_NOT_FOUND, &mut buf);

    let err = TborApiRevResp::decode_response(&buf[..len])
        .expect_err("non-zero status must short-circuit schema decode");
    assert_eq!(
        err,
        DecodeError::FwError(SESSION_NOT_FOUND),
        "expected FwError, not a generic UnexpectedTocType from missing fields",
    );
}

#[test]
fn zero_status_with_valid_body_still_decodes() {
    // Sanity: the new status gate must not regress the happy path. An
    // empty-body response with status=0 still decodes to Ok(()).
    let mut buf = [0u8; 64];
    let len = encode_err_envelope(0, &mut buf);

    TborSessionCloseResp::decode_response(&buf[..len])
        .expect("status=0 envelope must decode to Ok on empty response");
}
