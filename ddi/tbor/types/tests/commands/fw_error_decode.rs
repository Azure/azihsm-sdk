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

/// Builds a response envelope with the given status containing one placeholder `None` TOC entry.
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

/// Verifies that an empty response type surfaces its FW status.
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

/// Verifies that a fields response surfaces FW status before schema decoding.
#[test]
fn fields_response_surfaces_fw_status_before_schema_decode() {
    let mut buf = [0u8; 64];
    let len = encode_err_envelope(SESSION_NOT_FOUND, &mut buf);

    let err = TborApiRevResp::decode_response(&buf[..len])
        .expect_err("non-zero status must short-circuit schema decode");

    assert_eq!(
        err,
        DecodeError::FwError(SESSION_NOT_FOUND),
        "expected FwError, not a generic schema error from missing fields",
    );
}

/// Verifies that status zero still permits a valid empty response to decode.
#[test]
fn zero_status_with_valid_body_still_decodes() {
    let mut buf = [0u8; 64];
    let len = encode_err_envelope(0, &mut buf);

    TborSessionCloseResp::decode_response(&buf[..len])
        .expect("status=0 envelope must decode to Ok on empty response");
}

/// Verifies that several representative FW status values are preserved exactly.
#[test]
fn empty_response_preserves_representative_fw_status_values() {
    let statuses = [
        1,
        SESSION_NOT_FOUND,
        AEAD_ENVELOPE_AUTH_FAILED,
        0x0000_FFFF,
        0xFFFF_0000,
        u32::MAX,
    ];

    for status in statuses {
        let mut buf = [0u8; 64];
        let len = encode_err_envelope(status, &mut buf);

        let err = TborSessionCloseResp::decode_response(&buf[..len])
            .expect_err("every non-zero status must produce FwError");

        assert_eq!(
            err,
            DecodeError::FwError(status),
            "FW status {status:#010X} was not preserved exactly",
        );
    }
}

/// Verifies that fields responses preserve representative FW status values.
#[test]
fn fields_response_preserves_representative_fw_status_values() {
    let statuses = [
        1,
        SESSION_NOT_FOUND,
        AEAD_ENVELOPE_AUTH_FAILED,
        0x7FFF_FFFF,
        0x8000_0000,
        u32::MAX,
    ];

    for status in statuses {
        let mut buf = [0u8; 64];
        let len = encode_err_envelope(status, &mut buf);

        let err = TborApiRevResp::decode_response(&buf[..len])
            .expect_err("every non-zero status must short-circuit schema decode");

        assert_eq!(
            err,
            DecodeError::FwError(status),
            "FW status {status:#010X} was not preserved exactly",
        );
    }
}

/// Verifies that the smallest non-zero status is treated as an FW error.
#[test]
fn minimum_nonzero_status_surfaces_as_fw_error() {
    let mut buf = [0u8; 64];
    let len = encode_err_envelope(1, &mut buf);

    let err = TborSessionCloseResp::decode_response(&buf[..len])
        .expect_err("status=1 must be treated as non-zero");

    assert_eq!(err, DecodeError::FwError(1));
}

/// Verifies that the largest possible status is preserved without truncation.
#[test]
fn maximum_status_surfaces_without_truncation() {
    let mut buf = [0u8; 64];
    let len = encode_err_envelope(u32::MAX, &mut buf);

    let err = TborApiRevResp::decode_response(&buf[..len])
        .expect_err("u32::MAX must be surfaced as an FW error");

    assert_eq!(err, DecodeError::FwError(u32::MAX));
}

/// Verifies that the same encoded FW response can be decoded consistently.
#[test]
fn fw_error_decode_is_repeatable() {
    let mut buf = [0u8; 64];
    let len = encode_err_envelope(AEAD_ENVELOPE_AUTH_FAILED, &mut buf);
    let response = &buf[..len];

    for attempt in 0..3 {
        let err = TborSessionCloseResp::decode_response(response)
            .expect_err("non-zero status must produce FwError on every decode");

        assert_eq!(
            err,
            DecodeError::FwError(AEAD_ENVELOPE_AUTH_FAILED),
            "decode attempt {attempt} returned an unexpected error",
        );
    }
}

/// Verifies that FW error decoding does not modify the encoded response bytes.
#[test]
fn fw_error_decode_does_not_modify_input() {
    let mut buf = [0u8; 64];
    let len = encode_err_envelope(SESSION_NOT_FOUND, &mut buf);
    let original = buf[..len].to_vec();

    let err = TborApiRevResp::decode_response(&buf[..len])
        .expect_err("non-zero status must produce FwError");

    assert_eq!(err, DecodeError::FwError(SESSION_NOT_FOUND));
    assert_eq!(
        &buf[..len],
        original.as_slice(),
        "decode_response must not modify its input",
    );
}

/// Verifies that status zero does not incorrectly produce an FW error.
#[test]
fn zero_status_fields_response_continues_to_schema_decode() {
    let mut buf = [0u8; 64];
    let len = encode_err_envelope(0, &mut buf);

    let err = TborApiRevResp::decode_response(&buf[..len])
        .expect_err("placeholder body does not satisfy the fields-response schema");

    assert!(
        !matches!(err, DecodeError::FwError(_)),
        "status=0 must continue to schema decoding, but returned {err:?}",
    );
}

/// Verifies that different response types surface the same encoded FW status.
#[test]
fn fw_status_is_consistent_across_response_shapes() {
    let mut buf = [0u8; 64];
    let len = encode_err_envelope(AEAD_ENVELOPE_AUTH_FAILED, &mut buf);
    let response = &buf[..len];

    let empty_err = TborSessionCloseResp::decode_response(response)
        .expect_err("empty response must surface FW status");
    let fields_err = TborApiRevResp::decode_response(response)
        .expect_err("fields response must surface FW status");

    assert_eq!(empty_err, DecodeError::FwError(AEAD_ENVELOPE_AUTH_FAILED),);
    assert_eq!(fields_err, DecodeError::FwError(AEAD_ENVELOPE_AUTH_FAILED),);
    assert_eq!(
        empty_err, fields_err,
        "FW status handling must not depend on the response schema",
    );
}

/// Verifies that FW status takes precedence over a schema shape mismatch.
#[test]
fn fw_status_precedes_invalid_schema_body() {
    let mut buf = [0u8; 64];

    // A `None` body is invalid for TborApiRevResp, but the FW status must
    // be returned before the generated decoder inspects that body.
    let len = encode_err_envelope(AEAD_ENVELOPE_AUTH_FAILED, &mut buf);

    let err = TborApiRevResp::decode_response(&buf[..len])
        .expect_err("non-zero status must take precedence over schema errors");

    assert_eq!(err, DecodeError::FwError(AEAD_ENVELOPE_AUTH_FAILED),);
}

/// Verifies that every non-zero bit position is recognized as an FW error.
#[test]
fn every_single_bit_status_surfaces_as_fw_error() {
    for bit in 0..u32::BITS {
        let status = 1u32 << bit;
        let mut buf = [0u8; 64];
        let len = encode_err_envelope(status, &mut buf);

        let err = TborSessionCloseResp::decode_response(&buf[..len])
            .expect_err("every non-zero status bit must produce FwError");

        assert_eq!(
            err,
            DecodeError::FwError(status),
            "status bit {bit} was not preserved",
        );
    }
}

/// Verifies that alternating-bit FW status values are preserved exactly.
#[test]
fn alternating_bit_status_values_are_preserved() {
    for status in [0xAAAA_AAAA, 0x5555_5555] {
        let mut buf = [0u8; 64];
        let len = encode_err_envelope(status, &mut buf);

        let err = TborApiRevResp::decode_response(&buf[..len])
            .expect_err("alternating-bit non-zero status must produce FwError");

        assert_eq!(err, DecodeError::FwError(status));
    }
}

/// Verifies that decoding does not modify bytes outside the response slice.
#[test]
fn fw_status_decode_does_not_modify_bytes_outside_response_slice() {
    let mut buf = [0xA5u8; 128];
    let len = encode_err_envelope(SESSION_NOT_FOUND, &mut buf);

    // Snapshot the tail after encoding so this test isolates decoder behavior
    // from any writes performed by ResponseEncoder.
    let tail_before_decode = buf[len..].to_vec();

    let err = TborSessionCloseResp::decode_response(&buf[..len])
        .expect_err("non-zero status must produce FwError");

    assert_eq!(err, DecodeError::FwError(SESSION_NOT_FOUND));

    assert_eq!(
        &buf[len..],
        tail_before_decode.as_slice(),
        "decode_response unexpectedly modified bytes outside the response slice",
    );
}

/// Verifies that adjacent FW status values are not confused or normalized.
#[test]
fn adjacent_fw_status_values_remain_distinct() {
    let first_status = SESSION_NOT_FOUND;
    let second_status = SESSION_NOT_FOUND + 1;

    let mut first_buf = [0u8; 64];
    let first_len = encode_err_envelope(first_status, &mut first_buf);

    let mut second_buf = [0u8; 64];
    let second_len = encode_err_envelope(second_status, &mut second_buf);

    let first_err = TborSessionCloseResp::decode_response(&first_buf[..first_len])
        .expect_err("first status must produce FwError");
    let second_err = TborSessionCloseResp::decode_response(&second_buf[..second_len])
        .expect_err("second status must produce FwError");

    assert_eq!(first_err, DecodeError::FwError(first_status));
    assert_eq!(second_err, DecodeError::FwError(second_status));
    assert_ne!(first_err, second_err);
}

/// Verifies that decoding one FW error does not affect a subsequent success.
#[test]
fn fw_error_does_not_poison_subsequent_successful_decode() {
    let mut error_buf = [0u8; 64];
    let error_len = encode_err_envelope(AEAD_ENVELOPE_AUTH_FAILED, &mut error_buf);

    let err = TborSessionCloseResp::decode_response(&error_buf[..error_len])
        .expect_err("non-zero status must produce FwError");

    assert_eq!(err, DecodeError::FwError(AEAD_ENVELOPE_AUTH_FAILED),);

    let mut success_buf = [0u8; 64];
    let success_len = encode_err_envelope(0, &mut success_buf);

    TborSessionCloseResp::decode_response(&success_buf[..success_len])
        .expect("a prior FW error must not affect a later successful decode");
}

/// Verifies that a successful decode does not affect a subsequent FW error.
#[test]
fn successful_decode_does_not_hide_subsequent_fw_error() {
    let mut success_buf = [0u8; 64];
    let success_len = encode_err_envelope(0, &mut success_buf);

    TborSessionCloseResp::decode_response(&success_buf[..success_len])
        .expect("status zero must decode successfully");

    let mut error_buf = [0u8; 64];
    let error_len = encode_err_envelope(SESSION_NOT_FOUND, &mut error_buf);

    let err = TborSessionCloseResp::decode_response(&error_buf[..error_len])
        .expect_err("a later non-zero status must still produce FwError");

    assert_eq!(err, DecodeError::FwError(SESSION_NOT_FOUND));
}

/// Verifies the zero/non-zero boundary on both response shapes.
#[test]
fn status_gate_boundary_is_consistent_across_response_shapes() {
    for status in [0, 1] {
        let mut buf = [0u8; 64];
        let len = encode_err_envelope(status, &mut buf);
        let response = &buf[..len];

        let empty_result = TborSessionCloseResp::decode_response(response);
        let fields_result = TborApiRevResp::decode_response(response);

        if status == 0 {
            assert!(
                empty_result.is_ok(),
                "empty response with status zero must decode successfully",
            );

            let fields_err =
                fields_result.expect_err("status-zero placeholder body must reach schema decoding");
            assert!(
                !matches!(fields_err, DecodeError::FwError(_)),
                "status zero must not be reported as an FW error",
            );
        } else {
            assert_eq!(
                empty_result.expect_err("non-zero status must fail"),
                DecodeError::FwError(status),
            );
            assert_eq!(
                fields_result.expect_err("non-zero status must fail"),
                DecodeError::FwError(status),
            );
        }
    }
}

/// Verifies that every non-zero status bit short-circuits fields-response decoding.
#[test]
fn every_single_bit_status_surfaces_for_fields_response() {
    for bit in 0..u32::BITS {
        let status = 1u32 << bit;
        let mut buf = [0u8; 64];
        let len = encode_err_envelope(status, &mut buf);

        let err = TborApiRevResp::decode_response(&buf[..len])
            .expect_err("every non-zero status bit must short-circuit schema decoding");

        assert_eq!(
            err,
            DecodeError::FwError(status),
            "status bit {bit} was not preserved for fields response",
        );
    }
}

/// Verifies that reusing an encoded-response buffer does not retain an old FW status.
#[test]
fn reused_buffer_surfaces_latest_fw_status() {
    let mut buf = [0u8; 64];

    let first_len = encode_err_envelope(SESSION_NOT_FOUND, &mut buf);
    let first_err = TborSessionCloseResp::decode_response(&buf[..first_len])
        .expect_err("first non-zero status must produce FwError");

    assert_eq!(first_err, DecodeError::FwError(SESSION_NOT_FOUND),);

    let second_len = encode_err_envelope(AEAD_ENVELOPE_AUTH_FAILED, &mut buf);
    let second_err = TborSessionCloseResp::decode_response(&buf[..second_len])
        .expect_err("second non-zero status must produce FwError");

    assert_eq!(
        second_err,
        DecodeError::FwError(AEAD_ENVELOPE_AUTH_FAILED),
        "decoder must surface the newly encoded status, not a previous one",
    );
}

/// Verifies that status-gate behavior remains correct when one buffer is reused.
#[test]
fn reused_buffer_handles_zero_nonzero_zero_transition() {
    let mut buf = [0u8; 64];

    let success_len = encode_err_envelope(0, &mut buf);
    TborSessionCloseResp::decode_response(&buf[..success_len])
        .expect("initial status-zero response must decode successfully");

    let error_len = encode_err_envelope(SESSION_NOT_FOUND, &mut buf);
    let err = TborSessionCloseResp::decode_response(&buf[..error_len])
        .expect_err("non-zero status must produce FwError");

    assert_eq!(err, DecodeError::FwError(SESSION_NOT_FOUND),);

    let success_len = encode_err_envelope(0, &mut buf);
    TborSessionCloseResp::decode_response(&buf[..success_len])
        .expect("status zero must decode successfully after an FW error");
}
