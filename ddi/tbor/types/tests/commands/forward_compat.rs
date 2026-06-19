// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the forward/backward-compatibility contract of derived
//! `TborResp::decode_response` implementations.
//!
//! The host derive emits a `toc_count() < expected_toc` gate so that:
//!
//! * **Fewer** entries than the schema knows  ⇒
//!   [`codec::DecodeError::MessageTruncated`] (legitimate truncation).
//! * **More** entries than the schema knows   ⇒ trailing entries are
//!   ignored and the known prefix decodes successfully (forward
//!   compatibility: a newer FW can append fields without breaking
//!   older host decoders).

use azihsm_ddi_tbor_types::codec::DecodeError;
use azihsm_ddi_tbor_types::codec::ResponseEncoder;
use azihsm_ddi_tbor_types::codec::PROTOCOL_VERSION;
use azihsm_ddi_tbor_types::TborGetApiRevResp;
use azihsm_ddi_tbor_types::TborResp;

#[test]
fn extra_trailing_toc_entries_are_ignored() {
    // TborGetApiRevResp expects two Uint8 TOC entries (current,
    // max_protocol_version). Encode three: the two real ones plus a
    // trailing future-field placeholder. Decode must succeed and
    // surface the two known fields.
    let mut buf = [0u8; 64];
    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(0x05)
        .expect("encode min")
        .uint8(0x07)
        .expect("encode max")
        .uint8(0xFF)
        .expect("encode trailing future field")
        .finish()
        .expect("finish");

    let resp = TborGetApiRevResp::decode_response(bytes)
        .expect("forward-compat: trailing entries must not block decode");
    assert_eq!(resp.min_protocol_version, 0x05);
    assert_eq!(resp.max_protocol_version, 0x07);
}

#[test]
fn fewer_toc_entries_than_schema_is_truncated() {
    // TborGetApiRevResp expects two Uint8 TOC entries; encode only one.
    let mut buf = [0u8; 64];
    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(0x05)
        .expect("encode current")
        .finish()
        .expect("finish");

    let err = TborGetApiRevResp::decode_response(bytes)
        .expect_err("expected MessageTruncated for missing TOC entries");
    assert_eq!(err, DecodeError::MessageTruncated);
}
