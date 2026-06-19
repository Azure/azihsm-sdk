// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for schema-shape mismatches reported by derived `TborResp`
//! implementations as [`codec::DecodeError::UnexpectedTocType`].

use azihsm_ddi_tbor_types::codec::DecodeError;
use azihsm_ddi_tbor_types::codec::ResponseEncoder;
use azihsm_ddi_tbor_types::codec::PROTOCOL_VERSION;
use azihsm_ddi_tbor_types::TborGetApiRevResp;
use azihsm_ddi_tbor_types::TborResp;

#[test]
fn wrong_toc_entry_type_yields_unexpected_toc_type() {
    // TborGetApiRevResp expects two Uint8 TOC entries. Encode the
    // first slot as a SessionId (a wrong type) instead — status is 0
    // so the FwError gate does not short-circuit the schema decoder.
    let mut buf = [0u8; 64];
    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .session_id(0xAAAA)
        .expect("encode session_id")
        .uint8(0x02)
        .expect("encode uint8")
        .finish()
        .expect("finish");

    let err = TborGetApiRevResp::decode_response(bytes)
        .expect_err("expected schema-shape mismatch to be rejected");
    assert_eq!(err, DecodeError::UnexpectedTocType);
}
