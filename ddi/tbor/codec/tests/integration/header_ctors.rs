// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Constructor coverage for the public `Request` / `Response` header types.

use azihsm_ddi_tbor_codec::Request;
use azihsm_ddi_tbor_codec::Response;
use azihsm_ddi_tbor_codec::PROTOCOL_VERSION;

#[test]
fn request_new_sets_current_version_and_opcode() {
    let hdr = Request::new(0x42);
    assert_eq!(hdr.version, PROTOCOL_VERSION);
    assert_eq!(hdr.opcode, 0x42);
}

#[test]
fn response_new_without_fips_clears_flags() {
    let hdr = Response::new(0x1234_5678, false);
    assert_eq!(hdr.version, PROTOCOL_VERSION);
    assert_eq!(hdr.status, 0x1234_5678);
    assert_eq!(hdr.flags, 0);
}

#[test]
fn response_new_with_fips_sets_flag_bit() {
    let hdr = Response::new(0, true);
    assert_eq!(
        hdr.flags & Response::FIPS_APPROVED_FLAG,
        Response::FIPS_APPROVED_FLAG
    );
}
