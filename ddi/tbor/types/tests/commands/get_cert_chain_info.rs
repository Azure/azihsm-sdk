// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the out-of-session TBOR `GetCertChainInfo`
//! command.
//!
//! `GetCertChainInfo` is the TBOR analogue of MBOR `GetCertChainInfo`:
//! it reports the number of certificates and the leaf-certificate
//! SHA-256 thumbprint for the caller's partition at a chain slot,
//! without first establishing a session. The tests round-trip the
//! command, assert stability, cross-check the result against the MBOR
//! path (same underlying cert store), and confirm an invalid slot is
//! rejected.

use azihsm_ddi_tbor_types::TborGetCertChainInfoReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::CERT_THUMBPRINT_LEN;

use azihsm_ddi_tbor_test_harness::TestCtx;

#[test]
fn round_trip() {
    let ctx = TestCtx::new();
    let resp = ctx
        .tbor(&TborGetCertChainInfoReq::new(0))
        .expect("TBOR GetCertChainInfo round-trip");

    assert!(
        resp.num_certs > 0,
        "default provisioned partition must have a non-empty chain",
    );
    assert_eq!(
        resp.thumbprint.len(),
        CERT_THUMBPRINT_LEN,
        "thumbprint must be the pinned length",
    );
    assert!(
        resp.thumbprint.iter().any(|&b| b != 0),
        "thumbprint must be materialized (non-zero)",
    );
}

/// `GetCertChainInfo` is a pure read — repeated calls on a quiescent
/// partition return a byte-identical response.
#[test]
fn repeated_stable() {
    let ctx = TestCtx::new();
    let first = ctx
        .tbor(&TborGetCertChainInfoReq::new(0))
        .expect("first GetCertChainInfo");
    let second = ctx
        .tbor(&TborGetCertChainInfoReq::new(0))
        .expect("second GetCertChainInfo");
    assert_eq!(
        first, second,
        "GetCertChainInfo must be stable across calls",
    );
}

/// The TBOR result must agree with the MBOR `GetCertChainInfo` path —
/// both read the same underlying cert store, so `num_certs` and the
/// `thumbprint` must be identical.
#[test]
fn matches_mbor_path() {
    let ctx = TestCtx::new();
    let tbor = ctx
        .tbor(&TborGetCertChainInfoReq::new(0))
        .expect("TBOR GetCertChainInfo");
    let mbor = ctx.cert_chain_info().expect("MBOR GetCertChainInfo");

    assert_eq!(
        tbor.num_certs, mbor.data.num_certs,
        "TBOR and MBOR must report the same certificate count",
    );
    assert_eq!(
        &tbor.thumbprint[..],
        mbor.data.thumbprint.as_slice(),
        "TBOR and MBOR must report the same leaf thumbprint",
    );
}

/// The std/emu PAL only provisions chain slot 0; any other slot is
/// rejected with `InvalidArg`.
#[test]
fn invalid_slot_rejected() {
    let ctx = TestCtx::new();
    ctx.expect_fw_reject(&TborGetCertChainInfoReq::new(1), TborStatus::InvalidArg);
}
