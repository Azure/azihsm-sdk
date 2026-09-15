// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the out-of-session TBOR `GetCertificate`
//! command.
//!
//! `GetCertificate` is the TBOR analogue of MBOR `GetCertificate`: it
//! returns a single DER-encoded X.509 certificate from the caller's
//! partition at a `(slot_id, cert_id)`, without first establishing a
//! session. The tests fetch every certificate in the chain, cross-check
//! each against the MBOR path (same underlying cert store), and confirm
//! that an out-of-range index or slot is rejected.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::TborGetCertChainInfoReq;
use azihsm_ddi_tbor_types::TborGetCertReq;
use azihsm_ddi_tbor_types::TborStatus;

use crate::harness::TestCtx;

/// Fetch the chain length via TBOR `GetCertChainInfo`.
fn num_certs(ctx: &TestCtx) -> u8 {
    ctx.tbor(&TborGetCertChainInfoReq::new(0))
        .expect("GetCertChainInfo")
        .num_certs
}

#[test]
fn all_indices_round_trip() {
    let ctx = TestCtx::new();
    let count = num_certs(&ctx);
    assert!(count > 0, "chain must be non-empty");

    for cert_id in 0..count {
        let resp = ctx
            .tbor(&TborGetCertReq::new(0, cert_id))
            .unwrap_or_else(|e| panic!("TBOR GetCertificate(idx={cert_id}) failed: {e:?}"));
        assert!(
            !resp.certificate.is_empty(),
            "certificate at index {cert_id} must be non-empty DER",
        );
        // DER-encoded X.509 certificates start with a SEQUENCE tag.
        assert_eq!(
            resp.certificate[0], 0x30,
            "certificate at index {cert_id} must be a DER SEQUENCE",
        );
    }
}

/// The TBOR certificate bytes must be identical to the MBOR path for
/// every index — both read the same underlying cert store.
#[test]
fn matches_mbor_path() {
    let ctx = TestCtx::new();
    let count = num_certs(&ctx);

    for cert_id in 0..count {
        let tbor = ctx
            .tbor(&TborGetCertReq::new(0, cert_id))
            .unwrap_or_else(|e| panic!("TBOR GetCertificate(idx={cert_id}): {e:?}"));
        let mbor = ctx
            .get_certificate(cert_id)
            .unwrap_or_else(|e| panic!("MBOR GetCertificate(idx={cert_id}): {e:?}"));
        assert_eq!(
            tbor.certificate.as_slice(),
            mbor.data.certificate.as_slice(),
            "TBOR and MBOR certificate bytes must match at index {cert_id}",
        );
    }
}

/// An index at or beyond the chain length is rejected with `InvalidArg`.
#[test]
fn invalid_index_rejected() {
    let ctx = TestCtx::new();
    let count = num_certs(&ctx);
    ctx.expect_fw_reject(&TborGetCertReq::new(0, count), TborStatus::InvalidArg);
}

/// The std/emu PAL only provisions chain slot 0; any other slot is
/// rejected with `InvalidArg`.
#[test]
fn invalid_slot_rejected() {
    let ctx = TestCtx::new();
    ctx.expect_fw_reject(&TborGetCertReq::new(1, 0), TborStatus::InvalidArg);
}
