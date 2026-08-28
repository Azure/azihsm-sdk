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

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborGetCertChainInfoReq;
use azihsm_ddi_tbor_types::TborGetCertReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::CERT_MAX_LEN;
use x509::X509Certificate;
use x509::X509CertificateOp;

use crate::harness::TestCtx;

const CO: u8 = 0;

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
        assert!(
            resp.certificate.len() <= CERT_MAX_LEN,
            "certificate at index {cert_id} exceeds the wire limit",
        );
        X509Certificate::from_der(&resp.certificate)
            .unwrap_or_else(|e| panic!("certificate at index {cert_id} is invalid X.509: {e:?}"));
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

/// Repeated reads of every advertised certificate return identical bytes.
#[test]
fn repeated_reads_are_stable() {
    let ctx = TestCtx::new();

    for cert_id in 0..num_certs(&ctx) {
        let first = ctx
            .tbor(&TborGetCertReq::new(0, cert_id))
            .unwrap_or_else(|e| panic!("first read of certificate {cert_id} failed: {e:?}"));
        let second = ctx
            .tbor(&TborGetCertReq::new(0, cert_id))
            .unwrap_or_else(|e| panic!("second read of certificate {cert_id} failed: {e:?}"));

        assert_eq!(
            first, second,
            "certificate {cert_id} must be stable across reads",
        );
    }
}

/// Distinct indices in a multi-certificate chain must not alias the same
/// certificate bytes.
#[test]
fn certificate_indices_do_not_alias() {
    let ctx = TestCtx::new();
    let mut certificates = Vec::new();

    for cert_id in 0..num_certs(&ctx) {
        let cert = ctx
            .tbor(&TborGetCertReq::new(0, cert_id))
            .unwrap_or_else(|e| panic!("failed to read certificate {cert_id}: {e:?}"));

        for (previous_id, previous) in certificates.iter().enumerate() {
            assert_ne!(
                &cert.certificate, previous,
                "certificate {cert_id} aliases certificate {previous_id}",
            );
        }

        certificates.push(cert.certificate);
    }
}

/// The first index beyond the chain and the largest representable index are
/// rejected with `InvalidArg`.
#[test]
fn invalid_indices_rejected() {
    let ctx = TestCtx::new();
    let count = num_certs(&ctx);

    for cert_id in [count, u8::MAX] {
        ctx.expect_fw_reject(&TborGetCertReq::new(0, cert_id), TborStatus::InvalidArg);
    }
}

/// The std/emu PAL only provisions chain slot 0; any other slot is
/// rejected with `InvalidArg`.
#[test]
fn invalid_slots_rejected() {
    let ctx = TestCtx::new();

    for slot_id in [1, 2, 127, 254, u8::MAX] {
        ctx.expect_fw_reject(&TborGetCertReq::new(slot_id, 0), TborStatus::InvalidArg);
    }
}

/// Rejected requests must not disturb a certificate that can be read from the
/// valid chain.
#[test]
fn rejected_requests_do_not_affect_valid_certificate() {
    let ctx = TestCtx::new();
    let request = TborGetCertReq::new(0, 0);
    let before = ctx
        .tbor(&request)
        .expect("valid certificate before rejects");

    ctx.expect_fw_reject(&TborGetCertReq::new(u8::MAX, 0), TborStatus::InvalidArg);
    ctx.expect_fw_reject(&TborGetCertReq::new(0, u8::MAX), TborStatus::InvalidArg);

    let after = ctx.tbor(&request).expect("valid certificate after rejects");
    assert_eq!(
        before, after,
        "rejected requests must not mutate the valid certificate chain",
    );
}

/// `GetCertificate` is out-of-session and remains callable while an unrelated
/// authenticated session is active.
#[test]
fn callable_while_session_active() {
    let ctx = TestCtx::new();
    let request = TborGetCertReq::new(0, 0);
    let before = ctx.tbor(&request).expect("certificate before session");

    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open CO authenticated session");
    let during = ctx
        .tbor(&request)
        .expect("certificate while session is active");

    assert_eq!(
        before, during,
        "active session must not affect out-of-session certificate reads",
    );
    session.close().expect("close CO authenticated session");
}

/// Every certificate index advertised by `GetCertChainInfo` is readable, and
/// the first index beyond the advertised chain is rejected.
#[test]
fn chain_info_count_matches_get_certificate_boundary() {
    let ctx = TestCtx::new();
    let count = num_certs(&ctx);

    assert!(count > 0, "chain must contain at least one certificate");

    for cert_id in 0..count {
        ctx.tbor(&TborGetCertReq::new(0, cert_id))
            .unwrap_or_else(|e| {
                panic!(
                    "GetCertChainInfo advertised certificate {cert_id}, \
                     but GetCertificate rejected it: {e:?}"
                )
            });
    }

    ctx.expect_fw_reject(&TborGetCertReq::new(0, count), TborStatus::InvalidArg);
}

/// Reading other certificates in the chain must not affect a previously read
/// certificate.
#[test]
fn interleaved_reads_are_stable() {
    let ctx = TestCtx::new();
    let count = num_certs(&ctx);

    let first = ctx
        .tbor(&TborGetCertReq::new(0, 0))
        .expect("initial certificate 0 read");

    for cert_id in 0..count {
        ctx.tbor(&TborGetCertReq::new(0, cert_id))
            .unwrap_or_else(|e| panic!("interleaved certificate {cert_id} read failed: {e:?}"));
    }

    let after = ctx
        .tbor(&TborGetCertReq::new(0, 0))
        .expect("certificate 0 after interleaved reads");

    assert_eq!(
        first, after,
        "reading other certificates must not affect certificate 0",
    );
}

/// Opening and closing an authenticated session must not affect subsequent
/// out-of-session certificate reads.
#[test]
fn stable_across_session_lifecycle() {
    let ctx = TestCtx::new();
    let request = TborGetCertReq::new(0, 0);

    let before = ctx
        .tbor(&request)
        .expect("certificate before opening session");

    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open CO authenticated session");

    let during = ctx
        .tbor(&request)
        .expect("certificate while session is active");

    session.close().expect("close CO authenticated session");

    let after = ctx
        .tbor(&request)
        .expect("certificate after closing session");

    assert_eq!(
        before, during,
        "opening a session must not affect GetCertificate",
    );
    assert_eq!(
        before, after,
        "closing a session must not affect GetCertificate",
    );
}

/// A failed certificate lookup must not affect later reads of any valid
/// certificate in the chain.
#[test]
fn rejected_request_does_not_affect_entire_chain() {
    let ctx = TestCtx::new();
    let count = num_certs(&ctx);

    let before: Vec<_> = (0..count)
        .map(|cert_id| {
            ctx.tbor(&TborGetCertReq::new(0, cert_id))
                .unwrap_or_else(|e| panic!("initial certificate {cert_id} read failed: {e:?}"))
        })
        .collect();

    ctx.expect_fw_reject(
        &TborGetCertReq::new(u8::MAX, u8::MAX),
        TborStatus::InvalidArg,
    );

    for (cert_id, expected) in before.iter().enumerate() {
        let actual = ctx
            .tbor(&TborGetCertReq::new(0, cert_id as u8))
            .unwrap_or_else(|e| {
                panic!("certificate {cert_id} read after rejected request failed: {e:?}")
            });

        assert_eq!(
            &actual, expected,
            "rejected request must not modify certificate {cert_id}",
        );
    }
}

/// Reading certificates must not change the metadata reported by
/// `GetCertChainInfo`.
#[test]
fn certificate_reads_do_not_change_chain_info() {
    let ctx = TestCtx::new();

    let before = ctx
        .tbor(&TborGetCertChainInfoReq::new(0))
        .expect("chain info before certificate reads");

    for cert_id in 0..before.num_certs {
        ctx.tbor(&TborGetCertReq::new(0, cert_id))
            .unwrap_or_else(|e| panic!("certificate {cert_id} read failed: {e:?}"));
    }

    let after = ctx
        .tbor(&TborGetCertChainInfoReq::new(0))
        .expect("chain info after certificate reads");

    assert_eq!(
        before, after,
        "GetCertificate reads must not modify certificate-chain metadata",
    );
}

/// Certificates may be fetched in arbitrary order; reads do not depend on
/// sequential traversal of the chain.
#[test]
fn certificates_can_be_read_in_reverse_order() {
    let ctx = TestCtx::new();
    let count = num_certs(&ctx);

    for cert_id in (0..count).rev() {
        let cert = ctx
            .tbor(&TborGetCertReq::new(0, cert_id))
            .unwrap_or_else(|e| panic!("reverse read of certificate {cert_id} failed: {e:?}"));

        assert!(
            !cert.certificate.is_empty(),
            "certificate {cert_id} must be non-empty",
        );
    }
}
