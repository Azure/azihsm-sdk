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

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborGetCertChainInfoReq;
use azihsm_ddi_tbor_types::TborGetCertReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::CERT_THUMBPRINT_LEN;

use crate::harness::TestCtx;

const CO: u8 = 0;
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

/// The reported count defines the complete set of valid certificate
/// indices for the same slot: every advertised index is readable and the
/// first index beyond the count is rejected.
#[test]
fn reported_count_defines_certificate_bounds() {
    let ctx = TestCtx::new();
    let info = ctx
        .tbor(&TborGetCertChainInfoReq::new(0))
        .expect("GetCertChainInfo");

    assert!(info.num_certs > 0, "chain must be non-empty");
    for cert_id in 0..info.num_certs {
        let cert = ctx
            .tbor(&TborGetCertReq::new(0, cert_id))
            .unwrap_or_else(|e| panic!("advertised certificate {cert_id} is unreadable: {e:?}"));
        assert!(
            !cert.certificate.is_empty(),
            "advertised certificate {cert_id} must contain DER bytes",
        );
    }

    ctx.expect_fw_reject(
        &TborGetCertReq::new(0, info.num_certs),
        TborStatus::InvalidArg,
    );
}

/// The std/emu PAL only provisions chain slot 0; any other slot is
/// rejected with `InvalidArg`.
#[test]
fn invalid_slots_rejected() {
    let ctx = TestCtx::new();
    for slot_id in [1, u8::MAX] {
        ctx.expect_fw_reject(
            &TborGetCertChainInfoReq::new(slot_id),
            TborStatus::InvalidArg,
        );
    }
}

/// Reading certificates from the chain must not mutate the information
/// subsequently returned by `GetCertChainInfo`.
#[test]
fn certificate_reads_do_not_change_chain_info() {
    let ctx = TestCtx::new();

    let before = ctx
        .tbor(&TborGetCertChainInfoReq::new(0))
        .expect("GetCertChainInfo before certificate reads");

    for cert_id in 0..before.num_certs {
        ctx.tbor(&TborGetCertReq::new(0, cert_id))
            .unwrap_or_else(|e| panic!("failed to read certificate {cert_id}: {e:?}"));
    }

    let after = ctx
        .tbor(&TborGetCertChainInfoReq::new(0))
        .expect("GetCertChainInfo after certificate reads");

    assert_eq!(
        before, after,
        "certificate reads must not mutate chain metadata",
    );
}

/// Every advertised certificate is stable across repeated reads.
#[test]
fn certificates_are_stable_across_reads() {
    let ctx = TestCtx::new();
    let info = ctx
        .tbor(&TborGetCertChainInfoReq::new(0))
        .expect("GetCertChainInfo");

    assert!(info.num_certs > 0, "chain must be non-empty");

    for cert_id in 0..info.num_certs {
        let first = ctx
            .tbor(&TborGetCertReq::new(0, cert_id))
            .unwrap_or_else(|e| panic!("first read of certificate {cert_id} failed: {e:?}"));

        let second = ctx
            .tbor(&TborGetCertReq::new(0, cert_id))
            .unwrap_or_else(|e| panic!("second read of certificate {cert_id} failed: {e:?}"));

        assert_eq!(
            first.certificate, second.certificate,
            "certificate {cert_id} must be stable across reads",
        );
    }
}

/// Distinct indices in a multi-certificate chain must not alias the same
/// certificate bytes.
#[test]
fn certificate_indices_do_not_alias() {
    let ctx = TestCtx::new();
    let info = ctx
        .tbor(&TborGetCertChainInfoReq::new(0))
        .expect("GetCertChainInfo");

    let mut certificates = Vec::new();

    for cert_id in 0..info.num_certs {
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

/// A rejected request for another slot must not disturb the valid
/// provisioned chain in slot 0.
#[cfg(feature = "emu")]
#[test]
fn invalid_slot_does_not_affect_valid_slot() {
    let ctx = TestCtx::new();

    let before = ctx
        .tbor(&TborGetCertChainInfoReq::new(0))
        .expect("GetCertChainInfo before invalid request");

    ctx.expect_fw_reject(
        &TborGetCertChainInfoReq::new(u8::MAX),
        TborStatus::InvalidArg,
    );

    let after = ctx
        .tbor(&TborGetCertChainInfoReq::new(0))
        .expect("GetCertChainInfo after invalid request");

    assert_eq!(
        before, after,
        "invalid slot request must not affect the valid certificate chain",
    );
}

/// `GetCertChainInfo` remains stable across unrelated session activity.
#[test]
fn stable_across_session_activity() {
    let ctx = TestCtx::new();

    let before = ctx
        .tbor(&TborGetCertChainInfoReq::new(0))
        .expect("GetCertChainInfo before session activity");

    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open CO authenticated session");

    session.close().expect("close CO authenticated session");

    let after = ctx
        .tbor(&TborGetCertChainInfoReq::new(0))
        .expect("GetCertChainInfo after session activity");

    assert_eq!(
        before, after,
        "session activity must not change certificate-chain info",
    );
}

/// `GetCertChainInfo` remains callable while an unrelated session is active.
#[test]
fn callable_while_session_active() {
    let ctx = TestCtx::new();

    let before = ctx
        .tbor(&TborGetCertChainInfoReq::new(0))
        .expect("GetCertChainInfo before opening session");

    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open CO authenticated session");

    let during = ctx
        .tbor(&TborGetCertChainInfoReq::new(0))
        .expect("GetCertChainInfo while session is active");

    assert_eq!(
        before, during,
        "active session must not affect out-of-session certificate-chain info",
    );

    session.close().expect("close CO authenticated session");
}

/// Representative unsupported slot IDs are rejected with `InvalidArg`.
#[cfg(feature = "emu")]
#[test]
fn unsupported_slot_boundaries_rejected() {
    let ctx = TestCtx::new();

    for slot_id in [1, 2, 127, 254, u8::MAX] {
        ctx.expect_fw_reject(
            &TborGetCertChainInfoReq::new(slot_id),
            TborStatus::InvalidArg,
        );
    }
}
