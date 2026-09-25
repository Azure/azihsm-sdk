// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the out-of-session TBOR `GetCertChainInfo`
//! command.
//!
//! `GetCertChainInfo` is the TBOR analogue of MBOR `GetCertChainInfo`:
//! it reports the number of certificates and the leaf-certificate
//! SHA-256 thumbprint for the caller's partition at a chain slot,
//! without first establishing a session.The tests round-trip the
//! command, assert stability, cross-check the result against the MBOR
//! path (same underlying cert store), and confirm an invalid slot is
//! rejected.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::codec::DecodeError;
use azihsm_ddi_tbor_types::codec::ResponseEncoder;
use azihsm_ddi_tbor_types::codec::MAX_TOC_ENTRIES;
use azihsm_ddi_tbor_types::codec::PROTOCOL_VERSION;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborGetCertChainInfoReq;
use azihsm_ddi_tbor_types::TborGetCertChainInfoResp;
use azihsm_ddi_tbor_types::TborGetCertReq;
use azihsm_ddi_tbor_types::TborResp;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::CERT_THUMBPRINT_LEN;

use crate::commands::common::CO;
use crate::commands::common::CU;
use crate::harness::TestCtx;

const VALID_SLOT: u8 = 0;

/// The provisioned chain slot returns valid certificate-chain metadata.
#[test]
fn round_trip() {
    let ctx = TestCtx::new();
    let resp = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
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
        resp.thumbprint.iter().any(|&byte| byte != 0),
        "thumbprint must be materialized (non-zero)",
    );
}

/// `GetCertChainInfo` is a pure read — repeated calls on a quiescent
/// partition return a byte-identical response.
#[test]
fn repeated_stable() {
    let ctx = TestCtx::new();
    let first = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("first GetCertChainInfo");
    let second = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
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
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
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
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("GetCertChainInfo");

    assert!(info.num_certs > 0, "chain must be non-empty");
    for cert_id in 0..info.num_certs {
        let cert = ctx
            .tbor(&TborGetCertReq::new(VALID_SLOT, cert_id))
            .unwrap_or_else(|err| {
                panic!("advertised certificate {cert_id} is unreadable: {err:?}")
            });
        assert!(
            !cert.certificate.is_empty(),
            "advertised certificate {cert_id} must contain DER bytes",
        );
    }

    ctx.expect_fw_reject(
        &TborGetCertReq::new(VALID_SLOT, info.num_certs),
        TborStatus::InvalidArg,
    );
}

/// Reading certificates from the chain must not mutate the information
/// subsequently returned by `GetCertChainInfo`.
#[test]
fn certificate_reads_do_not_change_chain_info() {
    let ctx = TestCtx::new();

    let before = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("GetCertChainInfo before certificate reads");

    for cert_id in 0..before.num_certs {
        ctx.tbor(&TborGetCertReq::new(VALID_SLOT, cert_id))
            .unwrap_or_else(|err| panic!("failed to read certificate {cert_id}: {err:?}"));
    }

    let after = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
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
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("GetCertChainInfo");

    assert!(info.num_certs > 0, "chain must be non-empty");

    for cert_id in 0..info.num_certs {
        let first = ctx
            .tbor(&TborGetCertReq::new(VALID_SLOT, cert_id))
            .unwrap_or_else(|err| panic!("first read of certificate {cert_id} failed: {err:?}"));

        let second = ctx
            .tbor(&TborGetCertReq::new(VALID_SLOT, cert_id))
            .unwrap_or_else(|err| panic!("second read of certificate {cert_id} failed: {err:?}"));

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
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("GetCertChainInfo");

    let mut certificates = Vec::new();

    for cert_id in 0..info.num_certs {
        let cert = ctx
            .tbor(&TborGetCertReq::new(VALID_SLOT, cert_id))
            .unwrap_or_else(|err| panic!("failed to read certificate {cert_id}: {err:?}"));

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
#[test]
fn invalid_slot_does_not_affect_valid_slot() {
    let ctx = TestCtx::new();

    let before = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("GetCertChainInfo before invalid request");

    ctx.expect_fw_reject(
        &TborGetCertChainInfoReq::new(u8::MAX),
        TborStatus::InvalidArg,
    );

    let after = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("GetCertChainInfo after invalid request");

    assert_eq!(
        before, after,
        "invalid slot request must not affect the valid certificate chain",
    );
}

/// `GetCertChainInfo` remains stable across unrelated Crypto-Officer
/// session activity.
#[test]
fn stable_across_co_session_activity() {
    let ctx = TestCtx::new();

    let before = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("GetCertChainInfo before CO session activity");

    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open CO authenticated session");

    session.close().expect("close CO authenticated session");

    let after = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("GetCertChainInfo after CO session activity");

    assert_eq!(
        before, after,
        "CO session activity must not change certificate-chain info",
    );
}

/// `GetCertChainInfo` remains callable while a Crypto-Officer session is
/// active.
#[test]
fn callable_while_co_session_active() {
    let ctx = TestCtx::new();

    let before = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("GetCertChainInfo before opening CO session");

    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open CO authenticated session");

    let during = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("GetCertChainInfo while CO session is active");

    assert_eq!(
        before, during,
        "active CO session must not affect out-of-session certificate-chain info",
    );

    session.close().expect("close CO authenticated session");
}

/// Representative unsupported slot IDs are rejected with `InvalidArg`.
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

/// A response missing the thumbprint TOC entry is rejected as truncated.
#[test]
fn truncated_response_rejected() {
    let mut buf = [0u8; 128];

    // GetCertChainInfo expects:
    //   1. num_certs
    //   2. thumbprint
    // Encode only num_certs.
    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(4)
        .expect("encode num_certs")
        .finish()
        .expect("finish truncated response");

    let err = TborGetCertChainInfoResp::decode_response(bytes)
        .expect_err("missing thumbprint must be rejected");

    assert_eq!(err, DecodeError::MessageTruncated);
}

/// A response with the maximum supported TOC count still decodes the known prefix.
#[test]
fn max_toc_response_decodes_known_fields() {
    let mut buf = [0u8; 512];
    let thumbprint = [0xA5u8; CERT_THUMBPRINT_LEN];

    let mut encoder = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(4)
        .expect("encode num_certs")
        .buffer(&thumbprint)
        .expect("encode thumbprint");

    // Fill remaining TOC slots with unknown future fields.
    for _ in 2..MAX_TOC_ENTRIES {
        encoder = encoder.uint8(0xFF).expect("encode trailing TOC entry");
    }

    let bytes = encoder.finish().expect("finish max-TOC response");

    let resp = TborGetCertChainInfoResp::decode_response(bytes)
        .expect("maximum TOC response must decode known prefix");

    assert_eq!(resp.num_certs, 4);
    assert_eq!(resp.thumbprint, thumbprint);
}

/// A response with the wrong TOC type for `num_certs` is rejected.
#[test]
fn wrong_num_certs_type_rejected() {
    let mut buf = [0u8; 512];
    let thumbprint = [0xA5u8; CERT_THUMBPRINT_LEN];

    // num_certs expects Uint8; deliberately encode Uint16.
    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint16(4)
        .expect("encode wrong num_certs type")
        .buffer(&thumbprint)
        .expect("encode thumbprint")
        .finish()
        .expect("finish response");

    let err = TborGetCertChainInfoResp::decode_response(bytes)
        .expect_err("wrong num_certs TOC type must be rejected");

    assert_eq!(err, DecodeError::UnexpectedTocType);
}

/// A response with the wrong TOC type for the thumbprint is rejected.
#[test]
fn wrong_thumbprint_type_rejected() {
    let mut buf = [0u8; 128];

    // thumbprint expects Buffer; deliberately encode Uint8.
    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(4)
        .expect("encode num_certs")
        .uint8(0xA5)
        .expect("encode wrong thumbprint type")
        .finish()
        .expect("finish response");

    let err = TborGetCertChainInfoResp::decode_response(bytes)
        .expect_err("wrong thumbprint TOC type must be rejected");

    assert_eq!(err, DecodeError::UnexpectedTocType);
}

/// `GetCertChainInfo` remains stable across unrelated Crypto-User
/// session activity.
#[test]
fn stable_across_cu_session_activity() {
    let ctx = TestCtx::new();

    let before = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("GetCertChainInfo before CU session activity");

    // CU bootstrap sessions use PlainText while the CU PSK is still
    // the compiled-in default.
    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open CU plaintext session");

    session.close().expect("close CU plaintext session");

    let after = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("GetCertChainInfo after CU session activity");

    assert_eq!(
        before, after,
        "CU session activity must not change certificate-chain info",
    );
}

/// `GetCertChainInfo` remains callable while a Crypto-User session is
/// active.
#[test]
fn callable_while_cu_session_active() {
    let ctx = TestCtx::new();

    let before = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("GetCertChainInfo before opening CU session");

    // CU bootstrap sessions use PlainText while the CU PSK is still
    // the compiled-in default.
    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open CU plaintext session");

    let during = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("GetCertChainInfo while CU session is active");

    assert_eq!(
        before, during,
        "active CU session must not affect out-of-session certificate-chain info",
    );

    session.close().expect("close CU plaintext session");
}

/// A response containing one additional unknown TOC entry must preserve
/// the known fields.
#[test]
fn trailing_unknown_field_is_ignored() {
    // Leave enough room for the response header, TOC entries,
    // 32-byte thumbprint, and trailing forward-compatible field.
    let mut buf = [0u8; 512];
    let thumbprint = [0x5Au8; CERT_THUMBPRINT_LEN];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(2)
        .expect("encode num_certs")
        .buffer(&thumbprint)
        .expect("encode thumbprint")
        .uint8(0xFF)
        .expect("encode unknown trailing field")
        .finish()
        .expect("finish response with trailing field");

    let resp = TborGetCertChainInfoResp::decode_response(bytes)
        .expect("trailing unknown field must not break known prefix");

    assert_eq!(resp.num_certs, 2);
    assert_eq!(resp.thumbprint, thumbprint);
}

/// The request constructor preserves the supplied `slot_id`.
#[test]
fn request_constructor_preserves_slot_id() {
    for slot_id in [0, 1, 2, 127, 254, u8::MAX] {
        let req = TborGetCertChainInfoReq::new(slot_id);

        assert_eq!(
            req.slot_id, slot_id,
            "constructor must preserve slot_id {slot_id}",
        );
    }
}

/// The derived default request targets slot 0.
#[test]
fn default_request_targets_slot_zero() {
    let req = TborGetCertChainInfoReq::default();

    assert_eq!(
        req.slot_id, VALID_SLOT,
        "default request must target slot 0",
    );
}

/// The default request must behave identically to an explicitly
/// constructed request for slot 0.
#[test]
fn default_request_matches_explicit_slot_zero() {
    let ctx = TestCtx::new();

    let default_resp = ctx
        .tbor(&TborGetCertChainInfoReq::default())
        .expect("default GetCertChainInfo request");

    let explicit_resp = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("explicit slot-0 GetCertChainInfo request");

    assert_eq!(
        default_resp, explicit_resp,
        "default request and explicit slot 0 must be equivalent",
    );
}

/// Exercise several consecutive calls to catch accidental mutable command
/// state that may not be visible with only two requests.
#[test]
fn repeated_calls_remain_stable() {
    let ctx = TestCtx::new();

    let expected = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("initial GetCertChainInfo");

    for iteration in 0..8 {
        let actual = ctx
            .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
            .unwrap_or_else(|err| panic!("GetCertChainInfo iteration {iteration} failed: {err:?}"));

        assert_eq!(
            actual, expected,
            "GetCertChainInfo changed on iteration {iteration}",
        );
    }
}

/// Explicitly exercise the immediate boundary after the only supported
/// slot.
#[test]
fn first_unsupported_slot_rejected() {
    let ctx = TestCtx::new();

    ctx.expect_fw_reject(
        &TborGetCertChainInfoReq::new(VALID_SLOT + 1),
        TborStatus::InvalidArg,
    );
}

/// Explicitly exercise the maximum value representable by the request
/// parameter.
#[test]
fn maximum_slot_id_rejected() {
    let ctx = TestCtx::new();

    ctx.expect_fw_reject(
        &TborGetCertChainInfoReq::new(u8::MAX),
        TborStatus::InvalidArg,
    );
}

/// Several rejected requests must not accumulate state or otherwise alter
/// the valid chain.
#[test]
fn repeated_invalid_slots_do_not_affect_valid_slot() {
    let ctx = TestCtx::new();

    let expected = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("GetCertChainInfo before invalid requests");

    for slot_id in [1, 2, 127, 254, u8::MAX] {
        ctx.expect_fw_reject(
            &TborGetCertChainInfoReq::new(slot_id),
            TborStatus::InvalidArg,
        );
    }

    let actual = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("GetCertChainInfo after invalid requests");

    assert_eq!(
        expected, actual,
        "invalid requests must not affect the valid certificate chain",
    );
}

/// The maximum certificate index must also be rejected when it lies
/// outside the range advertised by `num_certs`.
#[test]
fn maximum_certificate_index_rejected_when_out_of_range() {
    let ctx = TestCtx::new();

    let info = ctx
        .tbor(&TborGetCertChainInfoReq::new(VALID_SLOT))
        .expect("GetCertChainInfo");

    if info.num_certs < u8::MAX {
        ctx.expect_fw_reject(
            &TborGetCertReq::new(VALID_SLOT, u8::MAX),
            TborStatus::InvalidArg,
        );
    }
}
