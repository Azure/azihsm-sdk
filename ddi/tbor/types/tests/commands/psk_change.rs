// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `PskChange` command.
//!
//! Cross-test isolation comes from `open_dev`'s factory-reset; no
//! per-test cleanup is required (see
//! [`crate::harness::fixture`]). Live sessions are owned by a
//! [`SessionGuard`] that closes on `Drop`, including during panic
//! unwind.
//!
//! Coverage:
//! * Happy paths (CO + CU), with explicit reopen using the rotated
//!   PSK to prove the rotation took effect.
//! * Reopen with the old (default) PSK fails after rotation.
//! * One-shot enforcement: second `PskChange` on the same session
//!   surfaces `TborStatus::InvalidPermissions`.
//! * Envelope-tampering negatives: ciphertext bit-flip and AAD
//!   bit-flip both surface `TborStatus::AeadEnvelopeAuthFailed`.
//! * Empty / wrong-length envelope → `TborStatus::TborInvalidFixedLength`
//!   (the schema pins `psk_envelope` to `PSK_CHANGE_ENVELOPE_LEN`).
//! * AAD that encodes a session id other than the request's
//!   session id → `TborStatus::AeadEnvelopeAuthFailed`.
//! * Envelope encrypted under a *different* session's `param_key`
//!   shipped through this session → `TborStatus::AeadEnvelopeAuthFailed`.
//! * Plaintext not exactly `PSK_LEN` (→ wrong envelope length) →
//!   `TborStatus::TborInvalidFixedLength`.

#![cfg(feature = "emu")]

use azihsm_crypto::aead_envelope;
use azihsm_crypto::aead_envelope::AeadAlg;
use azihsm_crypto::AesKey;
use azihsm_crypto::Rng;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::DEFAULT_PSK_CU;
use azihsm_ddi_tbor_types::PSK_LEN;

use crate::harness::build_psk_change_aad;
use crate::harness::encrypt_psk_envelope;
use crate::harness::SessionOpenInitOptions;
use crate::harness::TborPskChangeReq;
use crate::harness::TestCtx;

const CO: u8 = 0;
const CU: u8 = 1;

/// Distinct, non-default 32-byte PSK used by the happy-path tests.
const ROTATED_PSK: [u8; PSK_LEN] = [
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
    0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
];

/// Build an AEAD-GCM envelope under `param_key` with a caller-controlled
/// AAD and plaintext. Negative-path tests use this to exercise FW
/// arms that reject mismatched AAD, wrong-length plaintexts,
/// envelopes encrypted under a different session's key, etc.
fn build_envelope(param_key: &AesKey, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let iv = Rng::rand_vec(12).expect("rng iv");
    let total = aead_envelope::seal(AeadAlg::AesGcm256, param_key, &iv, aad, plaintext, None)
        .expect("aead size");
    let mut out = vec![0u8; total];
    let n = aead_envelope::seal(
        AeadAlg::AesGcm256,
        param_key,
        &iv,
        aad,
        plaintext,
        Some(&mut out),
    )
    .expect("aead seal");
    out.truncate(n);
    out
}

// ===========================================================================
// Happy paths
// ===========================================================================

/// Shared happy-path body for the CU and CO smoke tests below.
/// Open under the role's default PSK, rotate to [`ROTATED_PSK`],
/// then prove the rotation took effect by reopening under the new
/// bytes.
fn run_psk_change_happy(role: u8, sty: SessionType) {
    let ctx = TestCtx::new();
    let session = ctx.open_session(role, sty);
    ctx.psk_change(session.handshake(), &ROTATED_PSK)
        .expect("rotate to ROTATED_PSK");
    session.close().expect("close rotating session");

    // Prove the rotation took effect: a fresh open using the rotated
    // bytes must succeed.
    let opts = SessionOpenInitOptions::new(role, sty).with_psk(&ROTATED_PSK);
    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("reopen under rotated PSK must succeed");
    let resumed = ctx.session_open_finish(pending).expect("finish reopen");
    ctx.session_close(resumed.session_id)
        .expect("close resumed");
}

#[test]
fn psk_change_happy_cu_emu() {
    run_psk_change_happy(CU, SessionType::PlainText);
}

#[test]
fn psk_change_happy_co_emu() {
    run_psk_change_happy(CO, SessionType::Authenticated);
}

// ===========================================================================
// Reopen with old PSK fails after rotation
// ===========================================================================

#[test]
fn psk_change_reopen_with_old_psk_fails_emu() {
    let ctx = TestCtx::new();
    let session = ctx.open_session(CU, SessionType::PlainText);
    ctx.psk_change(session.handshake(), &ROTATED_PSK)
        .expect("rotate");
    session.close().expect("close rotating session");

    // Reopening with the default PSK now fails: host-derived
    // `exported` diverges from FW's, so Phase-1 MAC verification
    // (or HPKE auth) fails. Either a host-side or FW-side
    // rejection is acceptable; we only need "must err".
    let result = ctx.open_session_raw(CU, SessionType::PlainText);
    assert!(
        result.is_err(),
        "reopen with old default PSK must fail after rotation",
    );
}

// ===========================================================================
// One-shot enforcement
// ===========================================================================

#[test]
fn psk_change_second_attempt_same_session_fails_emu() {
    let ctx = TestCtx::new();
    let session = ctx.open_session(CU, SessionType::PlainText);
    ctx.psk_change(session.handshake(), &ROTATED_PSK)
        .expect("first rotate");

    // The session's PSK-change budget is now consumed. A second
    // PskChange on the same session must surface
    // `TborStatus::InvalidPermissions`.
    let err = ctx
        .psk_change(session.handshake(), &DEFAULT_PSK_CU)
        .expect_err("second psk_change on same session must fail");
    crate::harness::assertions::assert_fw_rejects(&err, TborStatus::InvalidPermissions);
}

// ===========================================================================
// Envelope tampering
//
// Both arms (ciphertext bit-flip, AAD bit-flip) must surface the same
// AEAD failure status. Layout reminder:
// HEADER(4) ‖ IV(12) ‖ AAD(32) ‖ CT(32) ‖ TAG(16). AAD starts at
// offset 16; CT starts at offset 48.
// ===========================================================================

#[test]
fn psk_change_envelope_tampered_emu() {
    let ctx = TestCtx::new();

    for (label, mutate) in [
        (
            "ciphertext bit-flip (offset = envelope_len / 2 — inside CT)",
            (|e: &mut Vec<u8>| {
                let target = e.len() / 2;
                e[target] ^= 0x01;
            }) as fn(&mut Vec<u8>),
        ),
        (
            "AAD bit-flip (offset 16 — first AAD byte)",
            (|e: &mut Vec<u8>| {
                e[16] ^= 0x01;
            }) as fn(&mut Vec<u8>),
        ),
    ] {
        let session = ctx.open_session(CU, SessionType::PlainText);
        let mut envelope =
            encrypt_psk_envelope(session.handshake(), &ROTATED_PSK).expect("encrypt envelope");
        mutate(&mut envelope);
        let req = TborPskChangeReq {
            session_id: session.session_id(),
            psk_envelope: envelope,
        };
        let err = ctx
            .tbor(&req)
            .expect_err(&format!("tamper case must be rejected: {label}"));
        crate::harness::assertions::assert_fw_rejects(&err, TborStatus::AeadEnvelopeAuthFailed);
    }
}

// ===========================================================================
// Empty envelope
// ===========================================================================

#[test]
fn psk_change_empty_envelope_emu() {
    let ctx = TestCtx::new();
    let session = ctx.open_session(CU, SessionType::PlainText);
    let req = TborPskChangeReq {
        session_id: session.session_id(),
        psk_envelope: Vec::new(),
    };
    // The FW schema pins `psk_envelope` to PSK_CHANGE_ENVELOPE_LEN
    // (100 B), so an empty envelope is rejected at decode.
    ctx.expect_fw_reject(&req, TborStatus::TborInvalidFixedLength);
}

// ===========================================================================
// AAD-vs-request session-id mismatch
// ===========================================================================

#[test]
fn psk_change_wrong_session_id_in_aad_emu() {
    let ctx = TestCtx::new();
    let session = ctx.open_session(CU, SessionType::PlainText);
    // Build an envelope whose AAD encodes a different (bogus)
    // session id. AEAD-GCM tag verifies (the FW recomputes the tag
    // over *these* bytes), but the FW then constant-compares the AAD
    // against `build_psk_change_aad(req.session_id)` and rejects.
    let bogus_aad = build_psk_change_aad(session.session_id() ^ 0x1234);
    let envelope = build_envelope(&session.handshake().param_key, &bogus_aad, &ROTATED_PSK);
    let req = TborPskChangeReq {
        session_id: session.session_id(),
        psk_envelope: envelope,
    };
    ctx.expect_fw_reject(&req, TborStatus::AeadEnvelopeAuthFailed);
}

// ===========================================================================
// Envelope built under a *different* session's param_key
// ===========================================================================

#[test]
fn psk_change_envelope_from_other_session_emu() {
    let ctx = TestCtx::new();
    let session_a = ctx.open_session(CU, SessionType::PlainText);
    let session_b = ctx.open_session(CU, SessionType::PlainText);
    // Encrypt under A's param_key but ship through B (with B's
    // session id in the request). FW uses B's param_key to verify
    // the AEAD-GCM tag → mismatch.
    let aad_for_b = build_psk_change_aad(session_b.session_id());
    let envelope = build_envelope(&session_a.handshake().param_key, &aad_for_b, &ROTATED_PSK);
    let req = TborPskChangeReq {
        session_id: session_b.session_id(),
        psk_envelope: envelope,
    };
    ctx.expect_fw_reject(&req, TborStatus::AeadEnvelopeAuthFailed);
}

// ===========================================================================
// Wrong plaintext length
// ===========================================================================

#[test]
fn psk_change_wrong_plaintext_length_emu() {
    let ctx = TestCtx::new();
    // PSK_LEN ± 1: shortest excursions either side of the canonical
    // length. A wrong plaintext length yields a wrong *envelope* length
    // (ciphertext tracks plaintext for GCM), so the FW schema's fixed
    // PSK_CHANGE_ENVELOPE_LEN (100 B) rejects both at decode.
    for len in [PSK_LEN - 1, PSK_LEN + 1] {
        let session = ctx.open_session(CU, SessionType::PlainText);
        let bogus_psk = vec![0xCDu8; len];
        let aad = build_psk_change_aad(session.session_id());
        let envelope = build_envelope(&session.handshake().param_key, &aad, &bogus_psk);
        let req = TborPskChangeReq {
            session_id: session.session_id(),
            psk_envelope: envelope,
        };
        let err = ctx.tbor(&req).expect_err(&format!(
            "plaintext length {len} (≠ PSK_LEN={PSK_LEN}) must be rejected",
        ));
        crate::harness::assertions::assert_fw_rejects(&err, TborStatus::TborInvalidFixedLength);
    }
}

// ===========================================================================
// Wrong AAD length (64 bytes — valid AEAD granularity but produces a
// wrong-length envelope the FW schema rejects at decode)
// ===========================================================================

#[test]
fn psk_change_wrong_aad_length_emu() {
    let ctx = TestCtx::new();
    let session = ctx.open_session(CU, SessionType::PlainText);
    // 64 bytes of arbitrary AAD (valid AEAD granularity) inflates the
    // envelope past PSK_CHANGE_ENVELOPE_LEN (100 B), so the FW schema's
    // fixed-length check rejects it at decode.
    let long_aad = vec![0u8; 64];
    let envelope = build_envelope(&session.handshake().param_key, &long_aad, &ROTATED_PSK);
    let req = TborPskChangeReq {
        session_id: session.session_id(),
        psk_envelope: envelope,
    };
    ctx.expect_fw_reject(&req, TborStatus::TborInvalidFixedLength);
}
