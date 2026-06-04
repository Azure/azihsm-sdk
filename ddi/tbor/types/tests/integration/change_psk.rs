// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Phase 5b integration tests for the TBOR `ChangePsk` command.
//!
//! Each test runs against the `emu` backend. PSK rotations are
//! persistent across tests because the emulator's `StdHsm` is
//! process-global; every test that performs a successful rotation
//! restores the canonical default PSK before exiting. Tests are
//! serialised via [`serial_test::serial`].
//!
//! Coverage:
//! * Happy paths (CO + CU), with explicit reopen using the rotated
//!   PSK to prove the rotation took effect.
//! * Reopen with the old (default) PSK fails after rotation.
//! * One-shot enforcement: second `ChangePsk` on the same session
//!   surfaces `HsmError::InvalidPermissions`.
//! * Envelope-tampering negatives: ciphertext bit-flip and AAD
//!   bit-flip both surface `HsmError::AeadEnvelopeAuthFailed`.
//! * Empty envelope → `HsmError::InvalidArg`.
//! * AAD that encodes a session id other than the request's
//!   session id → `HsmError::AeadEnvelopeAuthFailed`.
//! * Envelope encrypted under a *different* session's `param_key`
//!   shipped through this session → `HsmError::AeadEnvelopeAuthFailed`.
//! * Plaintext that is not exactly `PSK_LEN` bytes → `HsmError::InvalidArg`.

#![cfg(feature = "emu")]

use azihsm_crypto::aead_envelope;
use azihsm_crypto::aead_envelope::AeadAlg;
use azihsm_crypto::AesKey;
use azihsm_crypto::Rng;
use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_tbor_test_helpers::build_psk_change_aad;
use azihsm_ddi_tbor_test_helpers::change_psk;
use azihsm_ddi_tbor_test_helpers::close_session;
use azihsm_ddi_tbor_test_helpers::encrypt_psk_envelope;
use azihsm_ddi_tbor_test_helpers::open_session;
use azihsm_ddi_tbor_test_helpers::open_session_init_with_options;
use azihsm_ddi_tbor_test_helpers::OpenSessionInitOptions;
use azihsm_ddi_tbor_test_helpers::SessionHandshake;
use azihsm_ddi_tbor_test_helpers::TborChangePskReq;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::SessionType;
use azihsm_fw_hsm_pal_traits::DEFAULT_PSK_CO;
use azihsm_fw_hsm_pal_traits::DEFAULT_PSK_CU;
use azihsm_fw_hsm_pal_traits::PSK_LEN;
use serial_test::serial;

use crate::integration::common::assertions::assert_fw_rejects;
use crate::integration::common::fixture::open_dev;

const CO: u8 = 0;
const CU: u8 = 1;

type Dev = <AzihsmDdi as Ddi>::Dev;

/// Distinct, non-default 32-byte PSK used by the happy-path tests.
const ROTATED_PSK: [u8; PSK_LEN] = [
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
    0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
];

fn try_close(dev: &Dev, session_id: u16) {
    let _ = close_session(dev, session_id);
}

fn default_psk_for(psk_id: u8) -> [u8; PSK_LEN] {
    match psk_id {
        CO => DEFAULT_PSK_CO,
        CU => DEFAULT_PSK_CU,
        _ => unreachable!("psk_id must be 0 or 1"),
    }
}

/// Open a session using `psk` (instead of the partition default),
/// rotate the slot back to `target_psk`, and close. Used to undo a
/// successful test-side rotation so the emulator's process-global
/// PSK state does not leak into subsequent tests.
fn rotate_psk(dev: &Dev, psk_id: u8, current_psk: &[u8], target_psk: &[u8]) {
    let session_type = match psk_id {
        CO => SessionType::Authenticated,
        _ => SessionType::PlainText,
    };
    let opts = OpenSessionInitOptions::new(psk_id, session_type).with_psk(current_psk);
    let pending = open_session_init_with_options(dev, opts)
        .expect("init under current PSK must succeed during rotate");
    let session =
        azihsm_ddi_tbor_test_helpers::open_session_finish(dev, pending).expect("finish rotate");
    change_psk(dev, &session, target_psk).expect("rotate change_psk");
    try_close(dev, session.session_id);
}

/// Build an AEAD-GCM envelope under `param_key` with a caller-controlled
/// AAD and plaintext. Negative-path tests use this to exercise FW
/// arms that reject mismatched AAD, wrong-length plaintexts,
/// envelopes encrypted under a different session's key, etc.
///
/// `aad.len()` must be 0 or a multiple of 32 (the AEAD-GCM AAD
/// granularity); for a host-side malformed-length test, prefer
/// shipping a *different* valid length (e.g. 64) so the host seal
/// succeeds and the FW gets to apply its own length check.
fn build_envelope(param_key: &AesKey, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut iv = [0u8; 12];
    Rng::rand_bytes(&mut iv).expect("rng iv");
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

/// Ship a raw `TborChangePskReq` and surface the FW error (or
/// success).
fn send_change_psk_raw(
    dev: &Dev,
    session: &SessionHandshake,
    envelope: Vec<u8>,
) -> azihsm_ddi_interface::DdiResult<()> {
    let req = TborChangePskReq {
        session_id: session.session_id,
        psk_envelope: envelope,
    };
    let mut cookie = None;
    let _: azihsm_ddi_tbor_types::TborChangePskResp = dev.exec_op_tbor(&req, &mut cookie)?;
    Ok(())
}

// ===========================================================================
// Happy paths
// ===========================================================================

#[test]
#[serial]
fn change_psk_happy_cu_emu() {
    let dev = open_dev();
    let session = open_session(&dev, CU, SessionType::PlainText).expect("open CU");
    change_psk(&dev, &session, &ROTATED_PSK).expect("CU rotate to ROTATED_PSK");
    try_close(&dev, session.session_id);

    // Prove the rotation took effect: a fresh open using the rotated
    // bytes must succeed.
    let opts = OpenSessionInitOptions::new(CU, SessionType::PlainText).with_psk(&ROTATED_PSK);
    let pending =
        open_session_init_with_options(&dev, opts).expect("reopen under rotated PSK must succeed");
    let resumed =
        azihsm_ddi_tbor_test_helpers::open_session_finish(&dev, pending).expect("finish reopen");
    try_close(&dev, resumed.session_id);

    // Restore default so we don't contaminate later tests.
    rotate_psk(&dev, CU, &ROTATED_PSK, &default_psk_for(CU));
}

#[test]
#[serial]
fn change_psk_happy_co_emu() {
    let dev = open_dev();
    let session = open_session(&dev, CO, SessionType::Authenticated).expect("open CO");
    change_psk(&dev, &session, &ROTATED_PSK).expect("CO rotate to ROTATED_PSK");
    try_close(&dev, session.session_id);

    let opts = OpenSessionInitOptions::new(CO, SessionType::Authenticated).with_psk(&ROTATED_PSK);
    let pending =
        open_session_init_with_options(&dev, opts).expect("reopen under rotated PSK must succeed");
    let resumed =
        azihsm_ddi_tbor_test_helpers::open_session_finish(&dev, pending).expect("finish reopen");
    try_close(&dev, resumed.session_id);

    rotate_psk(&dev, CO, &ROTATED_PSK, &default_psk_for(CO));
}

// ===========================================================================
// Reopen with old PSK fails after rotation
// ===========================================================================

#[test]
#[serial]
fn change_psk_reopen_with_old_psk_fails_emu() {
    let dev = open_dev();
    let session = open_session(&dev, CU, SessionType::PlainText).expect("open CU");
    change_psk(&dev, &session, &ROTATED_PSK).expect("rotate");
    try_close(&dev, session.session_id);

    // Reopening with the default PSK now fails: host-derived
    // `exported` diverges from FW's, so Phase-1 MAC verification
    // (or HPKE auth) fails. The helper surfaces this as
    // `DdiError::TborDecodeError` (host-side compare) — see the
    // `crypto.rs::verify_phase1_mac` arm. Either a host-side or
    // FW-side rejection is acceptable; we only need "must err".
    let result = open_session(&dev, CU, SessionType::PlainText);
    assert!(
        result.is_err(),
        "reopen with old default PSK must fail after rotation",
    );

    rotate_psk(&dev, CU, &ROTATED_PSK, &default_psk_for(CU));
}

// ===========================================================================
// One-shot enforcement
// ===========================================================================

#[test]
#[serial]
fn change_psk_second_attempt_same_session_fails_emu() {
    let dev = open_dev();
    let session = open_session(&dev, CU, SessionType::PlainText).expect("open CU");
    change_psk(&dev, &session, &ROTATED_PSK).expect("first rotate");

    // The session's PSK-change budget is now consumed. A second
    // ChangePsk on the same session must surface
    // `HsmError::InvalidPermissions`.
    let err = change_psk(&dev, &session, &default_psk_for(CU))
        .expect_err("second change_psk on same session must fail");
    assert_fw_rejects(&err, HsmError::InvalidPermissions);
    try_close(&dev, session.session_id);

    // The rotation in step 1 still took effect; restore default via
    // a fresh session.
    rotate_psk(&dev, CU, &ROTATED_PSK, &default_psk_for(CU));
}

// ===========================================================================
// Envelope tampering
// ===========================================================================

#[test]
#[serial]
fn change_psk_ciphertext_tampered_emu() {
    let dev = open_dev();
    let session = open_session(&dev, CU, SessionType::PlainText).expect("open CU");
    let mut envelope = encrypt_psk_envelope(&session, &ROTATED_PSK).expect("encrypt envelope");
    // Envelope layout: HEADER(4) ‖ IV(12) ‖ AAD(32) ‖ CT(32) ‖ TAG(16).
    // CT starts at byte 48; flip a byte in the middle of the ciphertext.
    let target = envelope.len() / 2;
    envelope[target] ^= 0x01;
    let err = send_change_psk_raw(&dev, &session, envelope)
        .expect_err("ciphertext bit-flip must fail AEAD tag");
    assert_fw_rejects(&err, HsmError::AeadEnvelopeAuthFailed);
    try_close(&dev, session.session_id);
}

#[test]
#[serial]
fn change_psk_aad_tampered_emu() {
    let dev = open_dev();
    let session = open_session(&dev, CU, SessionType::PlainText).expect("open CU");
    let mut envelope = encrypt_psk_envelope(&session, &ROTATED_PSK).expect("encrypt envelope");
    // AAD starts at offset HEADER(4) + IV(12) = 16.
    envelope[16] ^= 0x01;
    let err =
        send_change_psk_raw(&dev, &session, envelope).expect_err("AAD bit-flip must fail AEAD tag");
    assert_fw_rejects(&err, HsmError::AeadEnvelopeAuthFailed);
    try_close(&dev, session.session_id);
}

// ===========================================================================
// Empty envelope
// ===========================================================================

#[test]
#[serial]
fn change_psk_empty_envelope_emu() {
    let dev = open_dev();
    let session = open_session(&dev, CU, SessionType::PlainText).expect("open CU");
    let err = send_change_psk_raw(&dev, &session, Vec::new())
        .expect_err("empty envelope must be rejected");
    assert_fw_rejects(&err, HsmError::InvalidArg);
    try_close(&dev, session.session_id);
}

// ===========================================================================
// AAD-vs-request session-id mismatch
// ===========================================================================

#[test]
#[serial]
fn change_psk_wrong_session_id_in_aad_emu() {
    let dev = open_dev();
    let session = open_session(&dev, CU, SessionType::PlainText).expect("open CU");
    // Build an envelope whose AAD encodes a different (bogus)
    // session id. AEAD-GCM tag verifies (the FW recomputes the tag
    // over *these* bytes), but the FW then constant-compares the AAD
    // against `build_psk_change_aad(req.session_id)` and rejects.
    let bogus_aad = build_psk_change_aad(session.session_id ^ 0x1234);
    let envelope = build_envelope(&session.param_key, &bogus_aad, &ROTATED_PSK);
    let err = send_change_psk_raw(&dev, &session, envelope)
        .expect_err("AAD encoding the wrong session id must be rejected");
    assert_fw_rejects(&err, HsmError::AeadEnvelopeAuthFailed);
    try_close(&dev, session.session_id);
}

// ===========================================================================
// Envelope built under a *different* session's param_key
// ===========================================================================

#[test]
#[serial]
fn change_psk_envelope_from_other_session_emu() {
    let dev = open_dev();
    let session_a = open_session(&dev, CU, SessionType::PlainText).expect("open A");
    let session_b = open_session(&dev, CU, SessionType::PlainText).expect("open B");
    // Encrypt under A's param_key but ship through B (with B's
    // session id in the request). FW uses B's param_key to verify
    // the AEAD-GCM tag → mismatch.
    let aad_for_b = build_psk_change_aad(session_b.session_id);
    let envelope = build_envelope(&session_a.param_key, &aad_for_b, &ROTATED_PSK);
    let err = send_change_psk_raw(&dev, &session_b, envelope)
        .expect_err("envelope under wrong param_key must fail HMAC");
    assert_fw_rejects(&err, HsmError::AeadEnvelopeAuthFailed);
    try_close(&dev, session_a.session_id);
    try_close(&dev, session_b.session_id);
}

// ===========================================================================
// Wrong plaintext length
// ===========================================================================

#[test]
#[serial]
fn change_psk_short_plaintext_emu() {
    let dev = open_dev();
    let session = open_session(&dev, CU, SessionType::PlainText).expect("open CU");
    // 31 bytes — one short of PSK_LEN.
    let short_psk = vec![0xCDu8; PSK_LEN - 1];
    let aad = build_psk_change_aad(session.session_id);
    let envelope = build_envelope(&session.param_key, &aad, &short_psk);
    let err = send_change_psk_raw(&dev, &session, envelope)
        .expect_err("plaintext shorter than PSK_LEN must be rejected");
    assert_fw_rejects(&err, HsmError::InvalidArg);
    try_close(&dev, session.session_id);
}

#[test]
#[serial]
fn change_psk_long_plaintext_emu() {
    let dev = open_dev();
    let session = open_session(&dev, CU, SessionType::PlainText).expect("open CU");
    // 33 bytes — one over PSK_LEN.
    let long_psk = vec![0xCDu8; PSK_LEN + 1];
    let aad = build_psk_change_aad(session.session_id);
    let envelope = build_envelope(&session.param_key, &aad, &long_psk);
    let err = send_change_psk_raw(&dev, &session, envelope)
        .expect_err("plaintext longer than PSK_LEN must be rejected");
    assert_fw_rejects(&err, HsmError::InvalidArg);
    try_close(&dev, session.session_id);
}

// ===========================================================================
// Wrong AAD length (64 bytes — valid AEAD granularity but FW expects exactly
// PSK_CHANGE_AAD_LEN = 32 bytes)
// ===========================================================================

#[test]
#[serial]
fn change_psk_wrong_aad_length_emu() {
    let dev = open_dev();
    let session = open_session(&dev, CU, SessionType::PlainText).expect("open CU");
    // 64 bytes of arbitrary AAD (valid AEAD granularity); AEAD-open
    // succeeds but FW's `view.aad.len() != PSK_CHANGE_AAD_LEN` check
    // rejects with InvalidArg before the AAD comparison.
    let long_aad = vec![0u8; 64];
    let envelope = build_envelope(&session.param_key, &long_aad, &ROTATED_PSK);
    let err = send_change_psk_raw(&dev, &session, envelope)
        .expect_err("AAD whose length != PSK_CHANGE_AAD_LEN must be rejected");
    assert_fw_rejects(&err, HsmError::InvalidArg);
    try_close(&dev, session.session_id);
}
