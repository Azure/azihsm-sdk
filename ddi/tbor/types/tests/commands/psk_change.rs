// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `PskChange` command.
//!
//! Backend is selected at compile time by
//! [`azihsm_ddi::AzihsmDdi::default`]; cross-test isolation comes
//! from the factory-reset performed by [`TestCtx::new`], and live
//! sessions close on `Drop` via [`SessionGuard`].
//!
//! Coverage:
//! * Happy paths (CO + CU), with an explicit reopen under the
//!   rotated PSK to prove the rotation took effect.
//! * Reopen with the old (default) PSK fails after rotation.
//! * One-shot enforcement: a second `PskChange` on the same session
//!   surfaces `TborStatus::InvalidPermissions`.
//! * Envelope tampering (ciphertext bit-flip, AAD bit-flip) →
//!   `TborStatus::AeadEnvelopeAuthFailed`.
//! * AAD that encodes a different session id → same auth failure.
//! * Envelope encrypted under a different session's `param_key` →
//!   same auth failure.
//! * Wrong envelope length (empty, wrong plaintext length, wrong
//!   AAD length) → `TborStatus::TborInvalidFixedLength`. The
//!   derive-generated schema decoder in `azihsm_fw_ddi_tbor_types`
//!   trips the `#[tbor(buffer, len = 100)]` check on both emu and
//!   hw; the FW response preserves the exact structural fault via
//!   the `HsmError::Tbor*` → `HsmErr::Tbor*` mapping.
//! * Rotation to a well-known default PSK is rejected with
//!   `TborStatus::InvalidArg` (the core `PskChange` handler enforces
//!   this, so it holds on both emu and hw).

use azihsm_crypto::aead_envelope;
use azihsm_crypto::aead_envelope::AeadAlg;
use azihsm_crypto::AesKey;
use azihsm_crypto::Rng;
use azihsm_ddi_tbor_test_harness::assertions::assert_fw_rejects;
use azihsm_ddi_tbor_test_harness::build_psk_change_aad;
use azihsm_ddi_tbor_test_harness::encrypt_psk_envelope;
use azihsm_ddi_tbor_test_harness::SessionOpenInitOptions;
use azihsm_ddi_tbor_test_harness::TborPskChangeReq;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::CO_PSK_ID as CO;
use azihsm_ddi_tbor_test_harness::CU_PSK_ID as CU;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::DEFAULT_PSK_CO;
use azihsm_ddi_tbor_types::DEFAULT_PSK_CU;
use azihsm_ddi_tbor_types::PSK_LEN;

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
    let session = ctx
        .open_session(role, sty)
        .expect("open_session must succeed");
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
fn psk_change_happy_cu() {
    run_psk_change_happy(CU, SessionType::PlainText);
}

#[test]
fn psk_change_happy_co() {
    run_psk_change_happy(CO, SessionType::Authenticated);
}

// ===========================================================================
// Reopen with old PSK fails after rotation
// ===========================================================================

/// Verifies the original CU PSK cannot authenticate after a successful rotation.
#[test]
fn psk_change_reopen_with_old_psk_fails() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open_session must succeed");
    ctx.psk_change(session.handshake(), &ROTATED_PSK)
        .expect("rotate");
    session.close().expect("close rotating session");

    // Reopening with the default PSK now fails: host-derived
    // `exported` diverges from FW's, so Phase-1 MAC verification
    // (or HPKE auth) fails. Either a host-side or FW-side
    // rejection is acceptable; we only need "must err".
    let result = ctx.open_session(CU, SessionType::PlainText);
    assert!(
        result.is_err(),
        "reopen with old default PSK must fail after rotation",
    );
}

// ===========================================================================
// One-shot enforcement
// ===========================================================================

/// Verifies a second CU PSK change on the same session is denied.
#[test]
fn psk_change_second_attempt_same_session_fails() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open_session must succeed");
    ctx.psk_change(session.handshake(), &ROTATED_PSK)
        .expect("first rotate");

    // The session's PSK-change budget is now consumed. A second
    // PskChange on the same session must surface
    // `TborStatus::InvalidPermissions`.
    let err = ctx
        .psk_change(session.handshake(), &DEFAULT_PSK_CU)
        .expect_err("second psk_change on same session must fail");
    azihsm_ddi_tbor_test_harness::assertions::assert_fw_rejects(
        &err,
        TborStatus::InvalidPermissions,
    );
}

// ===========================================================================
// Envelope tampering
//
// Both arms (ciphertext bit-flip, AAD bit-flip) must surface the same
// AEAD failure status. Layout reminder:
// HEADER(4) ‖ IV(12) ‖ AAD(32) ‖ CT(32) ‖ TAG(16). AAD starts at
// offset 16; CT starts at offset 48.
// ===========================================================================

/// Verifies tampering with envelope ciphertext or AAD causes authentication failure.
#[test]
fn psk_change_envelope_tampered() {
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
        let session = ctx
            .open_session(CU, SessionType::PlainText)
            .expect("open_session must succeed");
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
        azihsm_ddi_tbor_test_harness::assertions::assert_fw_rejects(
            &err,
            TborStatus::AeadEnvelopeAuthFailed,
        );
    }
}

// ===========================================================================
// Empty envelope
// ===========================================================================

/// Verifies an empty PSK envelope is rejected.
#[test]
fn psk_change_empty_envelope() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open_session must succeed");
    let req = TborPskChangeReq {
        session_id: session.session_id(),
        psk_envelope: Vec::new(),
    };
    // FW schema pins `psk_envelope` to PSK_CHANGE_ENVELOPE_LEN (100 B);
    // the derive-generated decoder rejects a wrong length with
    // `TborInvalidFixedLength` before the handler runs.
    ctx.expect_fw_reject(&req, TborStatus::TborInvalidFixedLength);
}

// ===========================================================================
// AAD-vs-request session-id mismatch
// ===========================================================================

/// Verifies AAD bound to a different session ID is rejected.
#[test]
fn psk_change_wrong_session_id_in_aad() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open_session must succeed");
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
// Envelope built under a different session's param_key
//
// Encrypt under session A's param_key but ship the request through
// session B (with B's id in both header and AAD). FW verifies with
// B's key and the tag fails. Session B is opened on a **second ctx**
// (via `TestCtx::new_with_path(ctx.path())`) so on hw the crafted
// request lands on B's fd — `AZIHSM_MAX_SESSIONS_PER_FD = 1` requires
// the second concurrent session to live on its own fd.
// ===========================================================================

/// Verifies an envelope encrypted with another session key is rejected.
#[test]
fn psk_change_envelope_from_other_session() {
    let ctx_a = TestCtx::new();
    let session_a = ctx_a
        .open_session(CU, SessionType::PlainText)
        .expect("open_session must succeed");

    let ctx_b = TestCtx::new_with_path(ctx_a.path());
    let session_b = ctx_b
        .open_session(CU, SessionType::PlainText)
        .expect("open session B on extra dev");

    let aad_for_b = build_psk_change_aad(session_b.session_id());
    let envelope = build_envelope(&session_a.handshake().param_key, &aad_for_b, &ROTATED_PSK);
    let req = TborPskChangeReq {
        session_id: session_b.session_id(),
        psk_envelope: envelope,
    };
    let err = ctx_b
        .tbor(&req)
        .expect_err("PskChange envelope from session A must be rejected on session B");
    azihsm_ddi_tbor_test_harness::assertions::assert_fw_rejects(
        &err,
        TborStatus::AeadEnvelopeAuthFailed,
    );

    // Both sessions close on drop via their SessionGuards.
}

// ===========================================================================
// Wrong plaintext length
// ===========================================================================

/// Verifies PSK plaintext lengths outside the required size are rejected.
#[test]
fn psk_change_wrong_plaintext_length() {
    let ctx = TestCtx::new();
    // PSK_LEN ± 1: shortest excursions either side of the canonical
    // length. A wrong plaintext length yields a wrong *envelope* length
    // (ciphertext tracks plaintext for GCM), so the FW schema's fixed
    // PSK_CHANGE_ENVELOPE_LEN (100 B) rejects both with
    // `TborInvalidFixedLength` in the derive-generated decoder.
    for len in [PSK_LEN - 1, PSK_LEN + 1] {
        let session = ctx
            .open_session(CU, SessionType::PlainText)
            .expect("open_session must succeed");
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
        azihsm_ddi_tbor_test_harness::assertions::assert_fw_rejects(
            &err,
            TborStatus::TborInvalidFixedLength,
        );
    }
}

// ===========================================================================
// Wrong AAD length (64 bytes — valid AEAD granularity but produces a
// wrong-length envelope the FW schema rejects at decode)
// ===========================================================================

/// Verifies an envelope containing incorrectly sized AAD is rejected.
#[test]
fn psk_change_wrong_aad_length() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open_session must succeed");
    // 64 bytes of arbitrary AAD (valid AEAD granularity) inflates the
    // envelope past PSK_CHANGE_ENVELOPE_LEN (100 B); the derive-
    // generated decoder rejects with `TborInvalidFixedLength`.
    let long_aad = vec![0u8; 64];
    let envelope = build_envelope(&session.handshake().param_key, &long_aad, &ROTATED_PSK);
    let req = TborPskChangeReq {
        session_id: session.session_id(),
        psk_envelope: envelope,
    };
    ctx.expect_fw_reject(&req, TborStatus::TborInvalidFixedLength);
}

// ===========================================================================
// Hardware-only: rotation to a default PSK must be rejected
//
// Rotating a partition's PSK back to `DEFAULT_PSK_CO` / `DEFAULT_PSK_CU`
// would let anyone with default-PSK knowledge re-establish a session,
// defeating the point of rotation. FW must reject with
// `TborStatus::InvalidArg` regardless of which role requests it and
// which default value is targeted (a CU must not be able to push the
// CO PSK back to default either).
//
// Hw-only: the reject lives in the silicon firmware, not in the
// in-tree Rust FW that emu runs. Emu accepts the rotation.
// ===========================================================================

fn run_psk_change_to_default_rejected(role: u8, sty: SessionType, new_psk: &[u8; PSK_LEN]) {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(role, sty)
        .expect("open_session must succeed");
    let err = ctx
        .psk_change(session.handshake(), new_psk)
        .expect_err("psk_change to a default PSK must be rejected");
    assert_fw_rejects(&err, TborStatus::InvalidArg);
}

/// Verifies CU cannot rotate its PSK to the default CU PSK.
#[test]
fn psk_change_cu_to_default_cu_rejected() {
    run_psk_change_to_default_rejected(CU, SessionType::PlainText, &DEFAULT_PSK_CU);
}

/// Verifies CU cannot rotate its PSK to the default CO PSK.
#[test]
fn psk_change_cu_to_default_co_rejected() {
    run_psk_change_to_default_rejected(CU, SessionType::PlainText, &DEFAULT_PSK_CO);
}

/// Verifies CO cannot rotate its PSK to the default CO PSK.
#[test]
fn psk_change_co_to_default_co_rejected() {
    run_psk_change_to_default_rejected(CO, SessionType::Authenticated, &DEFAULT_PSK_CO);
}

/// Verifies CU cannot rotate its PSK to the default CO PSK.
#[test]
fn psk_change_co_to_default_cu_rejected() {
    run_psk_change_to_default_rejected(CO, SessionType::Authenticated, &DEFAULT_PSK_CU);
}

/// Verifies a modified AES-GCM authentication tag is rejected.
#[test]
fn psk_change_tampered_auth_tag_rejected() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open CU session");

    let mut envelope =
        encrypt_psk_envelope(session.handshake(), &ROTATED_PSK).expect("encrypt PSK envelope");

    // The authentication tag occupies the last 16 bytes.
    let last = envelope.len() - 1;
    envelope[last] ^= 0x01;

    let req = TborPskChangeReq {
        session_id: session.session_id(),
        psk_envelope: envelope,
    };

    ctx.expect_fw_reject(&req, TborStatus::AeadEnvelopeAuthFailed);
}

/// Verifies a modified AES-GCM initialization vector is rejected.
#[test]
fn psk_change_tampered_iv_rejected() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open CU session");

    let mut envelope =
        encrypt_psk_envelope(session.handshake(), &ROTATED_PSK).expect("encrypt PSK envelope");

    // Envelope layout:
    // HEADER(4) | IV(12) | AAD(32) | CT(32) | TAG(16)
    // Byte 4 is the first IV byte.
    envelope[4] ^= 0x01;

    let req = TborPskChangeReq {
        session_id: session.session_id(),
        psk_envelope: envelope,
    };

    ctx.expect_fw_reject(&req, TborStatus::AeadEnvelopeAuthFailed);
}

/// Verifies truncated PSK envelopes are rejected at multiple length boundaries.
#[test]
fn psk_change_truncated_envelope_rejected() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open CU session");

    let valid =
        encrypt_psk_envelope(session.handshake(), &ROTATED_PSK).expect("encrypt PSK envelope");

    assert_eq!(valid.len(), 100);

    for len in [1usize, 4, 15, 16, 47, 48, 83, 84, 99] {
        let req = TborPskChangeReq {
            session_id: session.session_id(),
            psk_envelope: valid[..len].to_vec(),
        };

        ctx.expect_fw_reject(&req, TborStatus::TborInvalidFixedLength);
    }
}

/// Verifies PSK envelopes with extra trailing bytes are rejected.
#[test]
fn psk_change_oversized_envelope_rejected() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open CU session");

    let valid =
        encrypt_psk_envelope(session.handshake(), &ROTATED_PSK).expect("encrypt PSK envelope");

    assert_eq!(valid.len(), 100);

    for extra in [1usize, 2, 16, 32, 100] {
        let mut envelope = valid.clone();
        envelope.extend(vec![0xAA; extra]);

        let req = TborPskChangeReq {
            session_id: session.session_id(),
            psk_envelope: envelope,
        };

        ctx.expect_fw_reject(&req, TborStatus::TborInvalidFixedLength);
    }
}

/// Verifies a second CO PSK change on the same session is denied.
#[test]
fn psk_change_co_second_attempt_same_session_fails() {
    let ctx = TestCtx::new();

    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open CO session");

    ctx.psk_change(session.handshake(), &ROTATED_PSK)
        .expect("first CO PSK rotation");

    // Even a request containing a valid new PSK must fail.
    let second_psk = [0x5Au8; PSK_LEN];

    let err = ctx
        .psk_change(session.handshake(), &second_psk)
        .expect_err("second CO rotation must fail");

    assert_fw_rejects(&err, TborStatus::InvalidPermissions);
}

/// Verifies the rotated CU PSK authenticates across multiple fresh sessions.
#[test]
fn psk_change_rotated_psk_repeated_reopen() {
    let ctx = TestCtx::new();

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open original CU session");

    ctx.psk_change(session.handshake(), &ROTATED_PSK)
        .expect("rotate CU PSK");

    session.close().expect("close original CU session");

    // Check that the rotated key is persistent across
    // multiple independent session handshakes.
    for _ in 0..3 {
        let opts = SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&ROTATED_PSK);

        let pending = ctx
            .session_open_init_with_options(opts)
            .expect("init using rotated PSK");

        let resumed = ctx
            .session_open_finish(pending)
            .expect("finish using rotated PSK");

        ctx.session_close(resumed.session_id)
            .expect("failed to close reopened session");
    }
}

/// Verifies authenticated envelopes with modified AAD content are rejected.
#[test]
fn psk_change_invalid_aad_content_rejected() {
    let ctx = TestCtx::new();

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open CU session");

    let correct_aad = build_psk_change_aad(session.session_id());

    assert_eq!(correct_aad.len(), 32);

    for offset in [0usize, 8, 16, 31] {
        let mut wrong_aad = correct_aad;
        wrong_aad[offset] ^= 0x01;

        // Re-encrypt with the modified AAD so the
        // AES-GCM authentication tag remains valid.
        let envelope = build_envelope(&session.handshake().param_key, &wrong_aad, &ROTATED_PSK);

        let req = TborPskChangeReq {
            session_id: session.session_id(),
            psk_envelope: envelope,
        };

        let err = ctx
            .tbor(&req)
            .expect_err(&format!("modified AAD at offset {offset} must be rejected"));

        println!("AAD mutation at offset {offset} rejected: {err:?}");
    }
}

/// Verifies the rotated CO PSK works while the original CO PSK is rejected.
#[test]
fn psk_change_co_reopen_with_old_psk_fails() {
    let ctx = TestCtx::new();

    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open CO session");

    ctx.psk_change(session.handshake(), &ROTATED_PSK)
        .expect("rotate CO PSK");

    session.close().expect("close rotating CO session");

    // First prove that the rotated PSK works.
    let opts = SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&ROTATED_PSK);

    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("init with rotated CO PSK");

    let resumed = ctx
        .session_open_finish(pending)
        .expect("finish with rotated CO PSK");

    ctx.session_close(resumed.session_id)
        .expect("close reopened CO session");

    // Finally verify that the original default
    // CO PSK can no longer authenticate.
    let result = ctx.open_session(CO, SessionType::Authenticated);

    assert!(
        result.is_err(),
        "old default CO PSK must fail after rotation"
    );
}

/// Verifies a CU session rejects another PSK change after an invalid envelope.
#[test]
fn psk_change_failed_envelope_then_valid_rotation() {
    let ctx = TestCtx::new();

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open CU session");

    // Build a corrupted envelope.
    let mut bad_envelope =
        encrypt_psk_envelope(session.handshake(), &ROTATED_PSK).expect("encrypt envelope");

    let last = bad_envelope.len() - 1;
    bad_envelope[last] ^= 0x80;

    let bad_req = TborPskChangeReq {
        session_id: session.session_id(),
        psk_envelope: bad_envelope,
    };

    // First request must fail authentication.
    ctx.expect_fw_reject(&bad_req, TborStatus::AeadEnvelopeAuthFailed);

    // Current observed FW behavior: a subsequent
    // PskChange on this session is also rejected.
    let err = ctx
        .psk_change(session.handshake(), &ROTATED_PSK)
        .expect_err("second rotation request after failed envelope must fail");

    println!("PskChange retry after authentication failure: {err:?}");
}

/// Verifies rotating the CU PSK does not alter CO authentication.
#[test]
fn psk_change_cu_rotation_does_not_affect_co() {
    let ctx = TestCtx::new();

    // Rotate the CU PSK.
    let cu = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open CU session");

    ctx.psk_change(cu.handshake(), &ROTATED_PSK)
        .expect("rotate CU PSK");

    cu.close().expect("close CU session");

    // CO must still authenticate with its original PSK.
    let co = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("CU rotation must not affect CO PSK");

    co.close().expect("close CO session");

    // CU must authenticate with its new PSK.
    let opts = SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&ROTATED_PSK);

    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("open with rotated CU PSK");

    let resumed = ctx
        .session_open_finish(pending)
        .expect("finish rotated CU session");

    ctx.session_close(resumed.session_id)
        .expect("close reopened CU session");
}

/// Verifies a PSK change targeting an invalid CU session ID is rejected.
#[test]
fn psk_change_cu_invalid_session_id_rejected() {
    let ctx = TestCtx::new();

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open CU session");

    let envelope =
        encrypt_psk_envelope(session.handshake(), &ROTATED_PSK).expect("encrypt envelope");

    // Change the request session ID without changing
    // the envelope or the active session.
    let invalid_id = session.session_id() ^ 0x1234;

    let req = TborPskChangeReq {
        session_id: invalid_id,
        psk_envelope: envelope,
    };

    let err = ctx
        .tbor(&req)
        .expect_err("invalid session ID must be rejected");

    println!("Invalid session ID rejected: {err:?}");
}

/// Verifies a rejected CU PSK change leaves the original PSK usable.
#[test]
fn psk_change_cu_rejected_rotation_preserves_psk() {
    let ctx = TestCtx::new();

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open CU session");

    let mut envelope =
        encrypt_psk_envelope(session.handshake(), &ROTATED_PSK).expect("encrypt envelope");

    // Corrupt the authentication tag.
    let last = envelope.len() - 1;
    envelope[last] ^= 0x01;

    let req = TborPskChangeReq {
        session_id: session.session_id(),
        psk_envelope: envelope,
    };

    ctx.expect_fw_reject(&req, TborStatus::AeadEnvelopeAuthFailed);

    session.close().expect("close CU session");

    // The failed operation must not update stored PSK.
    let reopened = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("old CU PSK should remain valid");

    reopened.close().expect("close reopened CU session");
}
