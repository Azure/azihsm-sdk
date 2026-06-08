// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `OpenSessionInit` /
//! `OpenSessionFinish` two-phase session handshake.
//!
//! Cross-test isolation comes from `open_dev`'s factory-reset; the
//! [`TEST_LOCK`](crate::harness::fixture) held by every [`TestCtx`]
//! serialises access to the process-global emulator. Happy-path
//! sessions are owned by a [`SessionGuard`](crate::harness::SessionGuard)
//! that closes on `Drop`; negative-path tests intercept the handshake
//! through [`TestCtx::dev`].
//!
//! Coverage:
//! * Happy-path: CO + Authenticated, CU + PlainText (smoke).
//! * Role/type mismatches: CO + PlainText, CU + Authenticated
//!   (both must surface as `TborStatus::InvalidSessionType`).
//! * Invalid PSK id and invalid `session_type` byte at the parse stage.
//! * Phase-2 MAC tampering → `TborStatus::SessionAuthFailure`.
//! * Phase-2 `seed_envelope` tampering → `TborStatus::SessionAuthFailure`.
//! * `OpenSessionFinish` against an unknown session id, and a
//!   second finish against an already-completed slot.
//! * Multiple concurrent sessions return distinct session ids.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborOpenSessionFinishReq;
use azihsm_ddi_tbor_types::TborOpenSessionInitReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::PK_INIT_LEN;
use azihsm_ddi_tbor_types::SEED_ENVELOPE_LEN;
use azihsm_ddi_tbor_types::SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256;

use crate::harness::build_mac_fin;
use crate::harness::TestCtx;

const CO: u8 = 0;
const CU: u8 = 1;

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

#[test]
fn open_session_co_authenticated_happy_emu() {
    let ctx = TestCtx::new();
    let session = ctx.open_session(CO, SessionType::Authenticated);
    let h = session.handshake();
    assert_eq!(h.psk_id, CO);
    assert!(h.session_type.is_authenticated());
    assert!(
        !h.bmk_session.is_empty(),
        "FW must return a non-empty bmk_session envelope",
    );
    // Authenticated sessions: host can re-derive MAC keys from
    // `exported`; both should be 48 bytes.
    let tx = h.derive_mac_tx_key().expect("derive mac tx key");
    let rx = h.derive_mac_rx_key().expect("derive mac rx key");
    assert_eq!(tx.len(), 48);
    assert_eq!(rx.len(), 48);
    assert_ne!(tx, rx, "mac tx and rx keys must differ");
}

#[test]
fn open_session_cu_plaintext_happy_emu() {
    let ctx = TestCtx::new();
    let session = ctx.open_session(CU, SessionType::PlainText);
    let h = session.handshake();
    assert_eq!(h.psk_id, CU);
    assert!(!h.session_type.is_authenticated());
}

// ---------------------------------------------------------------------------
// Role / type mismatches
// ---------------------------------------------------------------------------

#[test]
fn open_session_co_plaintext_rejected_emu() {
    let ctx = TestCtx::new();
    let err = ctx
        .open_session_init(CO, SessionType::PlainText)
        .expect_err("CO + PlainText is not a permitted pairing");
    crate::harness::assertions::assert_fw_rejects(&err, TborStatus::InvalidSessionType);
}

#[test]
fn open_session_cu_authenticated_rejected_emu() {
    let ctx = TestCtx::new();
    let err = ctx
        .open_session_init(CU, SessionType::Authenticated)
        .expect_err("CU + Authenticated is not a permitted pairing");
    crate::harness::assertions::assert_fw_rejects(&err, TborStatus::InvalidSessionType);
}

// ---------------------------------------------------------------------------
// Parse-stage rejections
// ---------------------------------------------------------------------------

#[test]
fn open_session_invalid_psk_id_emu() {
    // Only `0` (CO) and `1` (CU) are valid `psk_id` values. Spot-check
    // a small set of out-of-range values covering: the smallest invalid
    // value (`2`), a mid-range value (`0x7F`), and the all-ones byte
    // (`0xFF`). All must surface `InvalidPskId` from the FW
    // dispatcher's `psk_id`-validation arm before any HPKE work.
    let ctx = TestCtx::new();
    for bad in [2u8, 0x7F, 0xFF] {
        let err = ctx
            .open_session_init(bad, SessionType::PlainText)
            .expect_err(&format!("psk_id {bad} must be rejected"));
        crate::harness::assertions::assert_fw_rejects(&err, TborStatus::InvalidPskId);
    }
}

#[test]
fn open_session_invalid_session_type_byte_emu() {
    // Bypass the typed `SessionType` enum to ship an out-of-range
    // byte directly. The FW `SessionType::from_u8` must reject.
    let ctx = TestCtx::new();
    let req = TborOpenSessionInitReq {
        psk_id: CU,
        session_type: 42,
        suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
        pk_init: [0x04u8; PK_INIT_LEN],
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidSessionType);
}

// ---------------------------------------------------------------------------
// Unsupported suite_id (negative test)
// ---------------------------------------------------------------------------

#[test]
fn open_session_unsupported_suite_id_emu() {
    // Any byte other than 0x01 must be rejected by `SessionSuite::from_u8`
    // before any HPKE work happens.  Spot-check three boundary values
    // covering "reserved-but-not-yet-implemented" (0x02), zero (0x00),
    // and the all-ones byte (0xFF).
    let ctx = TestCtx::new();
    for bad in [0x00u8, 0x02, 0xff] {
        let req = TborOpenSessionInitReq {
            psk_id: CU,
            session_type: SessionType::PlainText.to_u8(),
            suite_id: bad,
            pk_init: [0x04u8; PK_INIT_LEN],
        };
        ctx.expect_fw_reject(&req, TborStatus::UnsupportedSessionSuite);
    }
}

// ---------------------------------------------------------------------------
// Phase-2 MAC tampering
// ---------------------------------------------------------------------------

#[test]
fn open_session_finish_mac_tampered_emu() {
    let ctx = TestCtx::new();
    let pending = ctx
        .open_session_init(CU, SessionType::PlainText)
        .expect("phase 1 must succeed");
    let mut mac_fin = build_mac_fin(&pending).expect("build phase-2 mac");
    mac_fin[0] ^= 0x01;
    let err = ctx
        .open_session_finish_with_mac(pending, mac_fin)
        .expect_err("tampered mac_fin must be rejected by the FW");
    crate::harness::assertions::assert_fw_rejects(&err, TborStatus::SessionAuthFailure);
    // FW destroys the pending slot on MAC mismatch.
}

// ---------------------------------------------------------------------------
// Finish-side error paths
// ---------------------------------------------------------------------------

#[test]
fn open_session_finish_unknown_session_id_emu() {
    // Pick a session id that cannot possibly correspond to a live
    // pending slot. The FW pre-check fails to load the blob.
    let ctx = TestCtx::new();
    let req = TborOpenSessionFinishReq {
        session_id: 0xFFFF,
        mac_fin: [0u8; 48],
        seed_envelope: [0u8; SEED_ENVELOPE_LEN],
    };
    let err = ctx
        .tbor(&req)
        .expect_err("finish against unknown session_id must fail");
    assert!(
        matches!(err, azihsm_ddi_interface::DdiError::DdiError(_)),
        "expected FW-side rejection, got {err:?}",
    );
}

#[test]
fn open_session_double_finish_emu() {
    let ctx = TestCtx::new();
    let session = ctx.open_session(CU, SessionType::PlainText);
    // Replay the finish: pending slot is gone, FW must refuse.
    let req = TborOpenSessionFinishReq {
        session_id: session.session_id(),
        mac_fin: [0u8; 48],
        seed_envelope: [0u8; SEED_ENVELOPE_LEN],
    };
    let err = ctx
        .tbor(&req)
        .expect_err("second finish against the same slot must fail");
    assert!(
        matches!(err, azihsm_ddi_interface::DdiError::DdiError(_)),
        "expected FW-side rejection, got {err:?}",
    );
}

// ---------------------------------------------------------------------------
// Phase-2 seed_envelope tampering
// ---------------------------------------------------------------------------

#[test]
fn open_session_finish_seed_envelope_tampered_emu() {
    // Build a finish request by hand so we can corrupt the seed_envelope
    // ciphertext byte after Phase-1 succeeds but before shipping it.
    let ctx = TestCtx::new();
    let pending = ctx
        .open_session_init(CU, SessionType::PlainText)
        .expect("phase 1 must succeed");
    let session_id = pending.session_id;
    let mac_fin = build_mac_fin(&pending).expect("build phase-2 mac");

    // Ship a syntactically-valid but cryptographically-bogus envelope:
    // "AEAD" magic + correct alg/aad_len framing but all-zero IV / CT /
    // tag. The FW's AEAD-open must fail and destroy the slot.
    let mut seed_envelope = [0u8; SEED_ENVELOPE_LEN];
    seed_envelope[0..4].copy_from_slice(b"AEAD");
    seed_envelope[4] = 0x03; // AeadAlg::AesGcm256

    let req = TborOpenSessionFinishReq {
        session_id,
        mac_fin,
        seed_envelope,
    };
    ctx.expect_fw_reject(&req, TborStatus::SessionAuthFailure);
}

// ---------------------------------------------------------------------------
// Multiple concurrent sessions
// ---------------------------------------------------------------------------

#[test]
fn open_session_multiple_concurrent_emu() {
    let ctx = TestCtx::new();
    let a = ctx.open_session(CU, SessionType::PlainText);
    let b = ctx.open_session(CU, SessionType::PlainText);
    assert_ne!(
        a.session_id(),
        b.session_id(),
        "concurrent sessions must have distinct ids",
    );
}
