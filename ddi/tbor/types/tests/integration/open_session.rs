// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Phase 4 integration tests for the TBOR `OpenSessionInit` /
//! `OpenSessionFinish` two-phase session handshake.
//!
//! Each test runs against the `emu` backend, which exercises the real
//! FW handler stack end-to-end. Tests are serialised via
//! [`serial_test::serial`] because the emulator's `StdHsm` is
//! process-global and session-table state is shared across handles.
//!
//! Coverage:
//! * Happy-path: CO + Authenticated, CU + PlainText (smoke).
//! * Role/type mismatches: CO + PlainText, CU + Authenticated
//!   (both must surface as `HsmError::InvalidSessionType`).
//! * Invalid PSK id and invalid `session_type` byte at the parse stage.
//! * Phase-2 MAC tampering → `HsmError::SessionAuthFailure`.
//! * Phase-2 `seed_envelope` tampering → `HsmError::SessionAuthFailure`.
//! * `OpenSessionFinish` against an unknown session id, and a
//!   second finish against an already-completed slot.
//! * Multiple concurrent sessions return distinct session ids.

#![cfg(feature = "emu")]

use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_tbor_test_helpers::build_mac_fin;
use azihsm_ddi_tbor_test_helpers::close_session;
use azihsm_ddi_tbor_test_helpers::open_session;
use azihsm_ddi_tbor_test_helpers::open_session_finish_with_mac;
use azihsm_ddi_tbor_test_helpers::open_session_init;
use azihsm_ddi_tbor_types::TborOpenSessionFinishReq;
use azihsm_ddi_tbor_types::TborOpenSessionInitReq;
use azihsm_ddi_tbor_types::PK_INIT_LEN;
use azihsm_ddi_tbor_types::SEED_ENVELOPE_LEN;
use azihsm_ddi_tbor_types::SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::SessionType;
use serial_test::serial;

use crate::integration::common::assertions::assert_fw_rejects;
use crate::integration::common::fixture::open_dev;

const CO: u8 = 0;
const CU: u8 = 1;

/// Best-effort teardown so subsequent tests start from a clean session
/// table. The FW close handler is idempotent over already-closed ids,
/// but unknown ids will return an error — we swallow it.
fn try_close(dev: &<azihsm_ddi::AzihsmDdi as azihsm_ddi_interface::Ddi>::Dev, session_id: u16) {
    let _ = close_session(dev, session_id);
}

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn open_session_co_authenticated_happy_emu() {
    let dev = open_dev();
    let session = open_session(&dev, CO, SessionType::Authenticated)
        .expect("CO + Authenticated must complete the full handshake");
    assert_eq!(session.psk_id, CO);
    assert!(session.session_type.is_authenticated());
    assert!(
        !session.bmk_session.is_empty(),
        "FW must return a non-empty bmk_session envelope",
    );
    // Authenticated sessions: host can re-derive MAC keys from
    // `exported`; both should be 48 bytes.
    let tx = session.derive_mac_tx_key().expect("derive mac tx key");
    let rx = session.derive_mac_rx_key().expect("derive mac rx key");
    assert_eq!(tx.len(), 48);
    assert_eq!(rx.len(), 48);
    assert_ne!(tx, rx, "mac tx and rx keys must differ");
    try_close(&dev, session.session_id);
}

#[test]
#[serial]
fn open_session_cu_plaintext_happy_emu() {
    let dev = open_dev();
    let session = open_session(&dev, CU, SessionType::PlainText)
        .expect("CU + PlainText must complete the full handshake");
    assert_eq!(session.psk_id, CU);
    assert!(!session.session_type.is_authenticated());
    try_close(&dev, session.session_id);
}

// ---------------------------------------------------------------------------
// Role / type mismatches
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn open_session_co_plaintext_rejected_emu() {
    let dev = open_dev();
    let err = open_session_init(&dev, CO, SessionType::PlainText)
        .expect_err("CO + PlainText is not a permitted pairing");
    assert_fw_rejects(&err, HsmError::InvalidSessionType);
}

#[test]
#[serial]
fn open_session_cu_authenticated_rejected_emu() {
    let dev = open_dev();
    let err = open_session_init(&dev, CU, SessionType::Authenticated)
        .expect_err("CU + Authenticated is not a permitted pairing");
    assert_fw_rejects(&err, HsmError::InvalidSessionType);
}

// ---------------------------------------------------------------------------
// Parse-stage rejections
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn open_session_invalid_psk_id_emu() {
    let dev = open_dev();
    let err =
        open_session_init(&dev, 2, SessionType::PlainText).expect_err("psk_id must be 0 or 1");
    assert_fw_rejects(&err, HsmError::InvalidPskId);
}

#[test]
#[serial]
fn open_session_invalid_session_type_byte_emu() {
    // Bypass the typed `SessionType` enum to ship an out-of-range
    // byte directly. The FW `SessionType::from_u8` must reject.
    let dev = open_dev();
    let req = TborOpenSessionInitReq {
        psk_id: CU,
        session_type: 42,
        suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
        pk_init: [0x04u8; PK_INIT_LEN],
    };
    let mut cookie = None;
    let err = dev
        .exec_op_tbor::<TborOpenSessionInitReq>(&req, &mut cookie)
        .expect_err("session_type = 42 must be rejected at parse");
    assert_fw_rejects(&err, HsmError::InvalidSessionType);
}

// ---------------------------------------------------------------------------
// Unsupported suite_id (negative test)
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn open_session_unsupported_suite_id_emu() {
    // Any byte other than 0x01 must be rejected by `SessionSuite::from_u8`
    // before any HPKE work happens.  Spot-check three boundary values
    // covering "reserved-but-not-yet-implemented" (0x02), zero (0x00),
    // and the all-ones byte (0xFF).
    for bad in [0x00u8, 0x02, 0xff] {
        let dev = open_dev();
        let req = TborOpenSessionInitReq {
            psk_id: CU,
            session_type: SessionType::PlainText.to_u8(),
            suite_id: bad,
            pk_init: [0x04u8; PK_INIT_LEN],
        };
        let mut cookie = None;
        let err = dev
            .exec_op_tbor::<TborOpenSessionInitReq>(&req, &mut cookie)
            .expect_err("unsupported suite_id must be rejected at parse");
        assert_fw_rejects(&err, HsmError::UnsupportedSessionSuite);
    }
}

// ---------------------------------------------------------------------------
// Phase-2 MAC tampering
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn open_session_finish_mac_tampered_emu() {
    let dev = open_dev();
    let pending =
        open_session_init(&dev, CU, SessionType::PlainText).expect("phase 1 must succeed");
    let mut mac_fin = build_mac_fin(&pending).expect("build phase-2 mac");
    mac_fin[0] ^= 0x01;
    let session_id = pending.session_id;
    let err = open_session_finish_with_mac(&dev, pending, mac_fin)
        .expect_err("tampered mac_fin must be rejected by the FW");
    assert_fw_rejects(&err, HsmError::SessionAuthFailure);
    // FW destroys the pending slot on MAC mismatch (per
    // open_session_finish.rs:285); no cleanup needed, but try_close
    // is idempotent over unknown ids.
    try_close(&dev, session_id);
}

// ---------------------------------------------------------------------------
// Finish-side error paths
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn open_session_finish_unknown_session_id_emu() {
    // Pick a session id that cannot possibly correspond to a live
    // pending slot. The FW pre-check fails to load the blob.
    let dev = open_dev();
    let req = TborOpenSessionFinishReq {
        session_id: 0xFFFF,
        mac_fin: [0u8; 48],
        seed_envelope: [0u8; SEED_ENVELOPE_LEN],
    };
    let mut cookie = None;
    let err = dev
        .exec_op_tbor::<TborOpenSessionFinishReq>(&req, &mut cookie)
        .expect_err("finish against unknown session_id must fail");
    // FW returns an error from `session_pending_state` / its
    // pre-check; surface as any DdiError::DdiError(_).
    assert!(
        matches!(err, azihsm_ddi_interface::DdiError::DdiError(_)),
        "expected FW-side rejection, got {err:?}",
    );
}

#[test]
#[serial]
fn open_session_double_finish_emu() {
    let dev = open_dev();
    let session = open_session(&dev, CU, SessionType::PlainText).expect("first handshake");
    // Replay the finish: pending slot is gone, FW must refuse.
    let req = TborOpenSessionFinishReq {
        session_id: session.session_id,
        mac_fin: [0u8; 48],
        seed_envelope: [0u8; SEED_ENVELOPE_LEN],
    };
    let mut cookie = None;
    let err = dev
        .exec_op_tbor::<TborOpenSessionFinishReq>(&req, &mut cookie)
        .expect_err("second finish against the same slot must fail");
    assert!(
        matches!(err, azihsm_ddi_interface::DdiError::DdiError(_)),
        "expected FW-side rejection, got {err:?}",
    );
    try_close(&dev, session.session_id);
}

// ---------------------------------------------------------------------------
// Phase-2 seed_envelope tampering
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn open_session_finish_seed_envelope_tampered_emu() {
    // Build a finish request by hand so we can corrupt the seed_envelope
    // ciphertext byte after Phase-1 succeeds but before shipping it.
    let dev = open_dev();
    let pending =
        open_session_init(&dev, CU, SessionType::PlainText).expect("phase 1 must succeed");
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
    let mut cookie = None;
    let err = dev
        .exec_op_tbor::<TborOpenSessionFinishReq>(&req, &mut cookie)
        .expect_err("tampered seed_envelope must be rejected by the FW");
    assert_fw_rejects(&err, HsmError::SessionAuthFailure);
    try_close(&dev, session_id);
}

// ---------------------------------------------------------------------------
// Multiple concurrent sessions
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn open_session_multiple_concurrent_emu() {
    let dev = open_dev();
    let a = open_session(&dev, CU, SessionType::PlainText).expect("first CU session");
    let b = open_session(&dev, CU, SessionType::PlainText).expect("second CU session");
    assert_ne!(
        a.session_id, b.session_id,
        "concurrent sessions must have distinct ids",
    );
    try_close(&dev, a.session_id);
    try_close(&dev, b.session_id);
}
