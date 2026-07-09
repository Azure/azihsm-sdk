// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hardware end-to-end smoke tests for the TBOR
//! `SessionOpenInit` / `SessionOpenFinish` two-phase handshake.
//!
//! Exercises the full host -> nix/win backend -> silicon fw
//! `handle_tbor_op` pipeline against a live board. Each test either
//!
//! * runs a happy-path handshake and **explicitly** closes the
//!   resulting Active session via `SessionClose` (real silicon can't
//!   be factory-reset from a test binary — leaks would eventually
//!   exhaust the session table), or
//! * exercises a negative path that the firmware **already** cleans
//!   up as part of its error-handling contract (parse-stage rejects
//!   never allocate a slot; Phase-2 auth failures destroy the
//!   Pending slot before returning).
//!
//! Cross-worker safety is provided by [`crate::hw::open_hw_dev`]'s
//! process-global [`HW_TEST_LOCK`](crate::hw::HW_TEST_LOCK).
//!
//! Coverage mirrors the emu suite in `commands::open_session`:
//! happy paths for both permitted (role, session_type) pairings,
//! role/type mismatches, parse-stage negatives (psk_id,
//! session_type byte, suite_id), Phase-2 MAC and seed-envelope
//! tampering, and a concurrent-sessions distinctness check.
//!
//! Invoke with:
//!
//! ```text
//! cargo test --no-default-features \
//!     -p azihsm_ddi_tbor_types \
//!     --test azihsm_ddi_tbor_tests hw::open_session
//! ```

use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborSessionOpenFinishReq;
use azihsm_ddi_tbor_types::TborSessionOpenInitReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::PK_INIT_LEN;
use azihsm_ddi_tbor_types::SEED_ENVELOPE_LEN;
use azihsm_ddi_tbor_types::SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256;

use crate::hw::assertions::assert_fw_rejects;
use crate::hw::open_additional_hw_dev_fd;
use crate::hw::open_hw_dev;
use crate::hw::session_helper::build_mac_fin;
use crate::hw::session_helper::open_session;
use crate::hw::session_helper::session_close;
use crate::hw::session_helper::session_open_finish_with_mac;
use crate::hw::session_helper::session_open_init;

const CO: u8 = 0;
const CU: u8 = 1;

/// Ship `req` and expect an FW-side rejection with the given
/// `TborStatus`. Small local wrapper so each negative-path test
/// reads as a single call.
#[track_caller]
fn expect_init_rejects(req: &TborSessionOpenInitReq, expected: TborStatus) {
    let dev = open_hw_dev();
    let mut cookie = None;
    let err = dev
        .exec_op_tbor::<TborSessionOpenInitReq>(req, None, &mut cookie)
        .expect_err("FW must reject the malformed SessionOpenInit request");
    assert_fw_rejects(&err, expected);
}

// ---------------------------------------------------------------------------
// Happy paths — full two-phase handshake against real silicon.
// Each test explicitly closes the session; a bare `assert!` failure
// still runs `SessionClose` because we call it inline before the
// assertion (or in a helper that scopes cleanup around the check).
// ---------------------------------------------------------------------------

#[test]
fn co_authenticated_happy() {
    let dev = open_hw_dev();
    let handshake = open_session(&dev, CO, SessionType::Authenticated)
        .expect("hw handshake CO+Authenticated must succeed");
    let session_id = handshake.session_id;

    // Snapshot the invariants we want to check, then close the
    // session on the device before running assertions so a failure
    // never leaks a slot on the physical board.
    let psk_id = handshake.psk_id;
    let is_auth = handshake.session_type.is_authenticated();
    let bmk_len = handshake.bmk_session.len();
    let tx = handshake.derive_mac_tx_key().expect("derive mac tx key");
    let rx = handshake.derive_mac_rx_key().expect("derive mac rx key");
    drop(handshake);
    session_close(&dev, session_id).expect("SessionClose must succeed on hw");

    assert_eq!(psk_id, CO, "handshake carrier must round-trip psk_id");
    assert!(is_auth, "CO handshake must yield an Authenticated channel");
    assert!(
        bmk_len > 0,
        "FW must return a non-empty bmk_session envelope",
    );
    assert_eq!(tx.len(), 48, "mac tx key length");
    assert_eq!(rx.len(), 48, "mac rx key length");
    assert_ne!(tx, rx, "mac tx and rx keys must differ per direction");
}

#[test]
fn cu_plaintext_happy() {
    let dev = open_hw_dev();
    let handshake = open_session(&dev, CU, SessionType::PlainText)
        .expect("hw handshake CU+PlainText must succeed");
    let session_id = handshake.session_id;
    let psk_id = handshake.psk_id;
    let is_auth = handshake.session_type.is_authenticated();
    let bmk_len = handshake.bmk_session.len();
    drop(handshake);
    session_close(&dev, session_id).expect("SessionClose must succeed on hw");

    assert_eq!(psk_id, CU);
    assert!(!is_auth, "CU handshake must yield a PlainText channel");
    assert!(bmk_len > 0);
}

// ---------------------------------------------------------------------------
// Role / session_type mismatches — parse-stage rejections in
// `validate_for_role`. No pending slot is allocated, no cleanup
// needed.
// ---------------------------------------------------------------------------

#[test]
fn co_plaintext_rejected() {
    let dev = open_hw_dev();
    let err = session_open_init(&dev, CO, SessionType::PlainText)
        .expect_err("CO + PlainText must be rejected by validate_for_role");
    assert_fw_rejects(&err, TborStatus::InvalidSessionType);
}

#[test]
fn cu_authenticated_rejected() {
    let dev = open_hw_dev();
    let err = session_open_init(&dev, CU, SessionType::Authenticated)
        .expect_err("CU + Authenticated must be rejected by validate_for_role");
    assert_fw_rejects(&err, TborStatus::InvalidSessionType);
}

// ---------------------------------------------------------------------------
// Parse-stage negatives — FW rejects before any HPKE work; no
// pending slot allocated.
// ---------------------------------------------------------------------------

#[test]
fn invalid_psk_id_rejected() {
    // Bypass the typed `PskId(0|1)` guard by shipping raw bytes.
    // Spot-check a small set of out-of-range values covering: the
    // smallest invalid value (`2`), a mid-range value (`0x7F`), and
    // the all-ones byte (`0xFF`). All must surface `InvalidPskId`
    // from the FW dispatcher before any HPKE work.
    for bad in [2u8, 0x7F, 0xFF] {
        let req = TborSessionOpenInitReq {
            psk_id: bad,
            session_type: SessionType::PlainText.to_u8(),
            suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
            pk_init: [0x04u8; PK_INIT_LEN],
        };
        expect_init_rejects(&req, TborStatus::InvalidPskId);
    }
}

#[test]
fn invalid_session_type_byte_rejected() {
    // Bypass the typed `SessionType` enum — ship an out-of-range byte
    // directly so `SessionType::from_u8` in the FW rejects.
    let req = TborSessionOpenInitReq {
        psk_id: CU,
        session_type: 42,
        suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
        pk_init: [0x04u8; PK_INIT_LEN],
    };
    expect_init_rejects(&req, TborStatus::InvalidSessionType);
}

#[test]
fn unsupported_suite_id_rejected() {
    // Only 0x01 is supported; spot-check reserved (0x02), zero, and
    // the all-ones byte.
    for bad in [0x00u8, 0x02, 0xFF] {
        let req = TborSessionOpenInitReq {
            psk_id: CU,
            session_type: SessionType::PlainText.to_u8(),
            suite_id: bad,
            pk_init: [0x04u8; PK_INIT_LEN],
        };
        expect_init_rejects(&req, TborStatus::UnsupportedSessionSuite);
    }
}

// ---------------------------------------------------------------------------
// Phase-2 auth failures — FW's contract is to destroy the pending
// slot on either MAC mismatch or AEAD-open failure, so no explicit
// cleanup is needed. Regression for the destroy-on-auth-failure
// wiring.
// ---------------------------------------------------------------------------

#[test]
fn finish_mac_tampered() {
    let dev = open_hw_dev();
    let pending =
        session_open_init(&dev, CU, SessionType::PlainText).expect("Phase 1 must succeed");
    let mut mac_fin = build_mac_fin(&pending).expect("build phase-2 mac");
    mac_fin[0] ^= 0x01;
    let err = session_open_finish_with_mac(&dev, pending, mac_fin)
        .expect_err("tampered mac_fin must be rejected by the FW");
    assert_fw_rejects(&err, TborStatus::SessionAuthFailure);
    // No SessionClose — FW destroyed the slot as part of the auth
    // failure path (see `session_open_finish::on_start` +
    // `TborSessionAuthFailure` arm).
}

#[test]
fn finish_seed_envelope_tampered() {
    let dev = open_hw_dev();
    let pending =
        session_open_init(&dev, CU, SessionType::PlainText).expect("Phase 1 must succeed");
    let session_id = pending.session_id;
    let mac_fin = build_mac_fin(&pending).expect("build phase-2 mac");
    // Consume pending so it isn't reused; then hand-build a
    // syntactically-valid-but-cryptographically-bogus envelope.
    drop(pending);

    let mut seed_envelope = [0u8; SEED_ENVELOPE_LEN];
    seed_envelope[0..4].copy_from_slice(b"AEAD");
    seed_envelope[4] = 0x03; // AeadAlg::AesGcm256
                             // Bytes 5..8 remain zero (rsv=0, aad_len_be=0); IV/CT/TAG all
                             // zero — the AES-GCM tag will fail to verify.

    let req = TborSessionOpenFinishReq {
        session_id,
        mac_fin,
        seed_envelope,
    };
    let mut cookie = None;
    let err = dev
        .exec_op_tbor::<TborSessionOpenFinishReq>(&req, None, &mut cookie)
        .expect_err("tampered seed_envelope must be rejected by the FW");
    assert_fw_rejects(&err, TborStatus::SessionAuthFailure);
    // FW destroyed the slot on AEAD auth failure — no manual cleanup.
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

#[test]
fn multiple_concurrent_sessions_have_distinct_ids() {
    // The Linux kernel driver enforces `AZIHSM_MAX_SESSIONS_PER_FD = 1`
    // (see drivers/linux/drvsrc/azihsm_hsm.h), so two concurrent
    // sessions must be opened on two distinct file descriptors on
    // the same physical device. `open_hw_dev()` takes the shared
    // HW_TEST_LOCK; use `open_additional_hw_dev_fd()` for the
    // second fd so we don''t deadlock re-acquiring a non-reentrant
    // mutex.
    let dev_a = open_hw_dev();
    let dev_b = open_additional_hw_dev_fd(&dev_a);
    let a = open_session(&dev_a, CU, SessionType::PlainText).expect("first session must open");
    let b = open_session(&dev_b, CU, SessionType::PlainText).expect("second session must open");
    let id_a = a.session_id;
    let id_b = b.session_id;
    drop(a);
    drop(b);
    // Close both regardless of the assertion outcome so nothing
    // leaks on the physical board.
    let close_a = session_close(&dev_a, id_a);
    let close_b = session_close(&dev_b, id_b);
    close_a.expect("close session A");
    close_b.expect("close session B");
    assert_ne!(id_a, id_b, "concurrent sessions must have distinct ids");
}
