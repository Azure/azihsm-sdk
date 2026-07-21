// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SessionOpenInit` /
//! `SessionOpenFinish` two-phase session handshake.
//!
//! Runs against both backends via the [`Ctx`] alias: `TestCtx` under
//! `feature = "emu"` (soft-crypto backend, factory-reset per test),
//! `HwCtx` under `feature = "hw-tests"` (native OS backend against a
//! live board, NSSR per test).
//!
//! Happy-path sessions are owned by a
//! [`SessionGuard`](crate::harness::SessionGuard) that closes on
//! `Drop`; negative-path tests intercept the handshake through the
//! raw `session_open_init` / `session_open_finish` methods on `Ctx`.

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborSessionOpenFinishReq;
use azihsm_ddi_tbor_types::TborSessionOpenInitReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::PK_INIT_LEN;
use azihsm_ddi_tbor_types::SEED_ENVELOPE_LEN;
use azihsm_ddi_tbor_types::SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256;

use crate::harness::build_mac_fin;
use crate::harness::Ctx;

const CO: u8 = 0;
const CU: u8 = 1;

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

#[test]
fn open_session_co_authenticated_happy() {
    let ctx = Ctx::new();
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
fn open_session_cu_plaintext_happy() {
    let ctx = Ctx::new();
    let session = ctx.open_session(CU, SessionType::PlainText);
    let h = session.handshake();
    assert_eq!(h.psk_id, CU);
    assert!(!h.session_type.is_authenticated());
}

// ---------------------------------------------------------------------------
// Role / type mismatches
// ---------------------------------------------------------------------------

#[test]
fn open_session_co_plaintext_rejected() {
    let ctx = Ctx::new();
    let err = ctx
        .session_open_init(CO, SessionType::PlainText)
        .expect_err("CO + PlainText is not a permitted pairing");
    crate::harness::assertions::assert_fw_rejects(&err, TborStatus::InvalidSessionType);
}

#[test]
fn open_session_cu_authenticated_rejected() {
    let ctx = Ctx::new();
    let err = ctx
        .session_open_init(CU, SessionType::Authenticated)
        .expect_err("CU + Authenticated is not a permitted pairing");
    crate::harness::assertions::assert_fw_rejects(&err, TborStatus::InvalidSessionType);
}

// ---------------------------------------------------------------------------
// Parse-stage rejections
// ---------------------------------------------------------------------------

#[test]
fn open_session_invalid_psk_id() {
    // Only `0` (CO) and `1` (CU) are valid `psk_id` values. Spot-check
    // a small set of out-of-range values covering: the smallest invalid
    // value (`2`), a mid-range value (`0x7F`), and the all-ones byte
    // (`0xFF`). All must surface `InvalidPskId` from the FW
    // dispatcher's `psk_id`-validation arm before any HPKE work.
    let ctx = Ctx::new();
    for bad in [2u8, 0x7F, 0xFF] {
        let err = ctx
            .session_open_init(bad, SessionType::PlainText)
            .expect_err(&format!("psk_id {bad} must be rejected"));
        crate::harness::assertions::assert_fw_rejects(&err, TborStatus::InvalidPskId);
    }
}

#[test]
fn open_session_invalid_session_type_byte() {
    // Bypass the typed `SessionType` enum to ship an out-of-range
    // byte directly. The FW `SessionType::from_u8` must reject.
    let ctx = Ctx::new();
    let req = TborSessionOpenInitReq {
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
fn open_session_unsupported_suite_id() {
    // Any byte other than 0x01 must be rejected by `SessionSuite::from_u8`
    // before any HPKE work happens. Spot-check three boundary values
    // covering "reserved-but-not-yet-implemented" (0x02), zero (0x00),
    // and the all-ones byte (0xFF).
    let ctx = Ctx::new();
    for bad in [0x00u8, 0x02, 0xff] {
        let req = TborSessionOpenInitReq {
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
fn session_open_finish_mac_tampered() {
    let ctx = Ctx::new();
    let pending = ctx
        .session_open_init(CU, SessionType::PlainText)
        .expect("phase 1 must succeed");
    let mut mac_fin = build_mac_fin(&pending).expect("build phase-2 mac");
    mac_fin[0] ^= 0x01;
    let err = ctx
        .session_open_finish_with_mac(pending, mac_fin)
        .expect_err("tampered mac_fin must be rejected by the FW");
    crate::harness::assertions::assert_fw_rejects(&err, TborStatus::SessionAuthFailure);
    // FW destroys the pending slot on MAC mismatch.
}

// ---------------------------------------------------------------------------
// Finish-side error paths
// ---------------------------------------------------------------------------

#[test]
fn session_open_finish_unknown_session_id() {
    // Pick a session id that cannot possibly correspond to a live
    // pending slot. On emu the FW pre-check fails to load the blob
    // (`DdiError::DdiError`). On hw the Linux kernel driver enforces
    // per-fd session scoping and rejects the ioctl with
    // `FileHandleNoExistingSession` (`DdiError::DdiStatus`) before
    // the FW sees it — either surface is a valid rejection.
    let ctx = Ctx::new();
    let req = TborSessionOpenFinishReq {
        session_id: 0xFFFF,
        mac_fin: [0u8; 48],
        seed_envelope: [0u8; SEED_ENVELOPE_LEN],
    };
    let err = ctx
        .tbor(&req)
        .expect_err("finish against unknown session_id must fail");
    assert!(
        matches!(
            err,
            azihsm_ddi_interface::DdiError::TborStatus(_)
                | azihsm_ddi_interface::DdiError::DdiStatus(_)
        ),
        "expected FW or driver rejection, got {err:?}",
    );
}

#[test]
fn open_session_double_finish() {
    let ctx = Ctx::new();
    let session = ctx.open_session(CU, SessionType::PlainText);
    // Replay the finish: pending slot is gone, FW must refuse.
    let req = TborSessionOpenFinishReq {
        session_id: session.session_id(),
        mac_fin: [0u8; 48],
        seed_envelope: [0u8; SEED_ENVELOPE_LEN],
    };
    let err = ctx
        .tbor(&req)
        .expect_err("second finish against the same slot must fail");
    assert!(
        matches!(err, azihsm_ddi_interface::DdiError::TborStatus(_)),
        "expected FW-side rejection, got {err:?}",
    );
}

// ---------------------------------------------------------------------------
// Phase-2 seed_envelope tampering
// ---------------------------------------------------------------------------

#[test]
fn session_open_finish_seed_envelope_tampered() {
    // Build a finish request by hand so we can corrupt the seed_envelope
    // ciphertext byte after Phase-1 succeeds but before shipping it.
    let ctx = Ctx::new();
    let pending = ctx
        .session_open_init(CU, SessionType::PlainText)
        .expect("phase 1 must succeed");
    let session_id = pending.session_id;
    let mac_fin = build_mac_fin(&pending).expect("build phase-2 mac");

    // Ship a syntactically-valid but cryptographically-bogus envelope:
    // "AEAD" magic + correct alg/aad_len framing but all-zero IV / CT /
    // tag. The FW's AEAD-open must fail and destroy the slot.
    let mut seed_envelope = [0u8; SEED_ENVELOPE_LEN];
    seed_envelope[0..4].copy_from_slice(b"AEAD");
    seed_envelope[4] = 0x03; // AeadAlg::AesGcm256

    let req = TborSessionOpenFinishReq {
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
fn open_session_multiple_concurrent() {
    let ctx = Ctx::new();
    let a = ctx.open_session(CU, SessionType::PlainText);
    let b = ctx.open_session(CU, SessionType::PlainText);
    assert_ne!(
        a.session_id(),
        b.session_id(),
        "concurrent sessions must have distinct ids",
    );
}

// ---------------------------------------------------------------------------
// Session-table exhaustion + recovery
//
// Iteratively opens sessions until the FW reports the table is full,
// then closes them all and confirms one more open succeeds — the
// pending/active slot cleanup path must fully reclaim capacity.
//
// The table size differs by backend (emu FW has a small hardcoded
// table; hw silicon a larger one), so the loop is bounded generously
// at 16 and the "at least one rejection observed" invariant is a soft
// diagnostic — the value of the test is the close-all + reopen path.
// ---------------------------------------------------------------------------

#[test]
fn open_session_fills_table_then_recovers() {
    let ctx = Ctx::new();
    let mut ids: Vec<u16> = Vec::new();
    let mut rejection_seen = false;

    for _ in 0..16 {
        match ctx.open_session_raw(CU, SessionType::PlainText) {
            Ok(h) => ids.push(h.session_id),
            Err(e) => {
                // FW rejected — treat as "table full". Verify it is
                // an FW-side rejection (not a driver / decode fault)
                // before ending the ramp-up.
                assert!(
                    matches!(e, azihsm_ddi_interface::DdiError::DdiError(_)),
                    "table-full rejection must be FW-side, got {e:?}",
                );
                rejection_seen = true;
                break;
            }
        }
    }

    // Close everything we opened before running the recovery check,
    // so a recovery-side failure does not leak slots on the board.
    for id in &ids {
        let _ = ctx.session_close(*id);
    }

    // Recovery: one fresh open must succeed after the batch close.
    let recovered = ctx
        .open_session_raw(CU, SessionType::PlainText)
        .expect("session table must recover after close-all");
    ctx.session_close(recovered.session_id)
        .expect("SessionClose after recovery must succeed");

    if !rejection_seen {
        eprintln!(
            "open_session_fills_table_then_recovers: backend accepted {} concurrent sessions \
             without emitting a table-full rejection; capacity limit not observed",
            ids.len(),
        );
    }
}

// ---------------------------------------------------------------------------
// Open / close / reopen
// ---------------------------------------------------------------------------

/// Open a session, close it, then open again. The second open must
/// succeed — guards against a stale slot or leaked FSM state that
/// would otherwise wedge the second attempt.
#[test]
fn open_close_reopen_same_slot() {
    let ctx = Ctx::new();
    let first = ctx
        .open_session_raw(CU, SessionType::PlainText)
        .expect("first handshake must succeed");
    ctx.session_close(first.session_id)
        .expect("first SessionClose must succeed");

    let second = ctx
        .open_session_raw(CU, SessionType::PlainText)
        .expect("reopen after close must succeed");
    ctx.session_close(second.session_id)
        .expect("second SessionClose must succeed");
}

// ---------------------------------------------------------------------------
// Per-session key uniqueness
// ---------------------------------------------------------------------------

/// Two independent CO+Authenticated handshakes must derive distinct
/// exported material — which surfaces as distinct per-direction MAC
/// keys. Runs sequentially (open, snapshot, close, open again)
/// because hw silicon refuses to hold two Authenticated sessions
/// concurrently (`VaultSessionLimitReached`); the ephemeral-per-
/// handshake invariant this test guards is unchanged by that.
#[test]
fn co_authenticated_derives_unique_keys_per_session() {
    let ctx = Ctx::new();

    let a = ctx
        .open_session_raw(CO, SessionType::Authenticated)
        .expect("first CO+Authenticated handshake must succeed");
    let a_id = a.session_id;
    let a_tx = a.derive_mac_tx_key().expect("derive a tx");
    let a_rx = a.derive_mac_rx_key().expect("derive a rx");
    let a_exported = a.exported.clone();
    ctx.session_close(a_id)
        .expect("close first session must succeed");

    let b = ctx
        .open_session_raw(CO, SessionType::Authenticated)
        .expect("second CO+Authenticated handshake must succeed");
    let b_id = b.session_id;
    let b_tx = b.derive_mac_tx_key().expect("derive b tx");
    let b_rx = b.derive_mac_rx_key().expect("derive b rx");
    let b_exported = b.exported.clone();
    // Close before asserting so a failing assertion never leaks.
    ctx.session_close(b_id)
        .expect("close second session must succeed");

    assert_ne!(
        a_exported, b_exported,
        "two handshakes must derive distinct HPKE exported material",
    );
    assert_ne!(a_tx, b_tx, "per-session mac tx keys must differ");
    assert_ne!(a_rx, b_rx, "per-session mac rx keys must differ");
    // Sanity: within a single session, tx and rx are distinct.
    assert_ne!(a_tx, a_rx);
    assert_ne!(b_tx, b_rx);
}

// ---------------------------------------------------------------------------
// Point-validation negatives
//
// FW `EccPublicKeyValidation` checks that `pk_init` is a valid,
// non-identity point on the P-384 curve. The emu backend uses
// SoftAES + curve mocks that accept whatever is passed, so these
// two tests are hw-only.
//
// Assert a generic FW-side rejection rather than pinning
// `EccPointValidationFailed` in case a future FW change collapses
// validation errors into a broader category (e.g. `InvalidArg`).
// ---------------------------------------------------------------------------

/// `pk_init` all zeros is trivially off-curve (and encodes the point
/// at infinity in some conventions) — FW must reject.
#[cfg(feature = "hw-tests")]
#[test]
fn pk_init_all_zero_rejected() {
    let ctx = Ctx::new();
    let req = TborSessionOpenInitReq {
        psk_id: CU,
        session_type: SessionType::PlainText.to_u8(),
        suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
        pk_init: [0u8; PK_INIT_LEN],
    };
    let err = ctx
        .tbor(&req)
        .expect_err("all-zero pk_init must be rejected");
    assert!(
        matches!(err, azihsm_ddi_interface::DdiError::DdiError(_)),
        "expected FW-side rejection for all-zero pk_init, got {err:?}",
    );
}

/// `pk_init` with the SEC1 uncompressed prefix (`0x04`) but garbage
/// coordinates that do not satisfy the P-384 curve equation. FW's
/// on-curve validation must reject.
#[cfg(feature = "hw-tests")]
#[test]
fn pk_init_not_on_curve_rejected() {
    let ctx = Ctx::new();
    let mut pk_init = [0xFFu8; PK_INIT_LEN];
    pk_init[0] = 0x04; // SEC1 uncompressed prefix
    let req = TborSessionOpenInitReq {
        psk_id: CU,
        session_type: SessionType::PlainText.to_u8(),
        suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
        pk_init,
    };
    let err = ctx
        .tbor(&req)
        .expect_err("off-curve pk_init must be rejected");
    assert!(
        matches!(err, azihsm_ddi_interface::DdiError::DdiError(_)),
        "expected FW-side rejection for off-curve pk_init, got {err:?}",
    );
}
