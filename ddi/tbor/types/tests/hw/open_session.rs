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

// ---------------------------------------------------------------------------
// Finish-side error paths not already covered above.
// Ported from the emu suite (`commands::open_session`) so both suites
// stay wire-identical.
// ---------------------------------------------------------------------------

/// `SessionOpenFinish` against a session id that does not match
/// the pending slot on this fd must be rejected. The Linux kernel
/// driver enforces fd-scoping (`FileHandleNoExistingSession`) so we
/// establish a real pending slot first, then send the finish with
/// a mismatched id. Either the driver (id mismatch) or the FW
/// (pending-blob load fails) is a valid rejection surface — accept
/// both.
#[test]
fn finish_unknown_session_id_rejected() {
    let dev = open_hw_dev();
    let pending = session_open_init(&dev, CU, SessionType::PlainText)
        .expect("phase-1 to establish a real pending slot must succeed");
    let real_id = pending.session_id;
    // Consume `pending` so it isn't reused. The FW pending blob
    // remains until we either finish it or `SessionClose` it.
    drop(pending);

    // Mismatched id: flip the high bit so the value can never
    // collide with `real_id` on any realistic slot count.
    let bogus_id = real_id ^ 0x8000;

    let req = TborSessionOpenFinishReq {
        session_id: bogus_id,
        mac_fin: [0u8; 48],
        seed_envelope: [0u8; SEED_ENVELOPE_LEN],
    };
    let mut cookie = None;
    let err = dev
        .exec_op_tbor::<TborSessionOpenFinishReq>(&req, None, &mut cookie)
        .expect_err("finish against mismatched session_id must fail");
    assert!(
        matches!(
            err,
            azihsm_ddi_interface::DdiError::DdiError(_)
                | azihsm_ddi_interface::DdiError::DdiStatus(_)
        ),
        "expected FW or driver rejection, got {err:?}",
    );

    // Clean up the real pending slot we established up front.
    let _ = session_close(&dev, real_id);
}

/// Replaying `SessionOpenFinish` after a successful handshake must
/// fail: the pending blob has been consumed and the slot is Active,
/// so the finish-side pre-check refuses to load it as pending. This
/// is the regression for the "pending blob consumed on success"
/// wiring.
#[test]
fn double_finish_rejected() {
    let dev = open_hw_dev();
    let handshake = open_session(&dev, CU, SessionType::PlainText)
        .expect("hw handshake CU+PlainText must succeed");
    let session_id = handshake.session_id;
    drop(handshake);

    let req = TborSessionOpenFinishReq {
        session_id,
        mac_fin: [0u8; 48],
        seed_envelope: [0u8; SEED_ENVELOPE_LEN],
    };
    let mut cookie = None;
    let err = dev
        .exec_op_tbor::<TborSessionOpenFinishReq>(&req, None, &mut cookie)
        .expect_err("second finish against the same slot must fail");
    assert!(
        matches!(err, azihsm_ddi_interface::DdiError::DdiError(_)),
        "expected FW-side rejection on double-finish, got {err:?}",
    );
    // Close the Active slot we established up front so this test
    // does not leak on the physical board.
    session_close(&dev, session_id).expect("SessionClose must succeed on hw");
}

// ---------------------------------------------------------------------------
// Hardware-specific lifecycle: real silicon retains session-table
// state across tests, so an explicit "close fully frees the slot"
// regression only makes sense on hw. The emu harness gets a fresh
// factory reset per test and can't observe this.
// ---------------------------------------------------------------------------

/// Open a session, close it, then open again on the same fd. The
/// second open must succeed — this guards against a stale slot or
/// leaked FSM state that would otherwise wedge the second attempt.
#[test]
fn open_close_reopen_same_slot() {
    let dev = open_hw_dev();
    let first =
        open_session(&dev, CU, SessionType::PlainText).expect("first hw handshake must succeed");
    let first_id = first.session_id;
    drop(first);
    session_close(&dev, first_id).expect("first SessionClose must succeed");

    let second =
        open_session(&dev, CU, SessionType::PlainText).expect("reopen after close must succeed");
    let second_id = second.session_id;
    drop(second);
    session_close(&dev, second_id).expect("second SessionClose must succeed");
}

/// `SessionClose` against a session id that does not match the
/// active slot on this fd must be rejected. The Linux kernel driver
/// enforces fd-scoping (`FileHandleNoExistingSession`) so we open a
/// real session first, then close a mismatched id. Either the
/// driver or the FW is a valid rejection surface.
#[test]
fn session_close_unknown_session_id_rejected() {
    let dev = open_hw_dev();
    let handshake = open_session(&dev, CU, SessionType::PlainText)
        .expect("hw handshake to establish an Active slot must succeed");
    let real_id = handshake.session_id;
    drop(handshake);

    let bogus_id = real_id ^ 0x8000;
    let err =
        session_close(&dev, bogus_id).expect_err("SessionClose against mismatched id must fail");
    assert!(
        matches!(
            err,
            azihsm_ddi_interface::DdiError::DdiError(_)
                | azihsm_ddi_interface::DdiError::DdiStatus(_)
        ),
        "expected FW or driver rejection on close-unknown, got {err:?}",
    );

    // Close the real slot we opened for fixture setup.
    session_close(&dev, real_id).expect("close of the real session must succeed");
}

// ---------------------------------------------------------------------------
// Point-validation negatives. The FW `EccPublicKeyValidation` stage
// checks that `pk_init` is a valid, non-identity point on the P-384
// curve; the emu suite can't meaningfully hit the on-curve check
// (SoftAES + mocks accept whatever), so these are genuine hw-only
// coverage.
//
// We only assert a generic FW-side rejection rather than pinning
// `EccPointValidationFailed` in case a future FW change collapses
// validation errors into a broader category (e.g. `InvalidArg`).
// ---------------------------------------------------------------------------

/// `pk_init` all zeros is trivially off-curve (and encodes the point
/// at infinity in some conventions) — FW must reject.
#[test]
fn pk_init_all_zero_rejected() {
    let dev = open_hw_dev();
    let req = TborSessionOpenInitReq {
        psk_id: CU,
        session_type: SessionType::PlainText.to_u8(),
        suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
        pk_init: [0u8; PK_INIT_LEN],
    };
    let mut cookie = None;
    let err = dev
        .exec_op_tbor::<TborSessionOpenInitReq>(&req, None, &mut cookie)
        .expect_err("all-zero pk_init must be rejected");
    assert!(
        matches!(err, azihsm_ddi_interface::DdiError::DdiError(_)),
        "expected FW-side rejection for all-zero pk_init, got {err:?}",
    );
}

/// `pk_init` with the SEC1 uncompressed prefix (`0x04`) but garbage
/// coordinates that do not satisfy the P-384 curve equation. FW's
/// on-curve validation must reject.
#[test]
fn pk_init_not_on_curve_rejected() {
    let dev = open_hw_dev();
    let mut pk_init = [0xFFu8; PK_INIT_LEN];
    pk_init[0] = 0x04; // SEC1 uncompressed prefix
    let req = TborSessionOpenInitReq {
        psk_id: CU,
        session_type: SessionType::PlainText.to_u8(),
        suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
        pk_init,
    };
    let mut cookie = None;
    let err = dev
        .exec_op_tbor::<TborSessionOpenInitReq>(&req, None, &mut cookie)
        .expect_err("off-curve pk_init must be rejected");
    assert!(
        matches!(err, azihsm_ddi_interface::DdiError::DdiError(_)),
        "expected FW-side rejection for off-curve pk_init, got {err:?}",
    );
}

// ---------------------------------------------------------------------------
// Session table exhaustion + recovery. Iteratively opens sessions on
// fresh fds until the FW reports the table is full, then closes them
// all and confirms one more open succeeds — the pending/active slot
// cleanup path must fully reclaim capacity.
//
// We bound the loop at 16 to avoid running forever on future FW
// builds with a much larger table. If the loop completes without a
// rejection we still validate the cleanup path (close-all + reopen)
// but skip the "at least one rejection observed" invariant with a
// diagnostic message so the test remains meaningful across FW
// capacity changes.
// ---------------------------------------------------------------------------

#[test]
fn open_session_fills_table_then_recovers() {
    let dev = open_hw_dev();
    let mut fds: Vec<<azihsm_ddi::AzihsmDdi as azihsm_ddi_interface::Ddi>::Dev> = Vec::new();
    let mut ids: Vec<u16> = Vec::new();
    let mut rejection_seen = false;

    for _ in 0..16 {
        let fd = open_additional_hw_dev_fd(&dev);
        match open_session(&fd, CU, SessionType::PlainText) {
            Ok(h) => {
                ids.push(h.session_id);
                fds.push(fd);
                drop(h);
            }
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
    for (fd, id) in fds.iter().zip(ids.iter()) {
        let _ = session_close(fd, *id);
    }

    // Recovery: one fresh open must succeed after the batch close.
    let recovered = open_session(&dev, CU, SessionType::PlainText)
        .expect("session table must recover after close-all");
    let recovered_id = recovered.session_id;
    drop(recovered);
    session_close(&dev, recovered_id).expect("SessionClose after recovery must succeed");

    if !rejection_seen {
        eprintln!(
            "open_session_fills_table_then_recovers: FW accepted {} concurrent sessions              without emitting a table-full rejection; capacity limit not observed",
            ids.len(),
        );
    }
}

// ---------------------------------------------------------------------------
// Two independent handshakes must derive distinct exported material,
// which — for authenticated sessions — surfaces as distinct MAC
// keys. This is the invariant that lets the host use per-session
// MAC keys as replay-window nonces without cross-session collisions.
// ---------------------------------------------------------------------------

/// Two independent CO+Authenticated handshakes must derive distinct
/// exported material — which surfaces as distinct per-direction MAC
/// keys. Runs sequentially (open, snapshot, close, open again)
/// because real hw refuses to hold two Authenticated sessions
/// concurrently (`VaultSessionLimitReached`); the ephemeral-per-
/// handshake invariant this test guards is unchanged by that.
#[test]
fn co_authenticated_derives_unique_keys_per_session() {
    let dev = open_hw_dev();

    // First handshake — snapshot keys then close.
    let a = open_session(&dev, CO, SessionType::Authenticated)
        .expect("first CO+Authenticated handshake must succeed");
    let a_id = a.session_id;
    let a_tx = a.derive_mac_tx_key().expect("derive a tx");
    let a_rx = a.derive_mac_rx_key().expect("derive a rx");
    let a_exported = a.exported.clone();
    drop(a);
    session_close(&dev, a_id).expect("close first session must succeed");

    // Second handshake on the same fd — must derive fresh material
    // because the VM ephemeral keypair is regenerated per Phase-1.
    let b = open_session(&dev, CO, SessionType::Authenticated)
        .expect("second CO+Authenticated handshake must succeed");
    let b_id = b.session_id;
    let b_tx = b.derive_mac_tx_key().expect("derive b tx");
    let b_rx = b.derive_mac_rx_key().expect("derive b rx");
    let b_exported = b.exported.clone();
    drop(b);
    // Close before asserting so a failing assertion never leaks.
    session_close(&dev, b_id).expect("close second session must succeed");

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
