// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hardware end-to-end tests for the TBOR `SessionOpenInit` /
//! `SessionOpenFinish` handshake. Happy-path tests must explicitly
//! `SessionClose` their session (no factory reset on hw); negative
//! paths rely on FW's own cleanup contract. Cross-worker safety
//! comes from [`crate::hw::HW_TEST_LOCK`].
//!
//! Run: `cargo test --no-default-features --features hw-tests \
//! -p azihsm_ddi_tbor_types --test azihsm_ddi_tbor_tests hw::open_session`

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
use crate::hw::session_helper::session_open_finish;
use crate::hw::session_helper::session_open_finish_with_mac;
use crate::hw::session_helper::session_open_init;

const CO: u8 = 0;
const CU: u8 = 1;

/// Ship `req` and expect an FW rejection with `expected`.
#[track_caller]
fn expect_init_rejects(req: &TborSessionOpenInitReq, expected: TborStatus) {
    let dev = open_hw_dev();
    let mut cookie = None;
    let err = dev
        .exec_op_tbor::<TborSessionOpenInitReq>(req, None, &mut cookie)
        .expect_err("FW must reject the malformed SessionOpenInit request");
    assert_fw_rejects(&err, expected);
}

// ── Happy paths: close before asserting so failures never leak slots.

#[test]
fn co_authenticated_happy() {
    let dev = open_hw_dev();
    let handshake = open_session(&dev, CO, SessionType::Authenticated)
        .expect("hw handshake CO+Authenticated must succeed");
    let session_id = handshake.session_id;

    // Snapshot then close before asserting.
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

// ── Role/type mismatches: parse-stage rejects, no slot allocated.

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

// ── Parse-stage negatives: FW rejects before any HPKE work.

#[test]
fn invalid_psk_id_rejected() {
    // Bypass the typed guard; cover low, mid, and all-ones out-of-range values.
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
    // Out-of-range session_type byte -> FW `from_u8` rejects.
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
    // Only 0x01 is supported; cover zero, reserved, and all-ones.
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

// ── Phase-2 auth failures: FW destroys the pending slot itself.

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
    // No SessionClose — FW destroys the slot on auth failure.
}

#[test]
fn finish_seed_envelope_tampered() {
    let dev = open_hw_dev();
    let pending =
        session_open_init(&dev, CU, SessionType::PlainText).expect("Phase 1 must succeed");
    let session_id = pending.session_id;
    let mac_fin = build_mac_fin(&pending).expect("build phase-2 mac");
    // Hand-build a well-framed but crypto-bogus envelope.
    drop(pending);

    let mut seed_envelope = [0u8; SEED_ENVELOPE_LEN];
    seed_envelope[0..4].copy_from_slice(b"AEAD");
    seed_envelope[4] = 0x03; // AeadAlg::AesGcm256
                             // Remaining bytes are zero -> tag verify fails.

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
    // FW destroys the slot on AEAD auth failure.
}

// ── Concurrency

#[test]
fn multiple_concurrent_sessions_have_distinct_ids() {
    // Kernel enforces 1 session per fd; use a second fd (avoids
    // re-acquiring the non-reentrant HW_TEST_LOCK).
    let dev_a = open_hw_dev();
    let dev_b = open_additional_hw_dev_fd(&dev_a);
    let a = open_session(&dev_a, CU, SessionType::PlainText).expect("first session must open");
    let b = open_session(&dev_b, CU, SessionType::PlainText).expect("second session must open");
    let id_a = a.session_id;
    let id_b = b.session_id;
    drop(a);
    drop(b);
    // Close before asserting.
    let close_a = session_close(&dev_a, id_a);
    let close_b = session_close(&dev_b, id_b);
    close_a.expect("close session A");
    close_b.expect("close session B");
    assert_ne!(id_a, id_b, "concurrent sessions must have distinct ids");
}

// ── Finish-side error paths (ported from the emu suite).

/// Finish against a mismatched session id must be rejected by
/// either the driver (fd-scoping) or the FW (pending-blob load).
#[test]
fn finish_unknown_session_id_rejected() {
    let dev = open_hw_dev();
    let pending = session_open_init(&dev, CU, SessionType::PlainText)
        .expect("phase-1 to establish a real pending slot must succeed");
    let real_id = pending.session_id;
    // Consume `pending`; the FW blob stays until finish/close.
    drop(pending);

    // Flip high bit -> can't collide with any real slot.
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

/// Replay `SessionOpenFinish` after success: pending blob was
/// consumed, slot is now Active, so the finish pre-check must fail.
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
    // Close the Active slot we set up.
    session_close(&dev, session_id).expect("SessionClose must succeed on hw");
}

// ── HW-only lifecycle: real silicon persists state across tests.

/// Open, close, reopen on the same fd — second open must succeed.
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

/// `SessionClose` with a mismatched id must be rejected by
/// either the driver (fd-scoping) or the FW.
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

    // Close the real fixture slot.
    session_close(&dev, real_id).expect("close of the real session must succeed");
}

// ── Point-validation negatives (hw-only; emu mocks accept anything).
// Only assert a generic FW rejection so a future error-code widening
// doesn't churn these tests.

/// All-zero `pk_init` is off-curve — FW must reject.
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

/// SEC1 prefix with garbage coordinates -> FW on-curve check rejects.
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

// ── Table exhaustion + recovery. Loop bound at 16 so future
// larger tables don't run forever; probes reject then close-all
// and confirm one more open succeeds.

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
                // Table full; verify it's an FW-side rejection.
                assert!(
                    matches!(e, azihsm_ddi_interface::DdiError::DdiError(_)),
                    "table-full rejection must be FW-side, got {e:?}",
                );
                rejection_seen = true;
                break;
            }
        }
    }

    // Close all before recovery so a failure doesn't leak slots.
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

// ── Per-session key uniqueness.

/// Two sequential CO+Authenticated handshakes must derive distinct
/// exported material and MAC keys. Sequential because real hw
/// rejects two concurrent Authenticated sessions.
#[test]
fn co_authenticated_derives_unique_keys_per_session() {
    let dev = open_hw_dev();

    // First handshake — snapshot, then close.
    let a = open_session(&dev, CO, SessionType::Authenticated)
        .expect("first CO+Authenticated handshake must succeed");
    let a_id = a.session_id;
    let a_tx = a.derive_mac_tx_key().expect("derive a tx");
    let a_rx = a.derive_mac_rx_key().expect("derive a rx");
    let a_exported = a.exported.clone();
    drop(a);
    session_close(&dev, a_id).expect("close first session must succeed");

    // Second handshake — VM ephemeral is regenerated per Phase-1.
    let b = open_session(&dev, CO, SessionType::Authenticated)
        .expect("second CO+Authenticated handshake must succeed");
    let b_id = b.session_id;
    let b_tx = b.derive_mac_tx_key().expect("derive b tx");
    let b_rx = b.derive_mac_rx_key().expect("derive b rx");
    let b_exported = b.exported.clone();
    drop(b);
    // Close before asserting.
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

// ── P-384 point-validation vectors: coordinate == field prime `p`.

/// P-384 field prime `p`, big-endian (matches MBOR `TEST_ECC_384_PUBLIC_KEY_X/Y_AS_PRIME`).
const P384_PRIME_BE: [u8; 48] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
];

/// Filler Y paired with prime-as-X (verbatim from MBOR `TEST_ECC_384_PUBLIC_KEY_X_AS_PRIME`).
const P384_INVALID_Y_FOR_X_AS_PRIME_BE: [u8; 48] = [
    0x53, 0xbf, 0xf4, 0x76, 0x31, 0x31, 0x33, 0xa3, 0x58, 0x3c, 0x11, 0x3d, 0xeb, 0x8d, 0xb6, 0xb7,
    0x47, 0x4a, 0xe3, 0x51, 0xd0, 0x38, 0x26, 0xac, 0xec, 0x11, 0x34, 0x33, 0x04, 0x0d, 0xc6, 0xc3,
    0x75, 0x37, 0xa1, 0x89, 0xdd, 0x4f, 0x66, 0x57, 0x72, 0xac, 0xc5, 0x3b, 0xb6, 0xc6, 0xb8, 0x0c,
];

/// Filler X paired with prime-as-Y (verbatim from MBOR `TEST_ECC_384_PUBLIC_KEY_Y_AS_PRIME`).
const P384_INVALID_X_FOR_Y_AS_PRIME_BE: [u8; 48] = [
    0xcf, 0x6b, 0x8d, 0x9a, 0x48, 0x75, 0xa9, 0x5a, 0x19, 0x89, 0x72, 0x18, 0xa4, 0x94, 0x4d, 0xef,
    0x0a, 0x93, 0xce, 0x5b, 0x8b, 0x8d, 0xf1, 0x37, 0x54, 0x09, 0x17, 0x89, 0xbc, 0xef, 0x69, 0xdb,
    0x6c, 0xa7, 0x9e, 0xf6, 0xb6, 0x4b, 0x5c, 0x13, 0xed, 0x3c, 0xbf, 0xed, 0x0b, 0x3d, 0xf1, 0x7e,
];

/// Pack (X, Y) as SEC1 uncompressed: `0x04 ‖ X_be ‖ Y_be`.
fn pack_sec1_uncompressed(x_be: &[u8; 48], y_be: &[u8; 48]) -> [u8; PK_INIT_LEN] {
    let mut out = [0u8; PK_INIT_LEN];
    out[0] = 0x04;
    out[1..49].copy_from_slice(x_be);
    out[49..97].copy_from_slice(y_be);
    out
}

/// pk_init with X = P-384 prime `p`: valid field element, off-curve; FW must reject.
#[test]
fn pk_init_x_as_prime_rejected() {
    let dev = open_hw_dev();
    let pk_init = pack_sec1_uncompressed(&P384_PRIME_BE, &P384_INVALID_Y_FOR_X_AS_PRIME_BE);
    let req = TborSessionOpenInitReq {
        psk_id: CU,
        session_type: SessionType::PlainText.to_u8(),
        suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
        pk_init,
    };
    let mut cookie = None;
    let err = dev
        .exec_op_tbor::<TborSessionOpenInitReq>(&req, None, &mut cookie)
        .expect_err("pk_init with X = P-384 prime must be rejected");
    assert!(
        matches!(err, azihsm_ddi_interface::DdiError::DdiError(_)),
        "expected FW-side rejection for X-as-prime pk_init, got {err:?}",
    );
}

/// Symmetric to `pk_init_x_as_prime_rejected`; guards against X-only validation bugs.
#[test]
fn pk_init_y_as_prime_rejected() {
    let dev = open_hw_dev();
    let pk_init = pack_sec1_uncompressed(&P384_INVALID_X_FOR_Y_AS_PRIME_BE, &P384_PRIME_BE);
    let req = TborSessionOpenInitReq {
        psk_id: CU,
        session_type: SessionType::PlainText.to_u8(),
        suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
        pk_init,
    };
    let mut cookie = None;
    let err = dev
        .exec_op_tbor::<TborSessionOpenInitReq>(&req, None, &mut cookie)
        .expect_err("pk_init with Y = P-384 prime must be rejected");
    assert!(
        matches!(err, azihsm_ddi_interface::DdiError::DdiError(_)),
        "expected FW-side rejection for Y-as-prime pk_init, got {err:?}",
    );
}

// ── Bit-flip on a valid ephemeral pk_init.

#[test]
fn pk_init_single_byte_tampered_rejected() {
    let dev = open_hw_dev();
    let ephemeral = azihsm_session_ex_crypto::generate_vm_ephemeral()
        .expect("generate_vm_ephemeral must succeed on the test host");
    let mut pk_init = ephemeral.pk_sec1;
    pk_init[8] ^= 0x01; // Inside X (X is bytes 1..49); avoids prefix + X/Y boundary.

    let req = TborSessionOpenInitReq {
        psk_id: CU,
        session_type: SessionType::PlainText.to_u8(),
        suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
        pk_init,
    };
    let mut cookie = None;
    let err = dev
        .exec_op_tbor::<TborSessionOpenInitReq>(&req, None, &mut cookie)
        .expect_err("single-bit-tampered pk_init must be rejected");
    assert!(
        matches!(err, azihsm_ddi_interface::DdiError::DdiError(_)),
        "expected FW-side rejection for tampered pk_init, got {err:?}",
    );
}

// ── Partition identity pub key must not rotate per handshake.

#[test]
fn partition_pk_hsm_stable_across_handshakes() {
    let dev = open_hw_dev();

    // pk_hsm is only surfaced on Phase-1 `PendingHandshake`; capture between phases.
    let pending_a =
        session_open_init(&dev, CU, SessionType::PlainText).expect("first Phase-1 must succeed");
    let pk_hsm_a = pending_a.pk_hsm;
    let handshake_a = session_open_finish(&dev, pending_a).expect("first Phase-2 must succeed");
    let a_id = handshake_a.session_id;
    drop(handshake_a);
    session_close(&dev, a_id).expect("close first session must succeed");

    let pending_b =
        session_open_init(&dev, CU, SessionType::PlainText).expect("second Phase-1 must succeed");
    let pk_hsm_b = pending_b.pk_hsm;
    let handshake_b = session_open_finish(&dev, pending_b).expect("second Phase-2 must succeed");
    let b_id = handshake_b.session_id;
    drop(handshake_b);
    session_close(&dev, b_id).expect("close second session must succeed");

    assert_eq!(
        pk_hsm_a, pk_hsm_b,
        "partition identity pub key must be stable across handshakes",
    );
}

// ── Concurrent open_session: race-safety of the slot allocator + undo wiring.
//    Main thread holds HW_TEST_LOCK; only backend `Dev` values cross threads.

const MULTI_THREADED_TOTAL: usize = 12;

/// Race N concurrent opens on distinct fds; winners must have distinct ids, losers clean FW rejections.
#[test]
fn open_session_multi_threaded_all_should_open() {
    let dev = open_hw_dev();

    let mut worker_fds: Vec<<azihsm_ddi::AzihsmDdi as azihsm_ddi_interface::Ddi>::Dev> = Vec::new();
    for _ in 0..MULTI_THREADED_TOTAL {
        worker_fds.push(open_additional_hw_dev_fd(&dev));
    }

    let mut handles = Vec::with_capacity(MULTI_THREADED_TOTAL);
    for fd in worker_fds {
        handles.push(std::thread::spawn(move || -> Result<
            (u16, <azihsm_ddi::AzihsmDdi as azihsm_ddi_interface::Ddi>::Dev),
            azihsm_ddi_interface::DdiError,
        > {
            let h = open_session(&fd, CU, SessionType::PlainText)?;
            let sid = h.session_id;
            drop(h);
            Ok((sid, fd))
        }));
    }

    let mut winners: Vec<(
        u16,
        <azihsm_ddi::AzihsmDdi as azihsm_ddi_interface::Ddi>::Dev,
    )> = Vec::new();
    let mut rejections: Vec<azihsm_ddi_interface::DdiError> = Vec::new();
    for h in handles {
        match h.join().expect("worker thread must not panic") {
            Ok(win) => winners.push(win),
            Err(e) => rejections.push(e),
        }
    }

    let winner_ids: Vec<u16> = winners.iter().map(|(id, _)| *id).collect();
    let mut sorted_ids = winner_ids.clone();
    sorted_ids.sort_unstable();
    sorted_ids.dedup();
    let unique_wins = sorted_ids.len();

    // Close winners before asserting so a failing assert never leaks slots.
    for (id, fd) in &winners {
        let _ = session_close(fd, *id);
    }

    assert!(
        !winner_ids.is_empty(),
        "at least one concurrent open_session must succeed; rejections = {rejections:?}",
    );
    assert_eq!(
        unique_wins,
        winner_ids.len(),
        "concurrent winners must have distinct session ids: {winner_ids:?}",
    );
    for err in &rejections {
        assert!(
            matches!(
                err,
                azihsm_ddi_interface::DdiError::DdiError(_)
                    | azihsm_ddi_interface::DdiError::DdiStatus(_)
            ),
            "concurrent open_session rejections must be FW/driver rejections, got {err:?}",
        );
    }
    if rejections.is_empty() {
        eprintln!(
            "open_session_multi_threaded_all_should_open: FW accepted all {MULTI_THREADED_TOTAL} \
             concurrent sessions without emitting any table-full rejection; race between success \
             and rejection branches not exercised at this thread count",
        );
    }
}

const SINGLE_WINNER_RACERS: usize = 8;

/// Fill to one free slot then race N threads; regression for `undo.push_session_destroy` on losers.
#[test]
fn open_session_multi_threaded_single_winner() {
    let dev = open_hw_dev();

    // Phase 1: probe capacity sequentially (ceiling 16, matches fills_table_then_recovers).
    let mut filler_fds: Vec<<azihsm_ddi::AzihsmDdi as azihsm_ddi_interface::Ddi>::Dev> = Vec::new();
    let mut filler_ids: Vec<u16> = Vec::new();
    let probe_ceiling = 16usize;
    for _ in 0..probe_ceiling {
        let fd = open_additional_hw_dev_fd(&dev);
        match open_session(&fd, CU, SessionType::PlainText) {
            Ok(h) => {
                filler_ids.push(h.session_id);
                filler_fds.push(fd);
                drop(h);
            }
            Err(_) => break,
        }
    }

    // Capacity exceeds ceiling: cannot set up a single-slot race — clean up + skip.
    if filler_fds.len() >= probe_ceiling {
        for (fd, id) in filler_fds.iter().zip(filler_ids.iter()) {
            let _ = session_close(fd, *id);
        }
        eprintln!(
            "open_session_multi_threaded_single_winner: FW capacity exceeds probe ceiling of \
             {probe_ceiling}; skipping single-slot race",
        );
        return;
    }

    // Phase 2: free exactly one slot.
    let freed_fd = filler_fds.pop().expect("at least one filler must exist");
    let freed_id = filler_ids.pop().expect("at least one filler id must exist");
    session_close(&freed_fd, freed_id).expect("close of freed filler slot must succeed");
    drop(freed_fd);

    // Phase 3: race SINGLE_WINNER_RACERS threads for the one slot.
    let mut racer_fds: Vec<<azihsm_ddi::AzihsmDdi as azihsm_ddi_interface::Ddi>::Dev> = Vec::new();
    for _ in 0..SINGLE_WINNER_RACERS {
        racer_fds.push(open_additional_hw_dev_fd(&dev));
    }

    let mut handles = Vec::with_capacity(SINGLE_WINNER_RACERS);
    for fd in racer_fds {
        handles.push(std::thread::spawn(move || -> Result<
            (u16, <azihsm_ddi::AzihsmDdi as azihsm_ddi_interface::Ddi>::Dev),
            azihsm_ddi_interface::DdiError,
        > {
            let h = open_session(&fd, CU, SessionType::PlainText)?;
            let sid = h.session_id;
            drop(h);
            Ok((sid, fd))
        }));
    }

    let mut winners: Vec<(
        u16,
        <azihsm_ddi::AzihsmDdi as azihsm_ddi_interface::Ddi>::Dev,
    )> = Vec::new();
    let mut rejections: Vec<azihsm_ddi_interface::DdiError> = Vec::new();
    for h in handles {
        match h.join().expect("racer thread must not panic") {
            Ok(win) => winners.push(win),
            Err(e) => rejections.push(e),
        }
    }

    let winner_count = winners.len();
    let rejection_count = rejections.len();
    for (id, fd) in &winners {
        let _ = session_close(fd, *id);
    }
    for (fd, id) in filler_fds.iter().zip(filler_ids.iter()) {
        let _ = session_close(fd, *id);
    }

    assert_eq!(
        winner_count, 1,
        "exactly one racer must win the single free slot (got {winner_count} winners, \
         {rejection_count} rejections: {rejections:?})",
    );
    assert_eq!(
        rejection_count,
        SINGLE_WINNER_RACERS - 1,
        "all non-winning racers must fail cleanly",
    );
    for err in &rejections {
        assert!(
            matches!(
                err,
                azihsm_ddi_interface::DdiError::DdiError(_)
                    | azihsm_ddi_interface::DdiError::DdiStatus(_)
            ),
            "single-winner losers must surface FW/driver rejections, got {err:?}",
        );
    }
}
