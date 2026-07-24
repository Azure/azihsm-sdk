// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SessionOpenInit` /
//! `SessionOpenFinish` two-phase session handshake.
//!
//! Backend is selected at compile time by
//! [`azihsm_ddi::AzihsmDdi::default`]. Happy-path sessions are owned
//! by a [`SessionGuard`](crate::harness::SessionGuard) that closes on
//! `Drop`; negative paths drive `session_open_init` /
//! `session_open_finish` on `TestCtx` directly.

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborSessionOpenFinishReq;
use azihsm_ddi_tbor_types::TborSessionOpenInitReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::PK_INIT_LEN;
use azihsm_ddi_tbor_types::SEED_ENVELOPE_LEN;
use azihsm_ddi_tbor_types::SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256;

use crate::harness::build_mac_fin;
use crate::harness::open_dev_with_path;
use crate::harness::session::open_session as open_session_on_dev;
use crate::harness::session::session_close as session_close_on_dev;
#[cfg(not(feature = "emu"))]
use crate::harness::session::session_open_finish as session_open_finish_on_dev;
#[cfg(not(feature = "emu"))]
use crate::harness::session::session_open_init as session_open_init_on_dev;
use crate::harness::TestCtx;

const CO: u8 = 0;
const CU: u8 = 1;

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

#[test]
fn open_session_co_authenticated_happy() {
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
fn open_session_cu_plaintext_happy() {
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
fn open_session_co_plaintext_rejected() {
    let ctx = TestCtx::new();
    let err = ctx
        .session_open_init(CO, SessionType::PlainText)
        .expect_err("CO + PlainText is not a permitted pairing");
    crate::harness::assertions::assert_fw_rejects(&err, TborStatus::InvalidSessionType);
}

#[test]
fn open_session_cu_authenticated_rejected() {
    let ctx = TestCtx::new();
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
    let ctx = TestCtx::new();
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
    let ctx = TestCtx::new();
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
    let ctx = TestCtx::new();
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
    let ctx = TestCtx::new();
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
    let ctx = TestCtx::new();
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
    let ctx = TestCtx::new();
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
    let ctx = TestCtx::new();
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
    let ctx = TestCtx::new();
    let a = ctx.open_session(CU, SessionType::PlainText);

    // Second session lives on its own Dev — on hw the kernel driver
    // enforces `AZIHSM_MAX_SESSIONS_PER_FD = 1`, so overlapping
    // sessions must sit on separate fds bound to the same underlying
    // device (`ctx.path()`).
    let dev_b = open_dev_with_path(ctx.path());
    let b = open_session_on_dev(&dev_b, CU, SessionType::PlainText)
        .expect("open second session on extra dev");

    assert_ne!(
        a.session_id(),
        b.session_id,
        "concurrent sessions must have distinct ids",
    );

    session_close_on_dev(&dev_b, b.session_id).expect("close session B on extra dev");
}

// ---------------------------------------------------------------------------
// Session-table exhaustion + recovery
//
// Iteratively opens sessions until the FW reports the table is full,
// then drops every extra fd and confirms one more open succeeds — the
// pending/active slot cleanup path must fully reclaim capacity.
//
// The table size differs by backend (emu FW has a small hardcoded
// table; hw silicon a larger one), so the loop is bounded generously
// at `MULTI_THREADED_TOTAL` and we assert a rejection was observed
// within that ceiling.
// ---------------------------------------------------------------------------

const MULTI_THREADED_TOTAL: usize = 12;

#[test]
fn open_session_fills_table_then_recovers() {
    let ctx = TestCtx::new();
    // Each concurrent session lives on its own extra `Dev` bound to
    // the same underlying device — required on hw where
    // `AZIHSM_MAX_SESSIONS_PER_FD = 1`. The Dev handles are kept
    // alive in the vec so their fds stay open while we probe capacity;
    // dropping the vec later closes every fd in one shot, which the
    // kernel driver must translate into per-session slot reclaim on
    // the FW side (that reclaim path is exactly what the recovery
    // assertion below exercises).
    let mut open_slots = Vec::new();
    let mut rejection_seen = false;

    for _ in 0..MULTI_THREADED_TOTAL {
        let dev = open_dev_with_path(ctx.path());
        match open_session_on_dev(&dev, CU, SessionType::PlainText) {
            Ok(h) => open_slots.push((dev, h.session_id)),
            Err(e) => {
                assert!(
                    matches!(
                        e,
                        azihsm_ddi_interface::DdiError::TborStatus(_)
                            | azihsm_ddi_interface::DdiError::DdiStatus(_)
                    ),
                    "expected FW/driver rejection, got {e:?}",
                );
                rejection_seen = true;
                break;
            }
        }
    }

    let slot_count = open_slots.len();
    assert!(
        rejection_seen,
        "capacity limit not observed within {slot_count} probes — either the backend supports \
         more concurrent CU sessions than the probe ceiling (bump the loop bound), or the \
         session table exhaustion path regressed",
    );

    // Recovery: drop every extra fd in one shot so the driver reclaims
    // their FW-side session slots, then one fresh open on the primary
    // ctx dev must succeed. Relying on fd-drop (rather than an
    // explicit close loop) is deliberate — the invariant we care
    // about is that fd-drop == slot-reclaim; if that isn't true, it's
    // a product bug worth surfacing.
    drop(open_slots);

    let recovered = ctx
        .open_session_raw(CU, SessionType::PlainText)
        .expect("session table must recover after all extra fds are dropped");
    ctx.session_close(recovered.session_id)
        .expect("SessionClose after recovery must succeed");
}

// ---------------------------------------------------------------------------
// Open / close / reopen
// ---------------------------------------------------------------------------

/// Open a session, close it, then open again. The second open must
/// succeed — guards against a stale slot or leaked FSM state that
/// would otherwise wedge the second attempt.
#[test]
fn open_close_reopen_same_slot() {
    let ctx = TestCtx::new();
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
    let ctx = TestCtx::new();

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
// Partition identity public key stability
// ---------------------------------------------------------------------------

/// `pk_hsm` (the partition identity pub key surfaced on Phase-1
/// `PendingHandshake`) must be stable across handshakes — it identifies
/// the partition, not the ephemeral session. Two sequential Phase-1s
/// must observe byte-identical `pk_hsm`; a rotation between handshakes
/// would break long-term binding assumed by higher-layer protocols.
#[test]
fn partition_pk_hsm_stable_across_handshakes() {
    let ctx = TestCtx::new();

    let pending_a = ctx
        .session_open_init(CU, SessionType::PlainText)
        .expect("first Phase-1 must succeed");
    let pk_hsm_a = pending_a.pk_hsm;
    let handshake_a = ctx
        .session_open_finish(pending_a)
        .expect("first Phase-2 must succeed");
    let a_id = handshake_a.session_id;
    ctx.session_close(a_id)
        .expect("close first session must succeed");

    let pending_b = ctx
        .session_open_init(CU, SessionType::PlainText)
        .expect("second Phase-1 must succeed");
    let pk_hsm_b = pending_b.pk_hsm;
    let handshake_b = ctx
        .session_open_finish(pending_b)
        .expect("second Phase-2 must succeed");
    let b_id = handshake_b.session_id;
    ctx.session_close(b_id)
        .expect("close second session must succeed");

    assert_eq!(
        pk_hsm_a, pk_hsm_b,
        "partition identity pub key must be stable across handshakes",
    );
}

// ---------------------------------------------------------------------------
// Point-validation negatives
//
// FW `EccPublicKeyValidation` checks that `pk_init` is a valid,
// non-identity point on the P-384 curve.
//
// Assert a generic FW-side rejection rather than pinning
// `EccPointValidationFailed` in case a future FW change collapses
// validation errors into a broader category (e.g. `InvalidArg`).
// ---------------------------------------------------------------------------

/// `pk_init` all zeros is trivially off-curve (and encodes the point
/// at infinity in some conventions) — FW must reject.
#[test]
fn pk_init_all_zero_rejected() {
    let ctx = TestCtx::new();
    let req = TborSessionOpenInitReq {
        psk_id: CU,
        session_type: SessionType::PlainText.to_u8(),
        suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
        pk_init: [0u8; PK_INIT_LEN],
    };
    let err = ctx
        .tbor(&req)
        .expect_err("all-zero pk_init must be rejected");
    crate::harness::assertions::assert_fw_rejects(&err, TborStatus::InvalidArg);
}

/// `pk_init` with the SEC1 uncompressed prefix (`0x04`) but garbage
/// coordinates that do not satisfy the P-384 curve equation. FW's
/// on-curve validation must reject.
#[test]
fn pk_init_not_on_curve_rejected() {
    let ctx = TestCtx::new();
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
    crate::harness::assertions::assert_fw_rejects(&err, TborStatus::EccPublicKeyValidationFailed);
}

// ---------------------------------------------------------------------------
// P-384 point-validation vectors: coordinate == field prime `p`
//
// Verbatim from MBOR `TEST_ECC_384_PUBLIC_KEY_X_AS_PRIME` /
// `TEST_ECC_384_PUBLIC_KEY_Y_AS_PRIME`. A coordinate equal to the
// field prime is a valid field element but off-curve — targeted
// regression for the on-curve validation stage.
// ---------------------------------------------------------------------------

/// P-384 field prime `p`, big-endian.
const P384_PRIME_BE: [u8; 48] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
];

/// Filler Y paired with prime-as-X (verbatim from MBOR vectors).
const P384_INVALID_Y_FOR_X_AS_PRIME_BE: [u8; 48] = [
    0x53, 0xbf, 0xf4, 0x76, 0x31, 0x31, 0x33, 0xa3, 0x58, 0x3c, 0x11, 0x3d, 0xeb, 0x8d, 0xb6, 0xb7,
    0x47, 0x4a, 0xe3, 0x51, 0xd0, 0x38, 0x26, 0xac, 0xec, 0x11, 0x34, 0x33, 0x04, 0x0d, 0xc6, 0xc3,
    0x75, 0x37, 0xa1, 0x89, 0xdd, 0x4f, 0x66, 0x57, 0x72, 0xac, 0xc5, 0x3b, 0xb6, 0xc6, 0xb8, 0x0c,
];

/// Filler X paired with prime-as-Y (verbatim from MBOR vectors).
const P384_INVALID_X_FOR_Y_AS_PRIME_BE: [u8; 48] = [
    0xcf, 0x6b, 0x8d, 0x9a, 0x48, 0x75, 0xa9, 0x5a, 0x19, 0x89, 0x72, 0x18, 0xa4, 0x94, 0x4d, 0xef,
    0x0a, 0x93, 0xce, 0x5b, 0x8b, 0x8d, 0xf1, 0x37, 0x54, 0x09, 0x17, 0x89, 0xbc, 0xef, 0x69, 0xdb,
    0x6c, 0xa7, 0x9e, 0xf6, 0xb6, 0x4b, 0x5c, 0x13, 0xed, 0x3c, 0xbf, 0xed, 0x0b, 0x3d, 0xf1, 0x7e,
];

/// Pack (X, Y) as SEC1 uncompressed: `0x04 || X_be || Y_be`.
fn pack_sec1_uncompressed(x_be: &[u8; 48], y_be: &[u8; 48]) -> [u8; PK_INIT_LEN] {
    let mut out = [0u8; PK_INIT_LEN];
    out[0] = 0x04;
    out[1..49].copy_from_slice(x_be);
    out[49..97].copy_from_slice(y_be);
    out
}

/// `pk_init` with X = P-384 prime `p`: valid field element, off-curve;
/// FW must reject.
#[test]
fn pk_init_x_as_prime_rejected() {
    let ctx = TestCtx::new();
    let pk_init = pack_sec1_uncompressed(&P384_PRIME_BE, &P384_INVALID_Y_FOR_X_AS_PRIME_BE);
    let req = TborSessionOpenInitReq {
        psk_id: CU,
        session_type: SessionType::PlainText.to_u8(),
        suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
        pk_init,
    };
    let err = ctx
        .tbor(&req)
        .expect_err("pk_init with X = P-384 prime must be rejected");
    crate::harness::assertions::assert_fw_rejects(&err, TborStatus::EccPublicKeyValidationFailed);
}

/// Symmetric to `pk_init_x_as_prime_rejected` — guards against
/// X-only validation bugs.
#[test]
fn pk_init_y_as_prime_rejected() {
    let ctx = TestCtx::new();
    let pk_init = pack_sec1_uncompressed(&P384_INVALID_X_FOR_Y_AS_PRIME_BE, &P384_PRIME_BE);
    let req = TborSessionOpenInitReq {
        psk_id: CU,
        session_type: SessionType::PlainText.to_u8(),
        suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
        pk_init,
    };
    let err = ctx
        .tbor(&req)
        .expect_err("pk_init with Y = P-384 prime must be rejected");
    crate::harness::assertions::assert_fw_rejects(&err, TborStatus::EccPublicKeyValidationFailed);
}

// ---------------------------------------------------------------------------
// Single-byte bit-flip on a valid ephemeral pk_init
//
// Generate a legitimate P-384 ephemeral, flip one bit in X, ship it.
// FW's on-curve validation must reject.
// ---------------------------------------------------------------------------

#[test]
fn pk_init_single_byte_tampered_rejected() {
    let ctx = TestCtx::new();
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
    let err = ctx
        .tbor(&req)
        .expect_err("single-bit-tampered pk_init must be rejected");
    crate::harness::assertions::assert_fw_rejects(&err, TborStatus::EccPointValidationFailed);
}

// ---------------------------------------------------------------------------
// Concurrency: multi-threaded races on the ctx (hw-only)
//
// Emu's `Arc<StdHsm>` is a process-global singleton and its TBOR
// handler chain is not reentrant across the two-phase handshake:
// concurrent inits clobber shared state mid-flight and surface as
// `SessionAuthFailure` / `SessionNotFound` at finish instead of the
// clean table-full / winner-takes-slot behaviour real FW produces.
// The property under test only holds on the native OS backend.
// ---------------------------------------------------------------------------

/// Race N concurrent opens; winners must have distinct session ids,
/// and any losers must surface as clean FW/driver rejections. Each
/// racing thread owns its own [`open_dev_with_path`] fd — hw requires
/// one fd per concurrent session (`AZIHSM_MAX_SESSIONS_PER_FD = 1`),
/// so `TestCtx` itself is not touched by the racers.
#[cfg(not(feature = "emu"))]
#[test]
fn open_session_multi_threaded_all_should_open() {
    let ctx = TestCtx::new();
    let path: &str = ctx.path();

    type Dev = <azihsm_ddi::AzihsmDdi as azihsm_ddi_interface::Ddi>::Dev;

    // Each entry holds the owning Dev + the session id so we can
    // close on the correct fd once the race resolves.
    let (winners, rejections) = std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(MULTI_THREADED_TOTAL);
        for _ in 0..MULTI_THREADED_TOTAL {
            handles.push(
                s.spawn(|| -> Result<(Dev, u16), azihsm_ddi_interface::DdiError> {
                    let dev = open_dev_with_path(path);
                    let pending = session_open_init_on_dev(&dev, CU, SessionType::PlainText)?;
                    let handshake = session_open_finish_on_dev(&dev, pending)?;
                    Ok((dev, handshake.session_id))
                }),
            );
        }
        let mut winners = Vec::new();
        let mut rejections = Vec::new();
        for h in handles {
            match h.join().expect("worker thread must not panic") {
                Ok(w) => winners.push(w),
                Err(e) => rejections.push(e),
            }
        }
        (winners, rejections)
    });

    let mut sorted_ids: Vec<u16> = winners.iter().map(|(_, sid)| *sid).collect();
    let winner_ids = sorted_ids.clone();
    sorted_ids.sort_unstable();
    sorted_ids.dedup();
    let unique_wins = sorted_ids.len();

    // Close winners on their owning fds before asserting so a failing
    // assert never leaves the session table dirty.
    for (dev, sid) in &winners {
        let _ = session_close_on_dev(dev, *sid);
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
                azihsm_ddi_interface::DdiError::TborStatus(_)
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

/// Fill to one free slot then race N threads for it. Regression for
/// FW's undo-on-loser path: every losing racer must see a clean
/// rejection and leave the session table intact for retry. Each
/// filler + racer holds its own `open_dev_with_path` fd — hw requires
/// one fd per concurrent session.
#[cfg(not(feature = "emu"))]
#[test]
fn open_session_multi_threaded_single_winner() {
    let ctx = TestCtx::new();
    let path: &str = ctx.path();

    type Dev = <azihsm_ddi::AzihsmDdi as azihsm_ddi_interface::Ddi>::Dev;

    // Phase 1: probe capacity sequentially; ceiling matches
    // fills_table_then_recovers so we don't loop forever on a
    // pathological build. Each filler session lives on its own Dev.
    let mut fillers = Vec::new();
    for _ in 0..MULTI_THREADED_TOTAL {
        let dev = open_dev_with_path(path);
        match session_open_init_on_dev(&dev, CU, SessionType::PlainText)
            .and_then(|pending| session_open_finish_on_dev(&dev, pending))
        {
            Ok(handshake) => fillers.push((dev, handshake.session_id)),
            Err(_) => break, // `dev` drops here — fd released cleanly.
        }
    }

    // Capacity exceeds ceiling: cannot set up a single-slot race — clean up + skip.
    if fillers.len() >= MULTI_THREADED_TOTAL {
        for (dev, sid) in &fillers {
            let _ = session_close_on_dev(dev, *sid);
        }
        eprintln!(
            "open_session_multi_threaded_single_winner: FW capacity exceeds probe ceiling of \
             {MULTI_THREADED_TOTAL}; skipping single-slot race",
        );
        return;
    }

    // Phase 2: free exactly one slot (close and drop the tail filler's Dev).
    let (freed_dev, freed_id) = fillers.pop().expect("at least one filler must exist");
    session_close_on_dev(&freed_dev, freed_id).expect("close of freed filler slot must succeed");
    drop(freed_dev);

    // Phase 3: race MULTI_THREADED_TOTAL threads for the one slot.
    let (winners, rejections) = std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(MULTI_THREADED_TOTAL);
        for _ in 0..MULTI_THREADED_TOTAL {
            handles.push(
                s.spawn(|| -> Result<(Dev, u16), azihsm_ddi_interface::DdiError> {
                    let dev = open_dev_with_path(path);
                    let pending = session_open_init_on_dev(&dev, CU, SessionType::PlainText)?;
                    let handshake = session_open_finish_on_dev(&dev, pending)?;
                    Ok((dev, handshake.session_id))
                }),
            );
        }
        let mut winners = Vec::new();
        let mut rejections = Vec::new();
        for h in handles {
            match h.join().expect("racer thread must not panic") {
                Ok(w) => winners.push(w),
                Err(e) => rejections.push(e),
            }
        }
        (winners, rejections)
    });

    let winner_count = winners.len();
    let rejection_count = rejections.len();
    for (dev, sid) in &winners {
        let _ = session_close_on_dev(dev, *sid);
    }
    for (dev, sid) in &fillers {
        let _ = session_close_on_dev(dev, *sid);
    }

    assert_eq!(
        winner_count, 1,
        "exactly one racer must win the single free slot (got {winner_count} winners, \
         {rejection_count} rejections: {rejections:?})",
    );
    assert_eq!(
        rejection_count,
        MULTI_THREADED_TOTAL - 1,
        "all non-winning racers must fail cleanly",
    );
    for err in &rejections {
        assert!(
            matches!(
                err,
                azihsm_ddi_interface::DdiError::TborStatus(_)
                    | azihsm_ddi_interface::DdiError::DdiStatus(_)
            ),
            "single-winner losers must surface FW/driver rejections, got {err:?}",
        );
    }
}
