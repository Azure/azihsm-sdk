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

use crate::harness::assertions::assert_fw_rejects;
use crate::harness::build_mac_fin;
use crate::harness::TestCtx;

const CO: u8 = 0;
const CU: u8 = 1;

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

#[test]
fn open_session_co_authenticated_happy() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open_session must succeed");
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
    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open_session must succeed");
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
    assert_fw_rejects(&err, TborStatus::InvalidSessionType);
}

#[test]
fn open_session_cu_authenticated_rejected() {
    let ctx = TestCtx::new();
    let err = ctx
        .session_open_init(CU, SessionType::Authenticated)
        .expect_err("CU + Authenticated is not a permitted pairing");
    assert_fw_rejects(&err, TborStatus::InvalidSessionType);
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
        assert_fw_rejects(&err, TborStatus::InvalidPskId);
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
    assert_fw_rejects(&err, TborStatus::SessionAuthFailure);
    // FW destroys the pending slot on MAC mismatch.
}

// ---------------------------------------------------------------------------
// Finish-side error paths
// ---------------------------------------------------------------------------

#[test]
fn session_open_finish_unknown_session_id() {
    // Pick a session id that cannot possibly correspond to a live
    // pending slot. The FW pre-check fails to load the blob.
    let ctx = TestCtx::new();
    let req = TborSessionOpenFinishReq {
        session_id: 0xFFFF,
        mac_fin: [0u8; 48],
        seed_envelope: [0u8; SEED_ENVELOPE_LEN],
    };
    let err = ctx
        .tbor(&req)
        .expect_err("finish against unknown session_id must fail");
    assert_fw_rejects(&err, TborStatus::SessionNotFound);
}

#[test]
fn open_session_double_finish() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open_session must succeed");
    // Replay the finish: pending slot is gone, FW must refuse.
    let req = TborSessionOpenFinishReq {
        session_id: session.session_id(),
        mac_fin: [0u8; 48],
        seed_envelope: [0u8; SEED_ENVELOPE_LEN],
    };
    let err = ctx
        .tbor(&req)
        .expect_err("second finish against the same slot must fail");
    assert_fw_rejects(&err, TborStatus::SessionNotPending);
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
    let ctx_a = TestCtx::new();
    let a = ctx_a
        .open_session(CU, SessionType::PlainText)
        .expect("open_session must succeed");

    // Second session lives on its own Dev — on hw the kernel driver
    // enforces `AZIHSM_MAX_SESSIONS_PER_FD = 1`, so overlapping
    // sessions must sit on separate fds bound to the same underlying
    // device (`ctx_a.path()`).
    let ctx_b = TestCtx::new_with_path(ctx_a.path());
    let b = ctx_b
        .open_session(CU, SessionType::PlainText)
        .expect("open second session on extra dev");

    assert_ne!(
        a.session_id(),
        b.session_id(),
        "concurrent sessions must have distinct ids",
    );

    // Both sessions close on drop via their SessionGuards.
}

// ---------------------------------------------------------------------------
// Per-fd session limit
// ---------------------------------------------------------------------------

/// Guards against a regression to the old "two `open_session` on the
/// same ctx succeed" behavior. On hw the kernel driver enforces
/// `AZIHSM_MAX_SESSIONS_PER_FD = 1`, so a second open on the fd that
/// already owns a live session must be rejected before FW is
/// dispatched. `exec_op_tbor`'s `map_ioctl_status_tbor` remaps that
/// driver-layer rejection to a `TborStatus`, so the caller sees a
/// TBOR-typed error for a TBOR command.
///
#[test]
fn open_session_second_on_same_fd_rejected() {
    let ctx = TestCtx::new();
    let _a = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("first open on a fresh fd must succeed");
    let err = ctx
        .open_session(CU, SessionType::PlainText)
        .expect_err("second open on the same fd must be rejected");
    assert_fw_rejects(&err, TborStatus::FileHandleSessionLimitReached);
}

// ---------------------------------------------------------------------------
// FW session-table capacity
//
// FW allocates a single 8-slot session table: slot 0 is reserved for
// CryptoOfficer (only 1 concurrent CO session), slots 1..=7 for
// CryptoUser (`CU_SESSION_LIMIT = 7` concurrent CU sessions). Limits
// are identical on emu (fw/plat/std) and hw (fw/plat/uno) — see
// `MAX_SESSIONS = 8` in
// `fw/plat/uno/fw/drivers/session_store/src/session_store.rs` and
// `fw/plat/std/pal/src/drivers/session.rs`.
// ---------------------------------------------------------------------------

const CU_SESSION_LIMIT: usize = 7;

// ---------------------------------------------------------------------------
// CU session-table exhaustion + recovery
//
// Opens exactly `CU_SESSION_LIMIT` CU sessions (all must succeed), then
// probes one more (must be rejected with `TborStatus`), then drops every
// extra fd and confirms one fresh open on the primary ctx succeeds —
// the pending/active slot cleanup path must fully reclaim capacity.
// Relying on fd-drop (rather than an explicit close loop) for the
// recovery is deliberate: the invariant we care about is
// `fd-drop == slot-reclaim`; if that isn't true, it's a product bug
// worth surfacing here.
// ---------------------------------------------------------------------------

#[test]
fn open_session_fills_cu_table_then_recovers() {
    let ctx = TestCtx::new();
    // Two-phase construction: allocate all secondary `TestCtx`s
    // first (each opens its own fd — required on hw where
    // `AZIHSM_MAX_SESSIONS_PER_FD = 1`), then borrow them to open
    // sessions and stash the `SessionGuard`s. The guards borrow
    // their ctx by reference, so ctxs must live at least as long as
    // guards; declaring ctxs first ensures rustc drops `guards`
    // before `ctxs`.
    let ctxs: Vec<_> = (0..CU_SESSION_LIMIT)
        .map(|_| TestCtx::new_with_path(ctx.path()))
        .collect();
    let mut guards: Vec<_> = ctxs
        .iter()
        .enumerate()
        .map(|(_i, c)| {
            c.open_session(CU, SessionType::PlainText)
                .unwrap_or_else(|e| {
                    panic!("CU session {_i} of {CU_SESSION_LIMIT} must succeed, got {e:?}")
                })
        })
        .collect();

    // One more CU open must be rejected — table is full.
    let overflow_ctx = TestCtx::new_with_path(ctx.path());
    let err = overflow_ctx
        .open_session(CU, SessionType::PlainText)
        .expect_err("open_session past CU limit must be rejected");
    assert_fw_rejects(&err, TborStatus::VaultSessionLimitReached);
    drop(overflow_ctx);

    // Recovery: drop the last guard only (its `Drop` sends
    // SessionClose). That frees exactly one CU slot — enough for a
    // fresh open on the primary ctx to succeed. The remaining guards
    // stay alive and close at end of scope.
    guards.pop().expect("guards must not be empty");

    let _recovered = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("session table must recover after freeing one slot");
    // `_recovered` closes on drop at end of scope.
}

// ---------------------------------------------------------------------------
// CO session-slot exhaustion + recovery
//
// CO has a single slot. Opening the first CO session must succeed,
// a second concurrent CO open must be rejected, and dropping the
// first fd must restore capacity.
// ---------------------------------------------------------------------------

#[test]
fn open_session_fills_co_slot_then_recovers() {
    let ctx = TestCtx::new();

    let ctx_first = TestCtx::new_with_path(ctx.path());
    let first = ctx_first
        .open_session(CO, SessionType::Authenticated)
        .expect("first CO session must succeed");

    let ctx_second = TestCtx::new_with_path(ctx.path());
    let err = ctx_second
        .open_session(CO, SessionType::Authenticated)
        .expect_err("second concurrent CO open must be rejected");
    assert_fw_rejects(&err, TborStatus::VaultSessionLimitReached);

    // Recovery: drop the first guard + fd; a fresh CO open must succeed.
    drop(first);
    drop(ctx_first);

    let _recovered = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("CO slot must recover after the first fd is dropped");
    // `_recovered` closes on drop at end of scope.
}

// ---------------------------------------------------------------------------
// Full session-table exhaustion (CO + CU together) + recovery
//
// The FW session table is a single 8-slot table shared across roles
// (1 CO slot + 7 CU slots). CO and CU exhaustion are exercised
// separately above, but this test drives both roles together to
// confirm the whole table can be filled in one go and that neither
// role's rejection path interferes with the other's.
//
// Sequence:
//  1. Open 1 CO + `CU_SESSION_LIMIT` CU sessions — every slot must
//     succeed.
//  2. One more CO open is rejected (CO slot occupied).
//  3. One more CU open is rejected (all CU slots occupied).
//  4. Drop a single CU guard; a fresh CU open must succeed while
//     the CO slot stays full — proves per-role slot accounting.
//  5. Drop the CO guard + fd; a fresh CO open must succeed —
//     proves the CO slot reclaims independently.
// ---------------------------------------------------------------------------

#[test]
fn open_session_fills_full_table_then_recovers() {
    let ctx = TestCtx::new();

    // CO slot: one guard + its own fd (hw needs one fd per session).
    let ctx_co = TestCtx::new_with_path(ctx.path());
    let co_guard = ctx_co
        .open_session(CO, SessionType::Authenticated)
        .expect("CO session must succeed");

    // CU slots: `CU_SESSION_LIMIT` guards, each on its own fd.
    let cu_ctxs: Vec<_> = (0..CU_SESSION_LIMIT)
        .map(|_| TestCtx::new_with_path(ctx.path()))
        .collect();
    let mut cu_guards: Vec<_> = cu_ctxs
        .iter()
        .enumerate()
        .map(|(_i, c)| {
            c.open_session(CU, SessionType::PlainText)
                .unwrap_or_else(|e| {
                    panic!("CU session {_i} of {CU_SESSION_LIMIT} must succeed, got {e:?}")
                })
        })
        .collect();

    // Table is full — one more CO open must be rejected.
    let overflow_co_ctx = TestCtx::new_with_path(ctx.path());
    let err_co = overflow_co_ctx
        .open_session(CO, SessionType::Authenticated)
        .expect_err("second concurrent CO open must be rejected");
    assert_fw_rejects(&err_co, TborStatus::VaultSessionLimitReached);
    drop(overflow_co_ctx);

    // One more CU open must be rejected too.
    let overflow_cu_ctx = TestCtx::new_with_path(ctx.path());
    let err_cu = overflow_cu_ctx
        .open_session(CU, SessionType::PlainText)
        .expect_err("open_session past CU limit must be rejected");
    assert_fw_rejects(&err_cu, TborStatus::VaultSessionLimitReached);
    drop(overflow_cu_ctx);

    // Recovery-1: drop one CU guard. That frees exactly one CU slot;
    // a fresh CU open on a new fd must succeed. CO stays full.
    cu_guards.pop().expect("cu_guards must not be empty");
    let ctx_recover_cu = TestCtx::new_with_path(ctx.path());
    let _recovered_cu = ctx_recover_cu
        .open_session(CU, SessionType::PlainText)
        .expect("CU slot must recover after freeing one CU guard");

    // Recovery-2: drop the CO guard + its fd. A fresh CO open on a
    // new fd must succeed. (A new fd is required because on hw
    // `AZIHSM_MAX_SESSIONS_PER_FD = 1`, so we cannot reuse
    // `ctx_recover_cu` — its fd already holds the CU session opened
    // in Recovery-1.)
    drop(co_guard);
    drop(ctx_co);
    let ctx_recover_co = TestCtx::new_with_path(ctx.path());
    let _recovered_co = ctx_recover_co
        .open_session(CO, SessionType::Authenticated)
        .expect("CO slot must recover after CO fd is dropped");
    // Remaining guards close on drop at end of scope.
}

// ---------------------------------------------------------------------------
// Open, close, open new session
// ---------------------------------------------------------------------------

/// Open a session, close it, then open a new one. The second open
/// must succeed — guards against a stale slot or leaked FSM state
/// that would otherwise wedge the second attempt.
#[test]
fn open_close_then_open_new_session() {
    let ctx = TestCtx::new();
    let first = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("first handshake must succeed");
    first.close().expect("first SessionClose must succeed");

    let second = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open new session after close must succeed");
    second.close().expect("second SessionClose must succeed");
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
        .open_session(CO, SessionType::Authenticated)
        .expect("first CO+Authenticated handshake must succeed");
    let a_tx = a.handshake().derive_mac_tx_key().expect("derive a tx");
    let a_rx = a.handshake().derive_mac_rx_key().expect("derive a rx");
    let a_exported = a.handshake().exported.clone();
    a.close().expect("close first session must succeed");

    let b = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("second CO+Authenticated handshake must succeed");
    let b_tx = b.handshake().derive_mac_tx_key().expect("derive b tx");
    let b_rx = b.handshake().derive_mac_rx_key().expect("derive b rx");
    let b_exported = b.handshake().exported.clone();
    // Close before asserting so a failing assertion never leaks.
    b.close().expect("close second session must succeed");

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
    assert_fw_rejects(&err, TborStatus::InvalidArg);
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
    assert_fw_rejects(&err, TborStatus::EccPublicKeyValidationFailed);
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
    assert_fw_rejects(&err, TborStatus::EccPublicKeyValidationFailed);
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
    assert_fw_rejects(&err, TborStatus::EccPublicKeyValidationFailed);
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
    assert_fw_rejects(&err, TborStatus::EccPointValidationFailed);
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

/// Race exactly `CU_SESSION_LIMIT` concurrent CU opens; all must
/// succeed with distinct session ids and no rejections. Each racing
/// thread owns its own [`TestCtx`] fd — hw requires one fd per
/// concurrent session (`AZIHSM_MAX_SESSIONS_PER_FD = 1`), so the
/// primary `ctx` itself is not touched by the racers.
#[cfg(not(feature = "emu"))]
#[test]
fn open_session_multi_threaded_all_should_open() {
    let ctx = TestCtx::new();
    let path = ctx.path();

    // Pre-allocate one ctx per racer on the main thread so the
    // spawned workers can borrow them and return `SessionGuard<'_>`
    // values whose borrow outlives `thread::scope`.
    let ctxs: Vec<_> = (0..CU_SESSION_LIMIT)
        .map(|_| TestCtx::new_with_path(path))
        .collect();

    let results: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = ctxs
            .iter()
            .map(|c| s.spawn(move || c.open_session(CU, SessionType::PlainText)))
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("worker thread must not panic"))
            .collect()
    });

    let (winner_results, rejections): (Vec<_>, Vec<_>) =
        results.into_iter().partition(Result::is_ok);
    let winners: Vec<_> = winner_results.into_iter().map(Result::unwrap).collect();
    let rejections: Vec<_> = rejections.into_iter().map(Result::unwrap_err).collect();

    let mut sorted_ids: Vec<_> = winners.iter().map(|g| g.session_id()).collect();
    let winner_ids = sorted_ids.clone();
    sorted_ids.sort_unstable();
    sorted_ids.dedup();
    let unique_wins = sorted_ids.len();

    assert!(
        rejections.is_empty(),
        "all {CU_SESSION_LIMIT} concurrent CU opens must succeed; observed rejections: \
         {rejections:?}",
    );
    assert_eq!(
        winner_ids.len(),
        CU_SESSION_LIMIT,
        "expected {CU_SESSION_LIMIT} winning session ids, got {winner_ids:?}",
    );
    assert_eq!(
        unique_wins, CU_SESSION_LIMIT,
        "concurrent winners must have distinct session ids: {winner_ids:?}",
    );
}
