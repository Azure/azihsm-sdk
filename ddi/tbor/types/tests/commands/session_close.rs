// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SessionClose` command.
//!
//! `SessionClose` is a thin pass-through to
//! `HsmSessionManager::session_destroy`, which (a) tears down any
//! vault state bound to the session and (b) frees the logical slot.
//! It is valid for both `Active` and `Pending` slots; closing an
//! unknown/already-closed slot is a logical error from the FW.
//!
//! Happy-path tests drive the [`SessionGuard`](crate::harness::SessionGuard)
//! RAII type: it opens, the test exercises, and either an explicit
//! `.close()` returns the `DdiResult` or `Drop` performs panic-safe
//! cleanup. Negative-path tests intentionally drive the low-level
//! [`TestCtx::session_open_init`] / [`TestCtx::session_close`]
//! methods so they can call close twice, close an unknown id, or
//! close a pending-only slot.
//!
//! Cross-test isolation comes from `open_dev`'s factory-reset; no
//! per-test cleanup is required.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::SessionType;

use crate::harness::TestCtx;

const CO: u8 = 0;
const CU: u8 = 1;

// ---------------------------------------------------------------------------
// Happy paths — close an Active session
// ---------------------------------------------------------------------------

#[test]
fn session_close_cu_plaintext_active_emu() {
    let ctx = TestCtx::new();
    let session = ctx.open_session(CU, SessionType::PlainText);
    session.close().expect("close active CU session");
}

#[test]
fn session_close_co_authenticated_active_emu() {
    let ctx = TestCtx::new();
    let session = ctx.open_session(CO, SessionType::Authenticated);
    session.close().expect("close active CO session");
}

// ---------------------------------------------------------------------------
// Pending-slot close (between Phase 1 and Phase 2) — intentional bypass
// of `SessionGuard` because no Finish is ever performed.
// ---------------------------------------------------------------------------

#[test]
fn session_close_pending_slot_emu() {
    let ctx = TestCtx::new();
    let pending = ctx
        .session_open_init(CU, SessionType::PlainText)
        .expect("phase 1 init reserves a pending slot");
    ctx.session_close(pending.session_id)
        .expect("close pending slot");
}

// ---------------------------------------------------------------------------
// Error paths — drive the low-level helper directly so the test can
// own the close-call shape (no real session vs. intentional double-close).
// ---------------------------------------------------------------------------

#[test]
fn session_close_unknown_id_emu() {
    let ctx = TestCtx::new();
    let err = ctx
        .session_close(0xFFFF)
        .expect_err("close of unknown id must fail");
    assert!(
        matches!(err, azihsm_ddi_interface::DdiError::DdiError(_)),
        "expected FW-side rejection, got {err:?}",
    );
}

#[test]
fn session_close_double_close_emu() {
    let ctx = TestCtx::new();
    // Take the `SessionHandshake` out of the guard via `.close()` so
    // we own the lifecycle for the second (failing) call. The first
    // close therefore must succeed — the test asserts the second.
    let session = ctx.open_session(CU, SessionType::PlainText);
    let session_id = session.session_id();
    session.close().expect("first close succeeds");
    let err = ctx
        .session_close(session_id)
        .expect_err("second close against the same id must fail");
    assert!(
        matches!(err, azihsm_ddi_interface::DdiError::DdiError(_)),
        "expected FW-side rejection on double-close, got {err:?}",
    );
}

// ---------------------------------------------------------------------------
// Close releases the slot for a subsequent open
// ---------------------------------------------------------------------------

#[test]
fn session_close_then_reopen_emu() {
    let ctx = TestCtx::new();
    let first = ctx.open_session(CU, SessionType::PlainText);
    first.close().expect("close first");
    // FW is free to reuse the freed slot id; we only assert the
    // second handshake completes end-to-end (guard drops it).
    let _second = ctx.open_session(CU, SessionType::PlainText);
}
