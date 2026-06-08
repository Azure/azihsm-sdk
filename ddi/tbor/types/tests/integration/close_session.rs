// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Phase 5a integration tests for the TBOR `CloseSession` command.
//!
//! `CloseSession` is a thin pass-through to
//! `HsmSessionManager::session_destroy`, which (a) tears down any
//! vault state bound to the session and (b) frees the logical slot.
//! It is valid for both `Active` and `Pending` slots; closing an
//! unknown/already-closed slot is a logical error from the FW.
//!
//! Tests serialised via [`serial_test::serial`] because the
//! emulator's session table is process-global.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_test_helpers::close_session;
use azihsm_ddi_tbor_test_helpers::open_session;
use azihsm_ddi_tbor_test_helpers::open_session_init;
use azihsm_fw_hsm_pal_traits::SessionType;
use serial_test::serial;

use crate::integration::common::fixture::open_dev;

const CO: u8 = 0;
const CU: u8 = 1;

// ---------------------------------------------------------------------------
// Happy paths — close an Active session
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn close_session_cu_plaintext_active_emu() {
    let dev = open_dev();
    let session = open_session(&dev, CU, SessionType::PlainText).expect("open CU PlainText");
    close_session(&dev, session.session_id).expect("close active CU session");
}

#[test]
#[serial]
fn close_session_co_authenticated_active_emu() {
    let dev = open_dev();
    let session =
        open_session(&dev, CO, SessionType::Authenticated).expect("open CO Authenticated");
    close_session(&dev, session.session_id).expect("close active CO session");
}

// ---------------------------------------------------------------------------
// Pending-slot close (between Phase 1 and Phase 2)
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn close_session_pending_slot_emu() {
    let dev = open_dev();
    let pending = open_session_init(&dev, CU, SessionType::PlainText)
        .expect("phase 1 init reserves a pending slot");
    close_session(&dev, pending.session_id).expect("close pending slot");
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn close_session_unknown_id_emu() {
    let dev = open_dev();
    let err = close_session(&dev, 0xFFFF).expect_err("close of unknown id must fail");
    assert!(
        matches!(err, azihsm_ddi_interface::DdiError::DdiError(_)),
        "expected FW-side rejection, got {err:?}",
    );
}

#[test]
#[serial]
fn close_session_double_close_emu() {
    let dev = open_dev();
    let session = open_session(&dev, CU, SessionType::PlainText).expect("open CU PlainText");
    close_session(&dev, session.session_id).expect("first close succeeds");
    let err = close_session(&dev, session.session_id)
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
#[serial]
fn close_session_then_reopen_emu() {
    let dev = open_dev();
    let first = open_session(&dev, CU, SessionType::PlainText).expect("first open");
    close_session(&dev, first.session_id).expect("close first");
    let second =
        open_session(&dev, CU, SessionType::PlainText).expect("reopen after close must succeed");
    // FW is free to reuse the freed slot id; we only assert the
    // second handshake completes end-to-end.
    close_session(&dev, second.session_id).expect("close second");
}
