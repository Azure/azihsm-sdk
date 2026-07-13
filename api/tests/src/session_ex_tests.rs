// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR security-domain session API
//! (`HsmPartition::open_session_ex`).
//!
//! These go through the *public* `azihsm_api` surface — the two-phase
//! HPKE handshake plus the resulting `HsmSession` (V2) handle — against
//! the FW emulator, exactly as an external caller (and the native FFI)
//! would.

use azihsm_api::*;

use crate::emu_helpers::*;

/// Happy path: CO pairs with an Authenticated session and returns a
/// live `HsmSession` over the public API.
#[test]
fn open_session_ex_co_authenticated() {
    let _guard = EMU_LOCK.lock();
    let (part, rev) = fresh_emu_partition();

    let session = part
        .open_session_ex(rev, CO, HsmSessionExType::Authenticated)
        .expect("CO/Authenticated open_session_ex should succeed against emu");

    // The V2 session must carry the negotiated api revision through.
    let sess_rev = session.api_rev();
    assert_eq!(
        (sess_rev.major, sess_rev.minor),
        (rev.major, rev.minor),
        "session must echo the negotiated api revision"
    );
}

/// Happy path: CU pairs with a PlainText session.
#[test]
fn open_session_ex_cu_plaintext() {
    let _guard = EMU_LOCK.lock();
    let (part, rev) = fresh_emu_partition();

    let session = part
        .open_session_ex(rev, CU, HsmSessionExType::PlainText)
        .expect("CU/PlainText open_session_ex should succeed against emu");

    let sess_rev = session.api_rev();
    assert_eq!(
        (sess_rev.major, sess_rev.minor),
        (rev.major, rev.minor),
        "session must echo the negotiated api revision"
    );
}

/// Negative path: an unknown `psk_id` (neither CO nor CU) is rejected by
/// the FW during Phase 1.
#[test]
fn open_session_ex_rejects_unknown_psk_id() {
    let _guard = EMU_LOCK.lock();
    let (part, rev) = fresh_emu_partition();

    let result = part.open_session_ex(rev, 2, HsmSessionExType::Authenticated);

    assert!(result.is_err(), "unknown psk_id must not yield a session");
}
