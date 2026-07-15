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
        .open_session_ex(
            rev,
            HsmSessionPsk::new(HsmPskId::CO),
            HsmSessionExType::Authenticated,
        )
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
        .open_session_ex(
            rev,
            HsmSessionPsk::new(HsmPskId::CU),
            HsmSessionExType::PlainText,
        )
        .expect("CU/PlainText open_session_ex should succeed against emu");

    let sess_rev = session.api_rev();
    assert_eq!(
        (sess_rev.major, sess_rev.minor),
        (rev.major, rev.minor),
        "session must echo the negotiated api revision"
    );
}

/// PSK-rotation round trip: after rotating the CO PSK from the default,
/// the partition accepts the new secret and rejects the default — the
/// full `change_psk` + optional-PSK-`open_session_ex` flow end to end.
#[test]
fn change_psk_rotates_co_psk() {
    let _guard = EMU_LOCK.lock();
    let (part, rev) = fresh_emu_partition();

    // A non-default replacement CO PSK.
    let new_psk = [0x5Au8; PSK_LEN];

    // Open with the default CO PSK, rotate it, then close the session.
    {
        let session = part
            .open_session_ex(
                rev,
                HsmSessionPsk::new(HsmPskId::CO),
                HsmSessionExType::Authenticated,
            )
            .expect("open with the default CO PSK");
        session
            .change_psk(&new_psk)
            .expect("rotate the CO PSK to the new secret");
    }

    // Reopening with the rotated secret must now succeed.
    part.open_session_ex(
        rev,
        HsmSessionPsk::with_psk(HsmPskId::CO, &new_psk),
        HsmSessionExType::Authenticated,
    )
    .expect("open with the rotated CO PSK should succeed");

    // Reopening with the (now stale) default CO PSK must be rejected.
    let stale = part.open_session_ex(
        rev,
        HsmSessionPsk::new(HsmPskId::CO),
        HsmSessionExType::Authenticated,
    );
    assert!(
        stale.is_err(),
        "the default CO PSK must be rejected after rotation",
    );
}
