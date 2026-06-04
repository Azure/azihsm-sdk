// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for TBOR `GetApiRev`.
//!
//! `round_trip_emu` exercises the full path host → emu backend → fw
//! `handle_tbor_op` → response. `unsupported_on_mock` asserts the
//! design contract that backends opt in to TBOR.
//!
//! Both tests need a real backend handle, so the module is entirely
//! gated on at least one backend feature being enabled.

#![cfg(any(feature = "emu", feature = "mock"))]

use crate::integration::common::fixture::open_dev;

#[cfg(feature = "emu")]
const EXPECTED: azihsm_ddi_tbor_types::TborGetApiRevResp =
    azihsm_ddi_tbor_types::TborGetApiRevResp {
        min_protocol_version: 1,
        max_protocol_version: 1,
    };

#[cfg(feature = "emu")]
#[test]
fn round_trip_emu() {
    use azihsm_ddi_tbor_test_helpers::helper_get_api_rev_tbor;

    let dev = open_dev();
    let resp = helper_get_api_rev_tbor(&dev).expect("TBOR GetApiRev round-trip");
    assert_eq!(
        resp, EXPECTED,
        "firmware should report min=max=1 for the bootstrap TBOR protocol version",
    );
}

/// A1: `GetApiRev` is stateless — repeated invocations on the same
/// device handle return byte-identical responses. Catches any
/// regression that would silently introduce per-call state (e.g. a
/// version negotiation cache, a session-dependent code path) in the
/// dispatcher's only out-of-session in-band handler.
#[cfg(feature = "emu")]
#[test]
fn get_api_rev_repeated_stable_emu() {
    use azihsm_ddi_tbor_test_helpers::helper_get_api_rev_tbor;

    let dev = open_dev();
    let baseline = helper_get_api_rev_tbor(&dev).expect("baseline GetApiRev");
    assert_eq!(baseline, EXPECTED, "baseline must match expected");
    for i in 1..16 {
        let resp = helper_get_api_rev_tbor(&dev).expect("repeated GetApiRev");
        assert_eq!(
            resp, baseline,
            "GetApiRev response changed on iteration {i}"
        );
    }
}

/// A2: `GetApiRev` is independent of session-machine state — it
/// returns the same response while a Pending (init-only) handshake
/// occupies a session slot, and continues to do so after the slot
/// transitions to Active. Together with the gate test in
/// `default_psk_gate.rs` this proves the dispatcher never lets
/// session state leak into the out-of-session handler.
#[cfg(feature = "emu")]
#[test]
#[serial_test::serial]
fn get_api_rev_independent_of_session_state_emu() {
    use azihsm_ddi_tbor_test_helpers::close_session;
    use azihsm_ddi_tbor_test_helpers::helper_get_api_rev_tbor;
    use azihsm_ddi_tbor_test_helpers::open_session_finish;
    use azihsm_ddi_tbor_test_helpers::open_session_init;
    use azihsm_fw_hsm_pal_traits::SessionType;

    let dev = open_dev();

    // No sessions outstanding.
    let pre = helper_get_api_rev_tbor(&dev).expect("GetApiRev before any session");
    assert_eq!(pre, EXPECTED);

    // CO Pending: init only, do not finish yet.
    let pending = open_session_init(&dev, 0, SessionType::Authenticated)
        .expect("OpenSessionInit (CO/Authenticated) for pending-state probe");
    let during_pending =
        helper_get_api_rev_tbor(&dev).expect("GetApiRev with one Pending session slot");
    assert_eq!(during_pending, EXPECTED);

    // CO Active: finish the same handshake.
    let session = open_session_finish(&dev, pending).expect("OpenSessionFinish for probe");
    let during_active =
        helper_get_api_rev_tbor(&dev).expect("GetApiRev with one Active session slot");
    assert_eq!(during_active, EXPECTED);

    // Cleanup.
    close_session(&dev, session.session_id).expect("close probe session");
    let post = helper_get_api_rev_tbor(&dev).expect("GetApiRev after close");
    assert_eq!(post, EXPECTED);
}

#[cfg(all(feature = "mock", not(feature = "emu")))]
#[test]
fn unsupported_on_mock() {
    use azihsm_ddi_tbor_test_helpers::helper_get_api_rev_tbor;

    use crate::integration::common::assertions::assert_unsupported_encoding;

    let dev = open_dev();
    let err =
        helper_get_api_rev_tbor(&dev).expect_err("mock backend must not implement exec_op_tbor");
    assert_unsupported_encoding(&err);
}
