// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for TBOR `GetApiRev`.
//!
//! `round_trip` exercises the full path host → backend (`emu` or `sock`)
//! → fw `handle_tbor_op` → response, so it is transport-agnostic.
//! `unsupported_on_mock` asserts the design contract that backends opt
//! in to TBOR.
//!
//! Pilot module for the [`TestCtx`](crate::harness::TestCtx)
//! migration — every test in this file constructs the ctx once and
//! drives every device interaction through its methods. Phase 6a
//! finished the migration of the session-state probe to the new
//! `ctx.open_session_init`/`finish`/`close_session` methods.

#![cfg(any(feature = "emu", feature = "mock", feature = "sock"))]

use azihsm_ddi_tbor_types::TborGetApiRevReq;

use crate::harness::TestCtx;

#[cfg(any(feature = "emu", feature = "sock"))]
const EXPECTED: azihsm_ddi_tbor_types::TborGetApiRevResp =
    azihsm_ddi_tbor_types::TborGetApiRevResp {
        min_protocol_version: 1,
        max_protocol_version: 1,
    };

#[cfg(any(feature = "emu", feature = "sock"))]
#[test]
fn round_trip() {
    let ctx = TestCtx::new();
    let resp = ctx
        .tbor(&TborGetApiRevReq::new())
        .expect("TBOR GetApiRev round-trip");
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
    let ctx = TestCtx::new();
    let baseline = ctx
        .tbor(&TborGetApiRevReq::new())
        .expect("baseline GetApiRev");
    assert_eq!(baseline, EXPECTED, "baseline must match expected");
    for i in 1..16 {
        let resp = ctx
            .tbor(&TborGetApiRevReq::new())
            .expect("repeated GetApiRev");
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
fn get_api_rev_independent_of_session_state_emu() {
    use azihsm_ddi_tbor_types::SessionType;

    let ctx = TestCtx::new();

    // No sessions outstanding.
    let pre = ctx
        .tbor(&TborGetApiRevReq::new())
        .expect("GetApiRev before any session");
    assert_eq!(pre, EXPECTED);

    // CO Pending: init only, do not finish yet.
    let pending = ctx
        .open_session_init(0, SessionType::Authenticated)
        .expect("OpenSessionInit (CO/Authenticated) for pending-state probe");
    let during_pending = ctx
        .tbor(&TborGetApiRevReq::new())
        .expect("GetApiRev with one Pending session slot");
    assert_eq!(during_pending, EXPECTED);

    // CO Active: finish the same handshake.
    let session = ctx
        .open_session_finish(pending)
        .expect("OpenSessionFinish for probe");
    let during_active = ctx
        .tbor(&TborGetApiRevReq::new())
        .expect("GetApiRev with one Active session slot");
    assert_eq!(during_active, EXPECTED);

    // Cleanup.
    ctx.close_session(session.session_id)
        .expect("close probe session");
    let post = ctx
        .tbor(&TborGetApiRevReq::new())
        .expect("GetApiRev after close");
    assert_eq!(post, EXPECTED);
}

#[cfg(all(feature = "mock", not(feature = "emu")))]
#[test]
fn unsupported_on_mock() {
    use crate::harness::assertions::assert_unsupported_encoding;

    let ctx = TestCtx::new();
    let err = ctx
        .tbor(&TborGetApiRevReq::new())
        .expect_err("mock backend must not implement exec_op_tbor");
    assert_unsupported_encoding(&err);
}
