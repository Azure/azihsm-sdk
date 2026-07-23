// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for TBOR `ApiRev`.
//!
//! `round_trip` exercises host → backend → fw `handle_tbor_op` →
//! response. `api_rev_repeated_stable` and
//! `api_rev_independent_of_session_state` guard against per-call or
//! session-scoped state leaking into the out-of-session handler.
//!
//! Backend is selected at compile time by
//! [`azihsm_ddi::AzihsmDdi::default`].

use azihsm_ddi_tbor_types::TborApiRevReq;

use crate::harness::TestCtx;

const EXPECTED: azihsm_ddi_tbor_types::TborApiRevResp = azihsm_ddi_tbor_types::TborApiRevResp {
    min_ver: 1,
    max_ver: 1,
};

#[test]
fn round_trip() {
    let ctx = TestCtx::new();
    let resp = ctx
        .tbor(&TborApiRevReq::new())
        .expect("TBOR ApiRev round-trip");
    assert_eq!(
        resp, EXPECTED,
        "firmware should report min=max=1 for the bootstrap TBOR protocol version",
    );
}

/// `ApiRev` is stateless — repeated invocations on the same device
/// handle return byte-identical responses. Catches any regression
/// that would silently introduce per-call state (e.g. a version
/// negotiation cache, a session-dependent code path) in the
/// dispatcher's only out-of-session in-band handler.
#[test]
fn api_rev_repeated_stable() {
    let ctx = TestCtx::new();
    let baseline = ctx.tbor(&TborApiRevReq::new()).expect("baseline ApiRev");
    assert_eq!(baseline, EXPECTED, "baseline must match expected");
    for i in 1..16 {
        let resp = ctx.tbor(&TborApiRevReq::new()).expect("repeated ApiRev");
        assert_eq!(resp, baseline, "ApiRev response changed on iteration {i}");
    }
}

/// `ApiRev` is independent of session-machine state — it returns the
/// same response while a Pending (init-only) handshake occupies a
/// session slot, and continues to do so after the slot transitions
/// to Active. Together with the gate test in `default_psk_gate.rs`
/// this proves the dispatcher never lets session state leak into the
/// out-of-session handler.
#[test]
fn api_rev_independent_of_session_state() {
    use azihsm_ddi_tbor_types::SessionType;

    let ctx = TestCtx::new();

    // No sessions outstanding.
    let pre = ctx
        .tbor(&TborApiRevReq::new())
        .expect("ApiRev before any session");
    assert_eq!(pre, EXPECTED);

    // CO Pending: init only, do not finish yet.
    let pending = ctx
        .session_open_init(0, SessionType::Authenticated)
        .expect("SessionOpenInit (CO/Authenticated) for pending-state probe");
    let during_pending = ctx
        .tbor(&TborApiRevReq::new())
        .expect("ApiRev with one Pending session slot");
    assert_eq!(during_pending, EXPECTED);

    // CO Active: finish the same handshake.
    let session = ctx
        .session_open_finish(pending)
        .expect("SessionOpenFinish for probe");
    let during_active = ctx
        .tbor(&TborApiRevReq::new())
        .expect("ApiRev with one Active session slot");
    assert_eq!(during_active, EXPECTED);

    // Cleanup.
    ctx.session_close(session.session_id)
        .expect("close probe session");
    let post = ctx.tbor(&TborApiRevReq::new()).expect("ApiRev after close");
    assert_eq!(post, EXPECTED);
}
