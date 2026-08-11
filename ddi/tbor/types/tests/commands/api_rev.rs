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

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborApiRevReq;
#[cfg(feature = "emu")]
use azihsm_ddi_tbor_types::TborStatus;

#[cfg(feature = "emu")]
use crate::harness::assertions::assert_fw_rejects;
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
/// that would silently introduce per-call state (e.g.a version
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

/// Asserts the `ApiRev` protocol-range invariants.
///
/// The firmware must advertise a valid version range that includes the
/// bootstrap TBOR protocol version.
#[cfg(any(feature = "emu", feature = "sock"))]
fn assert_expected_api_rev(resp: &azihsm_ddi_tbor_types::TborApiRevResp, context: &str) {
    assert!(
        resp.min_ver <= resp.max_ver,
        "{context}: minimum supported version {} must not exceed maximum supported version {}",
        resp.min_ver,
        resp.max_ver,
    );

    assert!(
        (resp.min_ver..=resp.max_ver).contains(&1),
        "{context}: bootstrap TBOR version 1 must be inside the advertised range {}..={}",
        resp.min_ver,
        resp.max_ver,
    );
}

/// A3: Independent device contexts must advertise the same protocol
/// range.
///
/// This catches accidental initialization-order dependencies or
/// process-global mutable state in the emulator/backend.
#[cfg(feature = "emu")]
#[test]
fn api_rev_consistent_across_fresh_contexts() {
    let first = {
        let ctx = TestCtx::new();
        ctx.tbor(&TborApiRevReq::new())
            .expect("ApiRev from first fresh context")
    };

    let second = {
        let ctx = TestCtx::new();
        ctx.tbor(&TborApiRevReq::new())
            .expect("ApiRev from second fresh context")
    };

    assert_expected_api_rev(&first, "first fresh context");
    assert_expected_api_rev(&second, "second fresh context");

    assert_eq!(
        first, second,
        "fresh TestCtx instances must report identical ApiRev responses",
    );
}

/// A4: Repeated Pending → Active → Closed transitions must not affect
/// the stateless `ApiRev` response.
///
/// This exercises several allocations and releases of session slots
/// rather than checking only a single session lifecycle.
#[cfg(feature = "emu")]
#[test]
fn api_rev_stable_across_repeated_session_lifecycles() {
    let ctx = TestCtx::new();

    let baseline = ctx
        .tbor(&TborApiRevReq::new())
        .expect("baseline ApiRev before lifecycle loop");

    assert_expected_api_rev(&baseline, "lifecycle-loop baseline");

    for iteration in 0..8 {
        let pending = ctx
            .session_open_init(0, SessionType::Authenticated)
            .unwrap_or_else(|err| {
                panic!("SessionOpenInit failed during lifecycle iteration {iteration}: {err:?}")
            });

        let pending_resp = ctx.tbor(&TborApiRevReq::new()).unwrap_or_else(|err| {
            panic!(
                "ApiRev failed while session was Pending during iteration \
                     {iteration}: {err:?}"
            )
        });

        assert_eq!(
            pending_resp, baseline,
            "ApiRev changed while session was Pending during iteration {iteration}",
        );

        let session = ctx.session_open_finish(pending).unwrap_or_else(|err| {
            panic!(
                "SessionOpenFinish failed during lifecycle iteration \
                     {iteration}: {err:?}"
            )
        });

        let active_resp = ctx.tbor(&TborApiRevReq::new()).unwrap_or_else(|err| {
            panic!(
                "ApiRev failed while session was Active during iteration \
                     {iteration}: {err:?}"
            )
        });

        assert_eq!(
            active_resp, baseline,
            "ApiRev changed while session was Active during iteration {iteration}",
        );

        ctx.session_close(session.session_id).unwrap_or_else(|err| {
            panic!("SessionClose failed during lifecycle iteration {iteration}: {err:?}")
        });

        let closed_resp = ctx.tbor(&TborApiRevReq::new()).unwrap_or_else(|err| {
            panic!(
                "ApiRev failed after session close during iteration \
                     {iteration}: {err:?}"
            )
        });

        assert_eq!(
            closed_resp, baseline,
            "ApiRev changed after session close during iteration {iteration}",
        );
    }
}

/// A5: Creating a fresh request value for every invocation must
/// produce the same response.
///
/// This guards against request-instance identity or mutation leaking
/// into command handling.
#[cfg(feature = "emu")]
#[test]
fn api_rev_fresh_request_each_call() {
    let ctx = TestCtx::new();

    let baseline = ctx
        .tbor(&TborApiRevReq::new())
        .expect("baseline ApiRev with fresh request");

    for iteration in 0..16 {
        let request = TborApiRevReq::new();

        let resp = ctx
            .tbor(&request)
            .unwrap_or_else(|err| panic!("ApiRev failed for fresh request {iteration}: {err:?}"));

        assert_eq!(
            resp, baseline,
            "fresh request {iteration} produced a different ApiRev response",
        );
    }
}

/// A6: The socket transport must also remain stable across repeated
/// requests.
///
/// Session-state manipulation is intentionally restricted to the
/// emulator tests, but basic transport-independent statelessness is
/// still verified for `sock`.
#[cfg(feature = "sock")]
#[test]
fn api_rev_repeated_stable_sock() {
    let ctx = TestCtx::new();

    let baseline = ctx
        .tbor(&TborApiRevReq::new())
        .expect("baseline ApiRev over socket backend");

    assert_expected_api_rev(&baseline, "socket baseline");

    for iteration in 1..8 {
        let resp = ctx.tbor(&TborApiRevReq::new()).unwrap_or_else(|err| {
            panic!(
                "ApiRev over socket backend failed on iteration \
                     {iteration}: {err:?}"
            )
        });

        assert_eq!(
            resp, baseline,
            "socket ApiRev response changed on iteration {iteration}",
        );
    }
}

/// A7: Device erase must not alter the advertised TBOR protocol range.
///
/// `ApiRev` is a firmware capability query and must remain available with
/// the same response before and after persistent device state is erased.
#[cfg(feature = "emu")]
#[test]
fn api_rev_stable_across_erase() {
    let ctx = TestCtx::new();

    let before = ctx
        .tbor(&TborApiRevReq::new())
        .expect("ApiRev before erase");

    ctx.erase().expect("erase device");

    let after = ctx.tbor(&TborApiRevReq::new()).expect("ApiRev after erase");

    assert_eq!(before, EXPECTED);
    assert_eq!(after, before, "erase must not change ApiRev");
}

/// A8: A rejected session operation must not poison subsequent `ApiRev`
/// dispatch.
///
/// Closing an impossible session ID exercises an error path before verifying
/// that the stateless out-of-session handler remains usable.
#[cfg(feature = "emu")]
#[test]
fn api_rev_works_after_failed_session_operation() {
    let ctx = TestCtx::new();

    let baseline = ctx.tbor(&TborApiRevReq::new()).expect("baseline ApiRev");

    let err = ctx
        .session_close(u16::MAX)
        .expect_err("invalid session close should fail");

    assert_fw_rejects(&err, TborStatus::SessionNotFound);

    let after_error = ctx
        .tbor(&TborApiRevReq::new())
        .expect("ApiRev after failed session operation");

    assert_eq!(
        after_error, baseline,
        "failed session operation must not affect ApiRev",
    );
}

/// A9: The same immutable `TborApiRevReq` value can be reused.
///
/// This complements A5, which constructs a fresh request for each call, and
/// guards against accidental mutation or consumption of request state.
#[cfg(feature = "emu")]
#[test]
fn api_rev_request_can_be_reused() {
    let ctx = TestCtx::new();
    let req = TborApiRevReq::new();

    let first = ctx.tbor(&req).expect("first ApiRev");
    let second = ctx.tbor(&req).expect("second ApiRev");

    assert_eq!(first, EXPECTED);
    assert_eq!(second, first);
}
