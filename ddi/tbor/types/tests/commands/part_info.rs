// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the out-of-session TBOR `PartInfo` command.
//!
//! `round_trip` asserts the device/partition fields the firmware
//! reports for the default provisioned partition.
//! `part_info_repeated_stable` and
//! `part_info_independent_of_session_state` guard against per-call
//! or session-scoped state leaking into the out-of-session handler.
//! `part_info_reflects_part_init_transition` covers the
//! `Enabled → Initializing` lifecycle transition.
//!
//! Backend is selected at compile time by
//! [`azihsm_ddi::AzihsmDdi::default`].

use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::CO_PSK_ID;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborPartInfoReq;

use crate::commands::part_init::known_good_part_policy;
use crate::commands::part_init::mach_seed;
use crate::commands::part_init::pota_thumbprint;

/// `DdiDeviceKind::Physical` discriminant — uno is a physical device.
const DEVICE_KIND_PHYSICAL: u8 = 2;

/// `PartState::Enabled` discriminant — the default provisioned state of
/// the emulator partition before any `PartInit`.
const PART_STATE_ENABLED: u8 = 2;

/// `PartState::Initializing` discriminant — the state a partition enters
/// after a successful `PartInit` binds its PTA / policy / POTA thumb.
pub(crate) const PART_STATE_INITIALIZING: u8 = 4;

/// Assert the invariant device-level fields PartInfo reports for the
/// default provisioned partition, plus that the identity public key is
/// materialized (not all-zero).
fn assert_default_part_info(resp: &azihsm_ddi_tbor_types::TborPartInfoResp) {
    assert_eq!(
        resp.device_kind, DEVICE_KIND_PHYSICAL,
        "uno firmware must report a physical device kind",
    );
    assert_eq!(
        resp.part_state, PART_STATE_ENABLED,
        "default provisioned partition must be Enabled",
    );
    assert!(
        resp.pid_pub_key.iter().any(|&b| b != 0),
        "identity public key must be materialized (non-zero)",
    );
}

#[test]
fn round_trip() {
    let ctx = TestCtx::new();
    let resp = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("TBOR PartInfo round-trip");
    assert_default_part_info(&resp);
}

/// `PartInfo` is stateless with respect to repeated invocation — on a
/// quiescent partition (no intervening lifecycle command) every call
/// returns a byte-identical response. Catches any regression that would
/// silently introduce per-call state (e.g. a counter, a cached
/// allocation) into the out-of-session handler.
#[test]
fn part_info_repeated_stable() {
    let ctx = TestCtx::new();
    let baseline = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("baseline PartInfo");
    assert_default_part_info(&baseline);
    for i in 1..16 {
        let resp = ctx
            .tbor(&TborPartInfoReq::new())
            .expect("repeated PartInfo");
        assert_eq!(resp, baseline, "PartInfo response changed on iteration {i}",);
    }
}

/// `PartInfo` is independent of session-machine state — it returns a
/// byte-identical response while a Pending (init-only) handshake
/// occupies a session slot, after that slot transitions to Active, and
/// again once it is closed. Catches any regression that would let
/// session state leak into the out-of-session handler.
#[test]
fn part_info_independent_of_session_state() {
    let ctx = TestCtx::new();

    // No sessions outstanding.
    let pre = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo before any session");
    assert_default_part_info(&pre);

    // CO Pending: init only, do not finish yet.
    let pending = ctx
        .session_open_init(CO_PSK_ID, SessionType::Authenticated)
        .expect("SessionOpenInit (CO/Authenticated) for pending-state probe");
    let during_pending = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo with one Pending session slot");
    assert_eq!(
        during_pending, pre,
        "PartInfo changed while a session was Pending",
    );

    // CO Active: finish the same handshake.
    let session = ctx
        .session_open_finish(pending)
        .expect("SessionOpenFinish for probe");
    let during_active = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo with one Active session slot");
    assert_eq!(
        during_active, pre,
        "PartInfo changed while a session was Active",
    );

    // Cleanup.
    ctx.session_close(session.session_id)
        .expect("close probe session");
    let post = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo after close");
    assert_eq!(post, pre, "PartInfo changed after the session closed");
}

/// `PartInfo` reflects partition lifecycle transitions. A successful
/// `PartInit` moves the partition from `Enabled` to `Initializing`;
/// `PartInfo` must report the new `part_state` afterwards, while the
/// stable device and identity fields (device kind, PID, identity public
/// key, owner/manufacturer SVN) remain unchanged across the transition.
///
/// Closing the CO session used for initialization must not revert the
/// persistent partition lifecycle state or alter those stable fields.
#[test]
fn part_info_reflects_part_init_transition() {
    let ctx = TestCtx::new();

    // Before PartInit: default Enabled posture with a materialized
    // identity.
    let before = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo before PartInit");

    assert_default_part_info(&before);

    // Drive PartInit — rotate the CO PSK first to clear the default-PSK
    // gate, then bind PTA / policy / POTA thumb on the rotated session.
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    ctx.part_init(
        &session,
        &mach_seed(),
        &known_good_part_policy(),
        &pota_thumbprint(),
    )
    .expect("PartInit");

    // After PartInit: the lifecycle state advances to Initializing while
    // the stable device and identity fields remain unchanged.
    let after = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo after PartInit");

    assert_eq!(
        after.part_state, PART_STATE_INITIALIZING,
        "PartInfo must report Initializing after PartInit",
    );

    assert_eq!(
        after.device_kind, before.device_kind,
        "device kind must be stable across PartInit",
    );

    assert_eq!(after.pid, before.pid, "PID must be stable across PartInit",);

    assert_eq!(
        after.pid_pub_key, before.pid_pub_key,
        "identity public key must be stable across PartInit",
    );

    assert!(
        after.pid_pub_key.iter().any(|&b| b != 0),
        "identity public key must remain materialized after PartInit",
    );

    assert_eq!(
        after.owner_svn, before.owner_svn,
        "owner SVN must be stable across PartInit",
    );

    assert_eq!(
        after.mfgr_svn, before.mfgr_svn,
        "manufacturer SVN must be stable across PartInit",
    );

    // Closing the CO session must not roll back persistent partition
    // lifecycle state.
    ctx.session_close(session.session_id)
        .expect("close CO session");

    let after_close = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo after closing CO session");

    assert_eq!(
        after_close.part_state, PART_STATE_INITIALIZING,
        "closing the CO session must not revert partition lifecycle state",
    );

    assert_eq!(
        after_close.device_kind, after.device_kind,
        "device kind must remain stable after CO session closes",
    );

    assert_eq!(
        after_close.pid, after.pid,
        "PID must remain stable after CO session closes",
    );

    assert_eq!(
        after_close.pid_pub_key, after.pid_pub_key,
        "identity public key must remain stable after CO session closes",
    );

    assert!(
        after_close.pid_pub_key.iter().any(|&b| b != 0),
        "identity public key must remain materialized after CO session closes",
    );

    assert_eq!(
        after_close.owner_svn, after.owner_svn,
        "owner SVN must remain stable after CO session closes",
    );

    assert_eq!(
        after_close.mfgr_svn, after.mfgr_svn,
        "manufacturer SVN must remain stable after CO session closes",
    );
}

/// Repeated `PartInfo` calls must not mutate or interfere with a Pending
/// session handshake. The same pending handshake must still be finishable
/// after multiple out-of-session `PartInfo` requests.
///
/// This strengthens `part_info_independent_of_session_state` by verifying
/// not only that `PartInfo` observes the same partition data while a slot
/// is Pending, but also that repeated reads do not corrupt the Pending
/// session state.
#[test]
fn part_info_does_not_disturb_pending_session() {
    let ctx = TestCtx::new();

    let baseline = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("baseline PartInfo");
    assert_default_part_info(&baseline);

    let pending = ctx
        .session_open_init(CO_PSK_ID, SessionType::Authenticated)
        .expect("SessionOpenInit (CO/Authenticated)");

    for i in 0..16 {
        let resp = ctx
            .tbor(&TborPartInfoReq::new())
            .expect("PartInfo while session is Pending");

        assert_eq!(
            resp, baseline,
            "PartInfo changed during Pending session on iteration {i}",
        );
    }

    // If PartInfo accidentally mutated the session machine, finishing the
    // original Pending handshake would fail here.
    let session = ctx
        .session_open_finish(pending)
        .expect("Pending session must remain finishable after PartInfo calls");

    let active = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo after Pending session becomes Active");

    assert_eq!(
        active, baseline,
        "PartInfo changed after Pending session transitioned to Active",
    );

    ctx.session_close(session.session_id)
        .expect("close probe session");
}

/// Repeated session creation and teardown must not leak state into the
/// out-of-session `PartInfo` handler.
///
/// This exercises multiple Pending → Active → Closed transitions instead
/// of only one session lifecycle and catches accumulated/session-slot
/// cleanup bugs that may not appear on the first open/close cycle.
#[test]
fn part_info_stable_across_repeated_session_cycles() {
    let ctx = TestCtx::new();

    let baseline = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("baseline PartInfo");
    assert_default_part_info(&baseline);

    for i in 0..8 {
        let pending = ctx
            .session_open_init(CO_PSK_ID, SessionType::Authenticated)
            .expect("SessionOpenInit during repeated session cycle");

        let during_pending = ctx
            .tbor(&TborPartInfoReq::new())
            .expect("PartInfo during Pending session");

        assert_eq!(
            during_pending, baseline,
            "PartInfo changed during Pending state on session cycle {i}",
        );

        let session = ctx
            .session_open_finish(pending)
            .expect("SessionOpenFinish during repeated session cycle");

        let during_active = ctx
            .tbor(&TborPartInfoReq::new())
            .expect("PartInfo during Active session");

        assert_eq!(
            during_active, baseline,
            "PartInfo changed during Active state on session cycle {i}",
        );

        ctx.session_close(session.session_id)
            .expect("close repeated probe session");

        let after_close = ctx
            .tbor(&TborPartInfoReq::new())
            .expect("PartInfo after session close");

        assert_eq!(
            after_close, baseline,
            "PartInfo changed after session close on cycle {i}",
        );
    }
}

/// Once `PartInit` advances the partition to `Initializing`, repeated
/// `PartInfo` reads must remain stable and closing the CO session used for
/// initialization must not revert or otherwise change the partition state.
///
/// This distinguishes persistent partition lifecycle state from transient
/// session state.
#[test]
fn part_info_initializing_state_persists_after_session_close() {
    let ctx = TestCtx::new();

    let before = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo before PartInit");
    assert_default_part_info(&before);

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    ctx.part_init(
        &session,
        &mach_seed(),
        &known_good_part_policy(),
        &pota_thumbprint(),
    )
    .expect("PartInit");

    let initializing = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo immediately after PartInit");

    assert_eq!(
        initializing.part_state, PART_STATE_INITIALIZING,
        "partition must enter Initializing after PartInit",
    );

    // Repeated reads in the new lifecycle state should be identical.
    for i in 0..16 {
        let resp = ctx
            .tbor(&TborPartInfoReq::new())
            .expect("repeated PartInfo while Initializing");

        assert_eq!(
            resp, initializing,
            "PartInfo changed while Initializing on iteration {i}",
        );
    }

    ctx.session_close(session.session_id)
        .expect("close CO session used for PartInit");

    // Closing the session must not roll back persistent partition state.
    let after_close = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo after closing PartInit CO session");

    assert_eq!(
        after_close, initializing,
        "closing the CO session must not change initialized partition state",
    );

    assert_eq!(
        after_close.part_state, PART_STATE_INITIALIZING,
        "partition must remain Initializing after CO session closes",
    );
}

/// Repeated `PartInfo` calls must not mutate or corrupt an Active session.
///
/// This complements `part_info_does_not_disturb_pending_session`: after
/// completing the handshake, repeated out-of-session `PartInfo` requests
/// must leave the Active session valid and closeable.
#[test]
fn part_info_does_not_disturb_active_session() {
    let ctx = TestCtx::new();

    let baseline = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("baseline PartInfo");
    assert_default_part_info(&baseline);

    let pending = ctx
        .session_open_init(CO_PSK_ID, SessionType::Authenticated)
        .expect("SessionOpenInit (CO/Authenticated)");

    let session = ctx.session_open_finish(pending).expect("SessionOpenFinish");

    for i in 0..16 {
        let resp = ctx
            .tbor(&TborPartInfoReq::new())
            .expect("PartInfo while session is Active");

        assert_eq!(
            resp, baseline,
            "PartInfo changed during Active session on iteration {i}",
        );
    }

    // If PartInfo corrupted the Active session slot, closing the original
    // session would fail here.
    ctx.session_close(session.session_id)
        .expect("Active session must remain closeable after PartInfo calls");

    let after_close = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo after closing Active session");

    assert_eq!(
        after_close, baseline,
        "PartInfo changed after Active session closed",
    );
}

/// `PartInfo` remains stable while the partition is `Initializing`,
/// including across a rejected attempt to open a new session.
///
/// Once `PartInit` advances the partition to `Initializing`, opening a
/// new authenticated session is rejected. That rejected session operation
/// must not mutate the partition state or any fields reported by
/// the out-of-session `PartInfo` handler.
#[test]
fn part_info_initializing_independent_of_session_state() {
    let ctx = TestCtx::new();

    // Move the partition from Enabled to Initializing.
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    ctx.part_init(
        &session,
        &mach_seed(),
        &known_good_part_policy(),
        &pota_thumbprint(),
    )
    .expect("PartInit");

    ctx.session_close(session.session_id)
        .expect("close PartInit CO session");

    // Establish the PartInfo baseline while the partition is Initializing.
    let baseline = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo while Initializing");

    assert_eq!(
        baseline.part_state, PART_STATE_INITIALIZING,
        "partition must be Initializing after PartInit",
    );

    // SessionOpenInit is rejected while the partition is Initializing.
    // Do not unwrap/expect success here: rejection is the behavior under test.
    let open_result = ctx.session_open_init(CO_PSK_ID, SessionType::Authenticated);

    assert!(
        open_result.is_err(),
        "SessionOpenInit must be rejected while partition is Initializing",
    );

    // A rejected session-open attempt must not alter PartInfo.
    let after_rejected_open = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo after rejected SessionOpenInit");

    assert_eq!(
        after_rejected_open, baseline,
        "rejected SessionOpenInit changed PartInfo while Initializing",
    );

    assert_eq!(
        after_rejected_open.part_state, PART_STATE_INITIALIZING,
        "rejected SessionOpenInit must not change partition lifecycle state",
    );

    // Ensure PartInfo remains stable on subsequent reads after the rejected
    // session operation.
    for i in 0..8 {
        let resp = ctx
            .tbor(&TborPartInfoReq::new())
            .expect("repeated PartInfo after rejected SessionOpenInit");

        assert_eq!(
            resp, baseline,
            "PartInfo changed after rejected SessionOpenInit on iteration {i}",
        );
    }
}
