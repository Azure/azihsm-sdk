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

use azihsm_ddi_tbor_types::TborPartInfoReq;

use crate::harness::TestCtx;
use crate::harness::CO_PSK_ID;

/// `DdiDeviceKind::Physical` discriminant — uno is a physical device.
const DEVICE_KIND_PHYSICAL: u8 = 2;

/// `PartState::Enabled` discriminant — the default provisioned state of
/// the emulator partition before any `PartInit`.
const PART_STATE_ENABLED: u8 = 2;

/// `PartState::Initializing` discriminant — the state a partition enters
/// after a successful `PartInit` binds its PTA / policy / POTA thumb.
const PART_STATE_INITIALIZING: u8 = 4;

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
    use azihsm_ddi_tbor_types::SessionType;

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
/// stable identity fields (PID, identity public key, owner/manufacturer
/// SVN) are unchanged across the transition. This is the property that
/// makes `PartInfo` more than a static device probe — it is the live
/// view of the bound partition's posture.
#[test]
fn part_info_reflects_part_init_transition() {
    use crate::commands::part_init::known_good_part_policy;
    use crate::commands::part_init::mach_seed;
    use crate::commands::part_init::pota_thumbprint;
    use crate::harness::bootstrap_rotated_co;
    use crate::harness::ROTATED_CO_PSK;

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
    // the identity and SVN lineage are unchanged.
    let after = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo after PartInit");
    assert_eq!(
        after.part_state, PART_STATE_INITIALIZING,
        "PartInfo must report Initializing after PartInit",
    );
    assert_eq!(after.pid, before.pid, "PID must be stable across PartInit",);
    assert_eq!(
        after.pid_pub_key, before.pid_pub_key,
        "identity public key must be stable across PartInit",
    );
    assert_eq!(
        after.owner_svn, before.owner_svn,
        "owner SVN must be stable across PartInit",
    );
    assert_eq!(
        after.mfgr_svn, before.mfgr_svn,
        "manufacturer SVN must be stable across PartInit",
    );

    ctx.session_close(session.session_id)
        .expect("close CO session");
}
