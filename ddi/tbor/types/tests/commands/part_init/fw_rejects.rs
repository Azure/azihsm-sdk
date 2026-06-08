// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `PartInit` rejects that fire **before** any partition-state
//! mutation: default-PSK dispatcher gate, CU-role handler gate, and
//! malformed-policy decode gate.  Each test asserts the canonical
//! [`TborStatus`] surfaced by the FW and relies on
//! [`super::bootstrap_rotated_co`] (where needed) to clear the
//! default-PSK arm before reaching the path under test.

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::PSK_LEN;

use super::bootstrap_rotated_co;
use super::known_good_part_policy;
use super::mach_seed;
use super::pota_thumbprint;
use super::CO;
use super::ROTATED_CO_PSK;
use crate::harness::assertions::assert_fw_rejects;
use crate::harness::OpenSessionInitOptions;
use crate::harness::SessionHandshake;
use crate::harness::TestCtx;

const CU: u8 = 1;

/// Non-default 32-byte CU PSK, used to clear the default-PSK gate
/// before exercising the CU role-reject path.  Distinct bytes from
/// [`ROTATED_CO_PSK`] so a copy/paste swap is loud.
const ROTATED_CU_PSK: [u8; PSK_LEN] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
];

/// Open a session of `role` + `sty` under the supplied PSK
/// (bypassing the partition default).
fn open_role_with(
    ctx: &TestCtx,
    role: u8,
    sty: SessionType,
    psk: &[u8; PSK_LEN],
) -> SessionHandshake {
    let opts = OpenSessionInitOptions::new(role, sty).with_psk(psk);
    let pending = ctx
        .open_session_init_with_options(opts)
        .expect("open_session_init under custom PSK");
    ctx.open_session_finish(pending)
        .expect("open_session_finish under custom PSK")
}

/// Default-PSK CO session: the TBOR dispatcher must reject `PartInit`
/// with [`TborStatus::DefaultPskMustRotate`] **before** the handler
/// runs.  Independent of partition state: the rejection lives in the
/// dispatcher gate, not in any setter.
#[test]
fn part_init_reject_default_psk_co_emu() {
    let ctx = TestCtx::new();

    let session = ctx.open_session(CO, SessionType::Authenticated);
    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(session.handshake(), &seed, &policy, &thumb)
        .expect_err("PartInit under default CO PSK must be rejected");
    assert_fw_rejects(&err, TborStatus::DefaultPskMustRotate);
}

/// CU session under a rotated PSK: the handler's CO-only role gate
/// must surface [`TborStatus::InvalidPermissions`].  The CU PSK is
/// rotated up-front so the dispatcher's default-PSK gate does not
/// fire first.
#[test]
fn part_init_reject_cu_session_emu() {
    let ctx = TestCtx::new();

    // Rotate CU PSK out of the default so we exercise the role gate,
    // not the default-PSK gate.  CU sessions are pinned to
    // `SessionType::PlainText` (CO-only is `Authenticated`).
    let bootstrap = ctx.open_session(CU, SessionType::PlainText);
    ctx.change_psk(bootstrap.handshake(), &ROTATED_CU_PSK)
        .expect("rotate CU PSK");
    bootstrap.close().expect("close bootstrap CU session");

    let session = open_role_with(&ctx, CU, SessionType::PlainText, &ROTATED_CU_PSK);
    let policy = known_good_part_policy();
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(&session, &seed, &policy, &thumb)
        .expect_err("PartInit on CU session must be rejected");
    assert_fw_rejects(&err, TborStatus::InvalidPermissions);
}

/// Rotated CO session with a syntactically invalid `PartPolicy`
/// (all-zero bytes — `version.major == 0` fails the canonical decode
/// gate in `policy::from_bytes`): the handler must reject with
/// [`TborStatus::InvalidArg`] **before** any setter runs, leaving
/// partition state untouched.
#[test]
fn part_init_reject_bad_policy_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let bad_policy = [0u8; PART_POLICY_LEN];
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    let err = ctx
        .part_init(&session, &seed, &bad_policy, &thumb)
        .expect_err("PartInit with malformed PartPolicy must be rejected");
    assert_fw_rejects(&err, TborStatus::InvalidArg);
}
