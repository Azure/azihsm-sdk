// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR dispatcher's default-PSK gate.
//!
//! The gate rejects in-session commands not on the bootstrap
//! allow-list when the calling role's partition PSK still matches the
//! compiled-in default (`DEFAULT_PSK_CO` / `DEFAULT_PSK_CU`).
//!
//! Out-of-session opcodes such as `ApiRev`, `SessionOpenInit`, and
//! `SessionOpenFinish` are never gated. In-session opcodes on the
//! bootstrap allow-list, such as `PskChange` and `SessionClose`, are
//! always permitted.
//!
//! Coverage in this file:
//!
//! * `ApiRev` bypasses the gate while PSKs are default.
//! * Supported CO and CU session-open flows work with default PSKs.
//! * `SessionClose` bypasses the gate for both roles.
//! * Repeated session close operations remain permitted.
//! * `PskChange` bypasses the gate while the CO PSK is default.
//! * A successful CO PSK rotation takes effect.
//! * The old CO PSK is rejected after rotation.
//! * An incorrect rotated PSK is rejected.
//! * A failed authentication attempt does not corrupt PSK state.
//! * CO can rotate its PSK more than once.
//! * The previous PSK is rejected after a second rotation.
//! * Rotating CO does not alter the CU PSK slot.
//! * CU activity does not alter the CO PSK slot.
//! * `ApiRev` remains available after rotation and during an active
//!   session.
//!
//! Each test receives a factory-reset device from
//! [`TestCtx::new`](crate::harness::TestCtx::new), so partition PSKs
//! begin at their canonical defaults.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::DEFAULT_PSK_CO;
use azihsm_ddi_tbor_types::DEFAULT_PSK_CU;
use azihsm_ddi_tbor_types::PSK_LEN;

use crate::commands::part_init::known_good_part_policy;
use crate::commands::part_init::mach_seed;
use crate::commands::part_init::pota_thumbprint;
use crate::harness::assertions::assert_fw_rejects;
use crate::harness::SessionOpenInitOptions;
use crate::harness::TestCtx;

const CO: u8 = 0;
const CU: u8 = 1;

/// First non-default CO PSK used by rotation tests.
const GATE_ROTATED_PSK_A: [u8; PSK_LEN] = [
    0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A,
    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
];

/// Second non-default CO PSK used to verify repeated rotation.
const GATE_ROTATED_PSK_B: [u8; PSK_LEN] = [
    0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C, 0x3C,
    0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3,
];

/// Incorrect non-default PSK used by negative authentication tests.
const GATE_WRONG_PSK: [u8; PSK_LEN] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
];

/// `ApiRev` is an out-of-session opcode and therefore never gated.
#[test]
fn default_psk_gate_api_rev_bypass() {
    let ctx = TestCtx::new();

    let _ = ctx.api_rev().expect("first ApiRev under default PSKs");

    let _ = ctx.api_rev().expect("second ApiRev under default PSKs");
}

/// Supported session-open flows must work while each role still uses
/// its compiled-in default PSK.
///
/// Supported combinations:
///
/// * CO: Authenticated
/// * CU: PlainText
#[test]
fn default_psk_gate_session_open_init_bypass() {
    let ctx = TestCtx::new();

    // Each role is probed sequentially on the same fd: hw enforces
    // `AZIHSM_MAX_SESSIONS_PER_FD = 1`, so the CO session must be
    // closed before CU's `SessionOpenInit` is issued. The gate is a
    // per-role property, so sequential probes prove it for both roles
    // without needing overlapping sessions.

    let opts_co =
        SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&DEFAULT_PSK_CO);

    let pending_co = ctx
        .session_open_init_with_options(opts_co)
        .expect("CO Authenticated init under default CO PSK");

    let session_co = ctx
        .session_open_finish(pending_co)
        .expect("CO Authenticated finish under default CO PSK");

    let opts_cu = SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&DEFAULT_PSK_CU);

    let pending_cu = ctx
        .session_open_init_with_options(opts_cu)
        .expect("CU PlainText init under default CU PSK");

    let session_cu = ctx
        .session_open_finish(pending_cu)
        .expect("CU PlainText finish under default CU PSK");

    ctx.session_close(session_co.session_id)
        .expect("close CO session");

    ctx.session_close(session_cu.session_id)
        .expect("close CU session");
}

/// `SessionClose` is on the bootstrap allow-list and must succeed
/// while the calling role's PSK remains at its default.
#[test]
fn default_psk_gate_session_close_bypass() {
    let ctx = TestCtx::new();

    let session_co = ctx.open_session(CO, SessionType::Authenticated);

    session_co
        .close()
        .expect("SessionClose must bypass gate while CO PSK is default");

    let session_cu = ctx.open_session(CU, SessionType::PlainText);

    session_cu
        .close()
        .expect("SessionClose must bypass gate while CU PSK is default");
}

/// Repeatedly opening and closing sessions must not alter allow-list
/// behavior.
#[test]
fn default_psk_gate_session_close_repeated_sessions_emu() {
    let ctx = TestCtx::new();

    for attempt in 1..=3 {
        let session = ctx.open_session(CO, SessionType::Authenticated);

        session.close().unwrap_or_else(|err| {
            panic!(
                "CO SessionClose attempt {attempt} must bypass the \
                 default-PSK gate: {err:?}"
            )
        });
    }

    for attempt in 1..=3 {
        let session = ctx.open_session(CU, SessionType::PlainText);

        session.close().unwrap_or_else(|err| {
            panic!(
                "CU SessionClose attempt {attempt} must bypass the \
                 default-PSK gate: {err:?}"
            )
        });
    }
}

/// `PskChange` is on the bootstrap allow-list and must succeed while
/// the CO PSK is still at its default.
#[test]
fn default_psk_gate_psk_change_bypass() {
    let ctx = TestCtx::new();
    let session = ctx.open_session(CO, SessionType::Authenticated);

    ctx.psk_change(session.handshake(), &GATE_ROTATED_PSK_A)
        .expect("PskChange must bypass gate while CO PSK is default");
}

/// Reopening with the rotated PSK proves that `PskChange` reached the
/// actual handler and replaced the stored CO credential.
#[test]
fn default_psk_gate_psk_change_co_rotation_takes_effect_emu() {
    let ctx = TestCtx::new();

    let session = ctx.open_session(CO, SessionType::Authenticated);

    ctx.psk_change(session.handshake(), &GATE_ROTATED_PSK_A)
        .expect("rotate CO PSK from default");

    session
        .close()
        .expect("SessionClose remains permitted after CO rotation");

    let opts =
        SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&GATE_ROTATED_PSK_A);

    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("CO SessionOpenInit with rotated PSK");

    let reopened = ctx
        .session_open_finish(pending)
        .expect("CO SessionOpenFinish with rotated PSK");

    ctx.session_close(reopened.session_id)
        .expect("close session opened with rotated CO PSK");
}

/// The original default CO PSK must stop authenticating after a
/// successful rotation.
#[test]
fn default_psk_gate_old_co_psk_rejected_after_rotation_emu() {
    let ctx = TestCtx::new();

    let session = ctx.open_session(CO, SessionType::Authenticated);

    ctx.psk_change(session.handshake(), &GATE_ROTATED_PSK_A)
        .expect("rotate CO PSK from default");

    session
        .close()
        .expect("close session used for CO PSK rotation");

    let old_psk_opts =
        SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&DEFAULT_PSK_CO);

    assert!(
        ctx.session_open_init_with_options(old_psk_opts).is_err(),
        "DEFAULT_PSK_CO must no longer authenticate after rotation"
    );

    let rotated_psk_opts =
        SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&GATE_ROTATED_PSK_A);

    let pending = ctx
        .session_open_init_with_options(rotated_psk_opts)
        .expect("rotated CO PSK must authenticate");

    let reopened = ctx
        .session_open_finish(pending)
        .expect("finish session using rotated CO PSK");

    ctx.session_close(reopened.session_id)
        .expect("close session authenticated with rotated CO PSK");
}

/// An incorrect non-default PSK must not authenticate after rotation.
///
/// A subsequent attempt using the correct rotated PSK must still
/// succeed, proving that the failed attempt did not corrupt stored PSK
/// state.
#[test]
fn default_psk_gate_wrong_rotated_psk_rejected_emu() {
    let ctx = TestCtx::new();

    let bootstrap = ctx.open_session(CO, SessionType::Authenticated);

    ctx.psk_change(bootstrap.handshake(), &GATE_ROTATED_PSK_A)
        .expect("rotate CO PSK");

    bootstrap.close().expect("close CO bootstrap session");

    let wrong_opts =
        SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&GATE_WRONG_PSK);

    assert!(
        ctx.session_open_init_with_options(wrong_opts).is_err(),
        "an incorrect non-default CO PSK must not authenticate"
    );

    let correct_opts =
        SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&GATE_ROTATED_PSK_A);

    let pending = ctx
        .session_open_init_with_options(correct_opts)
        .expect("correct rotated PSK must still authenticate");

    let reopened = ctx
        .session_open_finish(pending)
        .expect("finish session with correct rotated PSK");

    ctx.session_close(reopened.session_id)
        .expect("close session opened with correct rotated PSK");
}

/// CO must support a second PSK rotation after already moving away
/// from the compiled-in default.
#[test]
fn default_psk_gate_co_can_rotate_twice_emu() {
    let ctx = TestCtx::new();

    let bootstrap = ctx.open_session(CO, SessionType::Authenticated);

    ctx.psk_change(bootstrap.handshake(), &GATE_ROTATED_PSK_A)
        .expect("first CO PSK rotation: default to A");

    bootstrap
        .close()
        .expect("close session after first rotation");

    let opts_a =
        SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&GATE_ROTATED_PSK_A);

    let pending_a = ctx
        .session_open_init_with_options(opts_a)
        .expect("open CO session using PSK A");

    let session_a = ctx
        .session_open_finish(pending_a)
        .expect("finish CO session using PSK A");

    ctx.psk_change(&session_a, &GATE_ROTATED_PSK_B)
        .expect("second CO PSK rotation: A to B");

    ctx.session_close(session_a.session_id)
        .expect("close session after second rotation");

    let opts_b =
        SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&GATE_ROTATED_PSK_B);

    let pending_b = ctx
        .session_open_init_with_options(opts_b)
        .expect("open CO session using PSK B");

    let session_b = ctx
        .session_open_finish(pending_b)
        .expect("finish CO session using PSK B");

    ctx.session_close(session_b.session_id)
        .expect("close session authenticated with PSK B");
}

/// After the second rotation, PSK A must be rejected and PSK B must
/// authenticate successfully.
#[test]
fn default_psk_gate_previous_psk_rejected_after_second_rotation_emu() {
    let ctx = TestCtx::new();

    let bootstrap = ctx.open_session(CO, SessionType::Authenticated);

    ctx.psk_change(bootstrap.handshake(), &GATE_ROTATED_PSK_A)
        .expect("first CO PSK rotation: default to A");

    bootstrap
        .close()
        .expect("close session after first rotation");

    let opts_a =
        SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&GATE_ROTATED_PSK_A);

    let pending_a = ctx
        .session_open_init_with_options(opts_a)
        .expect("open session using PSK A");

    let session_a = ctx
        .session_open_finish(pending_a)
        .expect("finish session using PSK A");

    ctx.psk_change(&session_a, &GATE_ROTATED_PSK_B)
        .expect("second CO PSK rotation: A to B");

    ctx.session_close(session_a.session_id)
        .expect("close session after second rotation");

    let stale_opts =
        SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&GATE_ROTATED_PSK_A);

    assert!(
        ctx.session_open_init_with_options(stale_opts).is_err(),
        "PSK A must stop authenticating after rotation to PSK B"
    );

    let opts_b =
        SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&GATE_ROTATED_PSK_B);

    let pending_b = ctx
        .session_open_init_with_options(opts_b)
        .expect("PSK B must authenticate");

    let session_b = ctx
        .session_open_finish(pending_b)
        .expect("finish session using PSK B");

    ctx.session_close(session_b.session_id)
        .expect("close session authenticated with PSK B");
}

/// Rotating the CO PSK must not alter the CU PSK slot.
#[test]
fn default_psk_gate_co_rotation_does_not_change_cu_default_emu() {
    let ctx = TestCtx::new();

    let co_session = ctx.open_session(CO, SessionType::Authenticated);

    ctx.psk_change(co_session.handshake(), &GATE_ROTATED_PSK_A)
        .expect("rotate only the CO PSK");

    co_session
        .close()
        .expect("close CO bootstrap session after rotation");

    let opts = SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&DEFAULT_PSK_CU);

    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("CU PlainText init must still accept DEFAULT_PSK_CU");

    let cu_session = ctx
        .session_open_finish(pending)
        .expect("CU PlainText finish must still accept DEFAULT_PSK_CU");

    ctx.session_close(cu_session.session_id)
        .expect("close CU PlainText session");
}

/// Opening and closing a CU session must not alter the CO default PSK.
#[test]
fn default_psk_gate_cu_session_does_not_change_co_default_emu() {
    let ctx = TestCtx::new();

    let cu_session = ctx.open_session(CU, SessionType::PlainText);

    cu_session
        .close()
        .expect("close CU session while CU PSK is default");

    let co_session = ctx.open_session(CO, SessionType::Authenticated);

    ctx.psk_change(co_session.handshake(), &GATE_ROTATED_PSK_A)
        .expect("CO default PSK must remain valid after CU session");

    co_session.close().expect("close CO session after rotation");
}

/// `ApiRev` must remain available after CO PSK rotation.
#[test]
fn default_psk_gate_api_rev_bypass_after_co_rotation_emu() {
    let ctx = TestCtx::new();

    let session = ctx.open_session(CO, SessionType::Authenticated);

    ctx.psk_change(session.handshake(), &GATE_ROTATED_PSK_A)
        .expect("rotate CO PSK before ApiRev probe");

    session
        .close()
        .expect("close CO session before ApiRev probe");

    let _ = ctx
        .api_rev()
        .expect("ApiRev must remain ungated after CO PSK rotation");
}

/// `ApiRev` is out-of-session and must remain callable while a
/// default-PSK session is active.
#[test]
fn default_psk_gate_api_rev_bypass_while_session_active_emu() {
    let ctx = TestCtx::new();
    let session = ctx.open_session(CO, SessionType::Authenticated);

    let _ = ctx
        .api_rev()
        .expect("ApiRev must bypass gate while a CO session is active");

    session
        .close()
        .expect("close CO session after ApiRev probe");
}

/// Closing the same session twice must reject the second close without
/// affecting subsequently opened sessions.
#[test]
fn default_psk_gate_second_close_of_same_session_is_rejected_emu() {
    let ctx = TestCtx::new();

    let session = ctx.open_session(CO, SessionType::Authenticated);
    let session_id = session.handshake().session_id;

    session.close().expect("first SessionClose must succeed");

    assert!(
        ctx.session_close(session_id).is_err(),
        "second SessionClose for the same session must be rejected"
    );

    let replacement = ctx.open_session(CO, SessionType::Authenticated);

    replacement
        .close()
        .expect("failed duplicate close must not corrupt session state");
}
