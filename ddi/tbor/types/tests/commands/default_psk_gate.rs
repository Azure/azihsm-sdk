// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR dispatcher's default-PSK gate.
//!
//! The gate (see `fw/core/lib/src/ddi/tbor/mod.rs::dispatch`) rejects
//! in-session commands not on the bootstrap allow-list when the
//! calling role's partition PSK still matches its compiled-in default
//! (`DEFAULT_PSK_CO` / `DEFAULT_PSK_CU`). Out-of-session opcodes
//! (`ApiRev`, `SessionOpenInit`, `SessionOpenFinish`) are never
//! gated; the in-session opcodes `PskChange` and `SessionClose` are
//! on the allow-list and are always permitted.
//!
//! Coverage:
//! * Out-of-session opcodes bypass the gate: `ApiRev`,
//!   `SessionOpenInit`.
//! * Allow-listed in-session opcodes bypass the gate: `PskChange`,
//!   `SessionClose`.
//! * A non-allow-listed in-session opcode (`PartInit`) is rejected
//!   at dispatch with `DefaultPskMustRotate` before any handler
//!   mutation — safe to run on real silicon.
//!
//! Each test inherits a factory-reset device from `TestCtx::new`, so
//! partition PSKs are at their canonical defaults on entry.

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
use crate::harness::CO_PSK_ID as CO;
use crate::harness::CU_PSK_ID as CU;

/// Non-default PSK used as the rotation target for the `PskChange`
/// bypass test. Distinct from the constant used in `psk_change.rs` so
/// a leaked rotation from this file is trivially identifiable.
const GATE_ROTATED_PSK: [u8; PSK_LEN] = [
    0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A,
    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
];

/// `ApiRev` is out-of-session and therefore never gated. It must
/// succeed even when both partition PSKs are at their compiled-in
/// defaults. Two probes back-to-back confirm the gate is stateless.
#[test]
fn default_psk_gate_api_rev_bypass() {
    let ctx = TestCtx::new();
    let _ = ctx.api_rev().expect("first ApiRev under default PSK");
    let _ = ctx.api_rev().expect("second ApiRev under default PSK");
}

/// `SessionOpenInit` is out-of-session and therefore never gated.
/// Verified for both roles since each is bound to a distinct PSK slot.
#[test]
fn default_psk_gate_session_open_init_bypass() {
    let ctx = TestCtx::new();

    // Each role is probed sequentially on the same fd: hw enforces
    // `AZIHSM_MAX_SESSIONS_PER_FD = 1`, so the CO session must be
    // closed before CU's `SessionOpenInit` is issued. The gate is a
    // per-role property, so sequential probes prove it for both roles
    // without needing overlapping sessions.

    // CO + Authenticated under default CO PSK.
    let opts_co =
        SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&DEFAULT_PSK_CO);
    let pending_co = ctx
        .session_open_init_with_options(opts_co)
        .expect("CO init under default PSK");
    let session_co = ctx
        .session_open_finish(pending_co)
        .expect("CO finish under default PSK");
    ctx.session_close(session_co.session_id)
        .expect("close CO session");

    // CU + PlainText under default CU PSK.
    let opts_cu = SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&DEFAULT_PSK_CU);
    let pending_cu = ctx
        .session_open_init_with_options(opts_cu)
        .expect("CU init under default PSK");
    let session_cu = ctx
        .session_open_finish(pending_cu)
        .expect("CU finish under default PSK");
    ctx.session_close(session_cu.session_id)
        .expect("close CU session");
}

/// `SessionClose` is on the allow-list — it must succeed while the
/// role's PSK is still default. Exercised for both roles.
#[test]
fn default_psk_gate_session_close_bypass() {
    let ctx = TestCtx::new();

    let session_co = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open_session must succeed");
    session_co
        .close()
        .expect("SessionClose must bypass gate while CO PSK is default");

    let session_cu = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open_session must succeed");
    session_cu
        .close()
        .expect("SessionClose must bypass gate while CU PSK is default");
}

/// `PskChange` is on the allow-list — it must succeed while the
/// role's PSK is still default. This is exactly the bootstrap flow:
/// open under default, rotate.
///
/// Exercised for the CO role; the CU path is functionally identical
/// and is already covered by `psk_change_happy_cu` in `psk_change.rs`.
#[test]
fn default_psk_gate_psk_change_bypass() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open_session must succeed");
    ctx.psk_change(session.handshake(), &GATE_ROTATED_PSK)
        .expect("PskChange must bypass gate while CO PSK is default");
}

/// A non-allow-listed in-session opcode (`PartInit`) is rejected at
/// dispatch with `DefaultPskMustRotate`. The FW returns the gate
/// error before any partition-state mutation, so this is safe to run
/// on real silicon.
#[test]
fn default_psk_gate_part_init_rejected() {
    let ctx = TestCtx::new();
    let session = ctx
        .open_session(CO, SessionType::Authenticated)
        .expect("open_session must succeed");

    let err = ctx
        .part_init(
            session.handshake(),
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
        )
        .expect_err("PartInit under default PSK must be gated");
    assert_fw_rejects(&err, TborStatus::DefaultPskMustRotate);
}

/// `SessionOpenInit` is out-of-session and per-role, so parallel opens
/// against distinct roles on distinct fds must both succeed while both
/// partition PSKs are still at their compiled-in defaults. Regression
/// for the gate bleeding across roles: a CO handshake in flight must
/// not fault a concurrent CU handshake (or vice versa).
///
/// hw enforces `AZIHSM_MAX_SESSIONS_PER_FD = 1`, so the CO and CU
/// sessions sit on separate fds bound to the same underlying device
/// (`ctx.path()`). Both sessions stay live simultaneously until
/// asserted, then are closed on their owning fds.
#[test]
fn default_psk_gate_co_and_cu_parallel_on_separate_devs_bypass() {
    let ctx_a = TestCtx::new();

    // Session A: CO + Authenticated on ctx_a's fd, under default CO PSK.
    let session_co = ctx_a
        .open_session(CO, SessionType::Authenticated)
        .expect("open_session must succeed");

    // Session B: CU + PlainText on a second fd bound to the same
    // device, under default CU PSK. Held concurrently with A.
    let ctx_b = TestCtx::new_with_path(ctx_a.path());
    let session_cu = ctx_b
        .open_session(CU, SessionType::PlainText)
        .expect("CU open on second fd under default CU PSK must succeed while CO session is live");

    assert_ne!(
        session_co.session_id(),
        session_cu.session_id(),
        "parallel CO and CU sessions must have distinct ids",
    );

    // Both sessions close on drop via their SessionGuards.
}
