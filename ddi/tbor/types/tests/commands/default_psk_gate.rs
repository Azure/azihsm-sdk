// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR dispatcher's default-PSK gate.
//!
//! The gate (see `fw/core/lib/src/ddi/tbor/mod.rs::dispatch`) rejects
//! in-session commands not on the bootstrap allow-list when the
//! calling role's partition PSK still matches the compiled-in default
//! (`DEFAULT_PSK_CO` / `DEFAULT_PSK_CU`). Out-of-session opcodes
//! (`GetApiRev`, `OpenSessionInit`, `OpenSessionFinish`) are never
//! gated; in-session opcodes on the allow-list (`ChangePsk`,
//! `CloseSession`) are always permitted.
//!
//! Coverage in this file (positive bypass cases — E1, E2, E3, E5 from
//! the plan):
//!
//! * E5: `GetApiRev` reaches its handler with PSKs at default.
//! * E3: `OpenSessionInit` succeeds with PSKs at default.
//! * E1: `ChangePsk` is allow-listed — succeeds while PSK is default.
//! * E2: `CloseSession` is allow-listed — succeeds while PSK is default.
//!
//! E4 (a non-allow-listed in-session command being *rejected* with
//! `DefaultPskMustRotate`) is deferred until a second real in-session
//! opcode lands; synthesising one solely for a test would couple the
//! test to the FW's opcode allow-list at the wrong layer.
//!
//! Each test inherits a factory-reset device from
//! [`TestCtx::new`](crate::harness::TestCtx::new), so partition PSKs
//! are at their canonical defaults on entry.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::DEFAULT_PSK_CO;
use azihsm_ddi_tbor_types::DEFAULT_PSK_CU;
use azihsm_ddi_tbor_types::PSK_LEN;

use crate::harness::OpenSessionInitOptions;
use crate::harness::TestCtx;

const CO: u8 = 0;
const CU: u8 = 1;

/// Non-default PSK used as the rotation target for the `ChangePsk`
/// bypass test. Distinct from the constant used in `change_psk.rs` so
/// a leaked rotation from this file is trivially identifiable.
const GATE_ROTATED_PSK: [u8; PSK_LEN] = [
    0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A,
    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
];

/// E5: `GetApiRev` is an out-of-session opcode and therefore never
/// gated. It must succeed even when both partition PSKs are at their
/// compiled-in defaults.
#[test]
fn default_psk_gate_get_api_rev_bypass_emu() {
    let ctx = TestCtx::new();
    // Two probes back-to-back to confirm the call is genuinely
    // repeatable (gate is stateless) rather than passing on first
    // call by luck of ordering.
    let _ = ctx
        .get_api_rev()
        .expect("first GetApiRev under default PSK");
    let _ = ctx
        .get_api_rev()
        .expect("second GetApiRev under default PSK");
}

/// E3: `OpenSessionInit` is out-of-session and therefore never gated.
/// Verified for both roles since each is bound to a distinct PSK
/// slot.
#[test]
fn default_psk_gate_open_session_init_bypass_emu() {
    let ctx = TestCtx::new();

    // CO + Authenticated under default CO PSK.
    let opts_co =
        OpenSessionInitOptions::new(CO, SessionType::Authenticated).with_psk(&DEFAULT_PSK_CO);
    let pending_co = ctx
        .open_session_init_with_options(opts_co)
        .expect("CO init under default PSK");
    let session_co = ctx
        .open_session_finish(pending_co)
        .expect("CO finish under default PSK");

    // CU + PlainText under default CU PSK.
    let opts_cu = OpenSessionInitOptions::new(CU, SessionType::PlainText).with_psk(&DEFAULT_PSK_CU);
    let pending_cu = ctx
        .open_session_init_with_options(opts_cu)
        .expect("CU init under default PSK");
    let session_cu = ctx
        .open_session_finish(pending_cu)
        .expect("CU finish under default PSK");

    ctx.close_session(session_co.session_id)
        .expect("close CO session");
    ctx.close_session(session_cu.session_id)
        .expect("close CU session");
}

/// E2: `CloseSession` is on the allow-list — it must succeed while
/// the role's PSK is still default. Exercised for both roles.
#[test]
fn default_psk_gate_close_session_bypass_emu() {
    let ctx = TestCtx::new();

    let session_co = ctx.open_session(CO, SessionType::Authenticated);
    session_co
        .close()
        .expect("CloseSession must bypass gate while CO PSK is default");

    let session_cu = ctx.open_session(CU, SessionType::PlainText);
    session_cu
        .close()
        .expect("CloseSession must bypass gate while CU PSK is default");
}

/// E1: `ChangePsk` is on the allow-list — it must succeed while the
/// role's PSK is still default. This is exactly the bootstrap flow:
/// open under default, rotate.
///
/// Exercised for the CO role; the CU role's bootstrap path is
/// functionally identical and is already exercised by
/// `change_psk_happy_cu_emu` in `change_psk.rs`.
#[test]
fn default_psk_gate_change_psk_bypass_emu() {
    let ctx = TestCtx::new();
    let session = ctx.open_session(CO, SessionType::Authenticated);
    ctx.change_psk(session.handshake(), &GATE_ROTATED_PSK)
        .expect("ChangePsk must bypass gate while CO PSK is default");
}
