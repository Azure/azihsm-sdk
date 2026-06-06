// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Phase 6 integration tests for the TBOR dispatcher's default-PSK
//! gate.
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
//! All tests run against the `emu` backend and are serialised via
//! `#[serial_test::serial]`. Each test relies on the partition PSKs
//! being at their canonical defaults on entry — every prior test in
//! the suite that mutates a PSK restores it before exiting (see
//! `change_psk.rs::rotate_psk`). No test in this file leaves either
//! slot in a non-default state.

#![cfg(feature = "emu")]

use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_tbor_test_helpers::change_psk;
use azihsm_ddi_tbor_test_helpers::close_session;
use azihsm_ddi_tbor_test_helpers::helper_get_api_rev_tbor;
use azihsm_ddi_tbor_test_helpers::open_session;
use azihsm_ddi_tbor_test_helpers::open_session_init_with_options;
use azihsm_ddi_tbor_test_helpers::OpenSessionInitOptions;
use azihsm_fw_hsm_pal_traits::SessionType;
use azihsm_fw_hsm_pal_traits::DEFAULT_PSK_CO;
use azihsm_fw_hsm_pal_traits::DEFAULT_PSK_CU;
use azihsm_fw_hsm_pal_traits::PSK_LEN;
use serial_test::serial;

use crate::integration::common::fixture::open_dev;

const CO: u8 = 0;
const CU: u8 = 1;

type Dev = <AzihsmDdi as Ddi>::Dev;

/// Non-default PSK used as the rotation target for the `ChangePsk`
/// bypass test. Distinct from the constant used in `change_psk.rs` so
/// a leaked rotation from this file is trivially identifiable.
const GATE_ROTATED_PSK: [u8; PSK_LEN] = [
    0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A,
    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
];

fn default_psk_for(psk_id: u8) -> [u8; PSK_LEN] {
    match psk_id {
        CO => DEFAULT_PSK_CO,
        CU => DEFAULT_PSK_CU,
        _ => unreachable!("psk_id must be 0 or 1"),
    }
}

/// Mirror of `change_psk.rs::rotate_psk` — open a session under
/// `current_psk`, rotate to `target_psk`, close. Used solely to undo
/// the rotation performed by `default_psk_gate_change_psk_bypass_emu`
/// so the emulator's process-global PSK state is restored before the
/// next test runs.
fn rotate_psk(dev: &Dev, psk_id: u8, current_psk: &[u8], target_psk: &[u8]) {
    let session_type = match psk_id {
        CO => SessionType::Authenticated,
        _ => SessionType::PlainText,
    };
    let opts = OpenSessionInitOptions::new(psk_id, session_type).with_psk(current_psk);
    let pending = open_session_init_with_options(dev, opts)
        .expect("init under current PSK must succeed during rotate");
    let session = azihsm_ddi_tbor_test_helpers::open_session_finish(dev, pending)
        .expect("finish during rotate");
    change_psk(dev, &session, target_psk).expect("rotate ChangePsk must succeed");
    close_session(dev, session.session_id).expect("close after rotate");
}

/// E5: `GetApiRev` is an out-of-session opcode and therefore never
/// gated. It must succeed even when both partition PSKs are at their
/// compiled-in defaults.
#[test]
#[serial]
fn default_psk_gate_get_api_rev_bypass_emu() {
    let dev = open_dev();
    // Two probes back-to-back to confirm the call is genuinely
    // repeatable (gate is stateless) rather than passing on first
    // call by luck of ordering.
    let _ = helper_get_api_rev_tbor(&dev).expect("first GetApiRev under default PSK");
    let _ = helper_get_api_rev_tbor(&dev).expect("second GetApiRev under default PSK");
}

/// E3: `OpenSessionInit` is out-of-session and therefore never gated.
/// Verified for both roles since each is bound to a distinct PSK
/// slot.
#[test]
#[serial]
fn default_psk_gate_open_session_init_bypass_emu() {
    let dev = open_dev();

    // CO + Authenticated under default CO PSK.
    let opts_co =
        OpenSessionInitOptions::new(CO, SessionType::Authenticated).with_psk(&DEFAULT_PSK_CO);
    let pending_co =
        open_session_init_with_options(&dev, opts_co).expect("CO init under default PSK");
    let session_co = azihsm_ddi_tbor_test_helpers::open_session_finish(&dev, pending_co)
        .expect("CO finish under default PSK");

    // CU + PlainText under default CU PSK.
    let opts_cu = OpenSessionInitOptions::new(CU, SessionType::PlainText).with_psk(&DEFAULT_PSK_CU);
    let pending_cu =
        open_session_init_with_options(&dev, opts_cu).expect("CU init under default PSK");
    let session_cu = azihsm_ddi_tbor_test_helpers::open_session_finish(&dev, pending_cu)
        .expect("CU finish under default PSK");

    // Cleanup — neither session mutated PSK state.
    close_session(&dev, session_co.session_id).expect("close CO session");
    close_session(&dev, session_cu.session_id).expect("close CU session");
}

/// E2: `CloseSession` is on the allow-list — it must succeed while
/// the role's PSK is still default. Exercised for both roles.
#[test]
#[serial]
fn default_psk_gate_close_session_bypass_emu() {
    let dev = open_dev();

    let session_co =
        open_session(&dev, CO, SessionType::Authenticated).expect("open CO under default PSK");
    close_session(&dev, session_co.session_id)
        .expect("CloseSession must bypass gate while CO PSK is default");

    let session_cu =
        open_session(&dev, CU, SessionType::PlainText).expect("open CU under default PSK");
    close_session(&dev, session_cu.session_id)
        .expect("CloseSession must bypass gate while CU PSK is default");
}

/// E1: `ChangePsk` is on the allow-list — it must succeed while the
/// role's PSK is still default. This is exactly the bootstrap flow:
/// open under default, rotate, restore.
///
/// Exercised for the CO role; the CU role's bootstrap path is
/// functionally identical and is already exercised by
/// `change_psk_happy_cu_emu` in `change_psk.rs`. Restoring the slot
/// to its default at the end keeps the emulator's process-global
/// state clean for downstream tests.
#[test]
#[serial]
fn default_psk_gate_change_psk_bypass_emu() {
    let dev = open_dev();

    let session =
        open_session(&dev, CO, SessionType::Authenticated).expect("open CO under default PSK");
    change_psk(&dev, &session, &GATE_ROTATED_PSK)
        .expect("ChangePsk must bypass gate while CO PSK is default");
    close_session(&dev, session.session_id).expect("close bootstrap session");

    // Restore the CO slot so the emulator is left at defaults.
    rotate_psk(&dev, CO, &GATE_ROTATED_PSK, &default_psk_for(CO));
}
