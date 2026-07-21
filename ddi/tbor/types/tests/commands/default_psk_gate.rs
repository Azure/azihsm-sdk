// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(not(any(feature = "mock", feature = "sock")))]

//! Integration tests for the TBOR dispatcher's default-PSK gate.
//!
//! The gate (see `fw/core/lib/src/ddi/tbor/mod.rs::dispatch`) rejects
//! in-session commands not on the bootstrap allow-list when the
//! calling role's partition PSK still matches the compiled-in default
//! (`DEFAULT_PSK_CO` / `DEFAULT_PSK_CU`). Out-of-session opcodes
//! (`ApiRev`, `SessionOpenInit`, `SessionOpenFinish`) are never
//! gated; in-session opcodes on the allow-list (`PskChange`,
//! `SessionClose`) are always permitted.
//!
//! Coverage in this file (positive bypass cases E1, E2, E3, E5 plus
//! the negative case E4):
//!
//! * E5: `ApiRev` reaches its handler with PSKs at default.
//! * E3: `SessionOpenInit` succeeds with PSKs at default.
//! * E1: `PskChange` is allow-listed — succeeds while PSK is default.
//! * E2: `SessionClose` is allow-listed — succeeds while PSK is default.
//! * E4: a non-allow-listed in-session opcode (`PartInit`) is
//!   rejected at dispatch with `DefaultPskMustRotate`, before any
//!   handler mutation. Runs against emu and hw because the FW rejects
//!   before any state change.
//!
//! Each test inherits a factory-reset device from the ctx constructor,
//! so partition PSKs are at their canonical defaults on entry.

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::DEFAULT_PSK_CO;
use azihsm_ddi_tbor_types::DEFAULT_PSK_CU;
use azihsm_ddi_tbor_types::PSK_LEN;

use crate::harness::SessionOpenInitOptions;
use crate::harness::TestCtx;

const CO: u8 = 0;
const CU: u8 = 1;

/// Non-default PSK used as the rotation target for the `PskChange`
/// bypass test. Distinct from the constant used in `psk_change.rs` so
/// a leaked rotation from this file is trivially identifiable.
const GATE_ROTATED_PSK: [u8; PSK_LEN] = [
    0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A,
    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
];

/// E5: `ApiRev` is an out-of-session opcode and therefore never
/// gated. It must succeed even when both partition PSKs are at their
/// compiled-in defaults.
#[test]
fn default_psk_gate_api_rev_bypass() {
    let ctx = TestCtx::new();
    // Two probes back-to-back to confirm the call is genuinely
    // repeatable (gate is stateless) rather than passing on first
    // call by luck of ordering.
    let _ = ctx.api_rev().expect("first ApiRev under default PSK");
    let _ = ctx.api_rev().expect("second ApiRev under default PSK");
}

/// E3: `SessionOpenInit` is out-of-session and therefore never gated.
/// Verified for both roles since each is bound to a distinct PSK
/// slot.
#[test]
fn default_psk_gate_session_open_init_bypass() {
    let ctx = TestCtx::new();

    // CO + Authenticated under default CO PSK.
    let opts_co =
        SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&DEFAULT_PSK_CO);
    let pending_co = ctx
        .session_open_init_with_options(opts_co)
        .expect("CO init under default PSK");
    let session_co = ctx
        .session_open_finish(pending_co)
        .expect("CO finish under default PSK");

    // CU + PlainText under default CU PSK.
    let opts_cu = SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&DEFAULT_PSK_CU);
    let pending_cu = ctx
        .session_open_init_with_options(opts_cu)
        .expect("CU init under default PSK");
    let session_cu = ctx
        .session_open_finish(pending_cu)
        .expect("CU finish under default PSK");

    ctx.session_close(session_co.session_id)
        .expect("close CO session");
    ctx.session_close(session_cu.session_id)
        .expect("close CU session");
}

/// E2: `SessionClose` is on the allow-list — it must succeed while
/// the role's PSK is still default. Exercised for both roles.
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

/// E1: `PskChange` is on the allow-list — it must succeed while the
/// role's PSK is still default. This is exactly the bootstrap flow:
/// open under default, rotate.
///
/// Exercised for the CO role; the CU role's bootstrap path is
/// functionally identical and is already exercised by
/// `psk_change_happy_cu_emu` in `psk_change.rs`.
#[test]
fn default_psk_gate_psk_change_bypass() {
    let ctx = TestCtx::new();
    let session = ctx.open_session(CO, SessionType::Authenticated);
    ctx.psk_change(session.handshake(), &GATE_ROTATED_PSK)
        .expect("PskChange must bypass gate while CO PSK is default");
}

/// E4: an in-session, non-allow-listed opcode (`PartInit`) is
/// rejected at dispatch with `DefaultPskMustRotate`. The FW returns
/// the gate error before any partition-state mutation, so this test
/// is safe to run on real silicon.
#[test]
fn default_psk_gate_part_init_rejected() {
    use azihsm_ddi_tbor_types::PolicyKeyKind;
    use azihsm_ddi_tbor_types::TborStatus;
    use azihsm_ddi_tbor_types::MACH_SEED_LEN;
    use azihsm_ddi_tbor_types::PART_POLICY_LEN;
    use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;

    use crate::harness::assertions::assert_fw_rejects;

    // Build a 484-byte `PartPolicy` blob that passes wire decode so
    // the request reaches the dispatcher's gate. Mirrored from
    // `commands::part_init::known_good_part_policy` (kept inline so
    // this file stays runnable on hw without ungating the destructive
    // part_init/ submodules).
    fn known_good_part_policy() -> [u8; PART_POLICY_LEN] {
        const OFF_POTA: usize = 2;
        const OFF_SATA: usize = 102;
        const OFF_FLAGS: usize = 418;
        const OFF_INFO: usize = 419;

        fn write_pubkey(bytes: &mut [u8], off: usize, fill: u8) {
            bytes[off..off + 2].copy_from_slice(&PolicyKeyKind::Ecc384.0.to_le_bytes());
            bytes[off + 2..off + 4].copy_from_slice(&96u16.to_le_bytes());
            for (i, b) in bytes[off + 4..off + 4 + 96].iter_mut().enumerate() {
                *b = (fill.wrapping_add(i as u8)) | 0x80;
            }
        }

        let mut bytes = [0u8; PART_POLICY_LEN];
        bytes[0] = 1;
        bytes[1] = 0;
        write_pubkey(&mut bytes, OFF_POTA, 0x10);
        write_pubkey(&mut bytes, OFF_SATA, 0x20);
        bytes[OFF_FLAGS] = 0;
        for b in bytes[OFF_INFO..OFF_INFO + 64].iter_mut() {
            *b = 0xAB;
        }
        bytes
    }

    let ctx = TestCtx::new();
    let session = ctx.open_session(CO, SessionType::Authenticated);

    let mach_seed = {
        let mut v = [0u8; MACH_SEED_LEN];
        for (i, b) in v.iter_mut().enumerate() {
            *b = 0x40 + i as u8;
        }
        v
    };
    let pota_thumbprint = [0x5Au8; POTA_THUMBPRINT_LEN];

    let err = ctx
        .part_init(
            session.handshake(),
            &mach_seed,
            &known_good_part_policy(),
            &pota_thumbprint,
        )
        .expect_err("PartInit under default PSK must be gated");
    assert_fw_rejects(&err, TborStatus::DefaultPskMustRotate);
}
