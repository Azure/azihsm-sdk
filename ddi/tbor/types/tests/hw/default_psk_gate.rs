// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hardware end-to-end tests for the TBOR dispatcher's default-PSK
//! gate (see `fw/core/lib/src/ddi/tbor/mod.rs::dispatch`).
//!
//! Mirrors the emu suite in `commands::default_psk_gate` and adds
//! the E4 case (in-session, non-allow-listed opcode rejected with
//! `DefaultPskMustRotate`) using `PartInit`.
//!
//! Cross-test isolation comes from
//! [`hw_test_reset`](crate::hw::harness::hw_test_reset) — NSSR
//! before + after each test body so every test starts and ends with
//! the partition at pristine defaults.

use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborApiRevReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::DEFAULT_PSK_CO;
use azihsm_ddi_tbor_types::DEFAULT_PSK_CU;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::SATA_THUMBPRINT_LEN;

use crate::hw::assertions::assert_fw_rejects;
use crate::hw::harness::hw_test_reset;
use crate::hw::session_helper::open_session;
use crate::hw::session_helper::part_init;
use crate::hw::session_helper::session_close;
use crate::hw::session_helper::session_open_finish;
use crate::hw::session_helper::session_open_init_with_options;
use crate::hw::session_helper::SessionOpenInitOptions;

const CO: u8 = 0;
const CU: u8 = 1;

/// Build a 484-byte `PartPolicy` blob that passes wire decode so
/// the request reaches the dispatcher's gate. Mirrors
/// `commands::part_init::known_good_part_policy`.
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

fn mach_seed() -> [u8; MACH_SEED_LEN] {
    let mut v = [0u8; MACH_SEED_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = 0x40 + i as u8;
    }
    v
}

fn pota_thumbprint() -> [u8; POTA_THUMBPRINT_LEN] {
    [0x5Au8; POTA_THUMBPRINT_LEN]
}

fn sata_thumbprint() -> [u8; SATA_THUMBPRINT_LEN] {
    [0x6Au8; SATA_THUMBPRINT_LEN]
}

/// E5: out-of-session `ApiRev` is never gated.
#[test]
fn api_rev_bypass() {
    hw_test_reset(|dev| {
        let mut cookie = None;
        let _ = dev
            .exec_op_tbor(&TborApiRevReq::new(), None, &mut cookie)
            .expect("ApiRev bypasses the gate on any PSK state");
    });
}

/// E2 + E3: SessionOpenInit / SessionOpenFinish / SessionClose all
/// bypass the gate under the default PSK.
#[test]
fn session_open_and_close_bypass() {
    hw_test_reset(|dev| {
        let opts_co =
            SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&DEFAULT_PSK_CO);
        let pending_co = session_open_init_with_options(dev, opts_co).expect("CO init");
        let session_co = session_open_finish(dev, pending_co).expect("CO finish");
        session_close(dev, session_co.session_id).expect("CO close");

        let opts_cu =
            SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&DEFAULT_PSK_CU);
        let pending_cu = session_open_init_with_options(dev, opts_cu).expect("CU init");
        let session_cu = session_open_finish(dev, pending_cu).expect("CU finish");
        session_close(dev, session_cu.session_id).expect("CU close");
    });
}

/// E4: in-session non-allow-listed opcode (`PartInit`) is rejected
/// with `DefaultPskMustRotate`. Gate rejects at dispatch, before
/// any handler runs.
#[test]
fn part_init_rejected_under_default_psk() {
    hw_test_reset(|dev| {
        let session = open_session(dev, CO, SessionType::Authenticated).expect("open CO");
        let session_id = session.session_id;

        let err = part_init(
            dev,
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata_thumbprint(),
            None,
        )
        .expect_err("PartInit under default PSK must be gated");
        assert_fw_rejects(&err, TborStatus::DefaultPskMustRotate);

        session_close(dev, session_id).expect("close CO");
    });
}
