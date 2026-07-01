// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hardware smoke test for the out-of-session TBOR `PartInfo`
//! command.
//!
//! Exercises the full host -> nix/win backend -> silicon fw
//! `handle_tbor_op` -> response path and asserts the invariant
//! device/partition fields the firmware reports for the default
//! provisioned partition. Safe to run against a live board because
//! `PartInfo` is sessionless and does not mutate persistent state.

use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborPartInfoResp;

use crate::hw::open_hw_dev;

/// `DdiDeviceKind::Physical` discriminant. Mirrors the emu-harness
/// constant in `commands::part_info` so both paths pin the same
/// contract.
const DEVICE_KIND_PHYSICAL: u8 = 2;

/// `PartState::Enabled` discriminant — the default provisioned state
/// of a partition before any `PartInit`.
const PART_STATE_ENABLED: u8 = 2;

fn assert_default_part_info(resp: &TborPartInfoResp) {
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
    let dev = open_hw_dev();
    let mut cookie = None;
    let resp = dev
        .exec_op_tbor(&TborPartInfoReq::new(), &mut cookie)
        .expect("TBOR PartInfo round-trip on hardware");
    assert_default_part_info(&resp);
}
