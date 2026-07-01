// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hardware smoke test for TBOR `ApiRev`.
//!
//! Exercises the full host -> nix/win backend -> silicon fw
//! `handle_tbor_op` -> response path. `ApiRev` is sessionless and
//! stateless, so it is safe to run against a live board without
//! any pre-/post-test cleanup.

use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_tbor_types::TborApiRevReq;
use azihsm_ddi_tbor_types::TborApiRevResp;

use crate::hw::open_hw_dev;

/// Expected response for the bootstrap TBOR protocol version.
///
/// Mirrors the emu-harness constant in
/// `commands::api_rev::EXPECTED` so both paths pin the same wire
/// contract.
const EXPECTED: TborApiRevResp = TborApiRevResp {
    min_ver: 1,
    max_ver: 1,
};

#[test]
fn round_trip() {
    let dev = open_hw_dev();
    let mut cookie = None;
    let resp = dev
        .exec_op_tbor(&TborApiRevReq::new(), &mut cookie)
        .expect("TBOR ApiRev round-trip on hardware");
    assert_eq!(
        resp, EXPECTED,
        "firmware should report min=max=1 for the bootstrap TBOR protocol version",
    );
}
