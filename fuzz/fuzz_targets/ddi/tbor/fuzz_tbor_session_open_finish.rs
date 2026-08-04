// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_tbor_types::MAC_FIN_LEN;
use azihsm_ddi_tbor_types::SEED_ENVELOPE_LEN;
use azihsm_ddi_tbor_types::TborSessionOpenFinishReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    session_id: u16,
    mac_fin: [u8; MAC_FIN_LEN],
    seed_envelope: [u8; SEED_ENVELOPE_LEN],
}

fuzz_target!(|input: FuzzInput| {
    let dev = common::open_emu_dev();
    let req = TborSessionOpenFinishReq {
        session_id: input.session_id,
        mac_fin: input.mac_fin,
        seed_envelope: input.seed_envelope,
    };
    common::fuzz_exec_op_tbor(&dev, &req);
});
