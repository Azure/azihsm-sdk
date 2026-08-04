// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_tbor_types::PK_INIT_LEN;
use azihsm_ddi_tbor_types::TborSessionCloseReq;
use azihsm_ddi_tbor_types::TborSessionCloseResp;
use azihsm_ddi_tbor_types::TborSessionOpenInitReq;
use azihsm_ddi_tbor_types::TborSessionOpenInitResp;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    psk_id: u8,
    session_type: u8,
    suite_id: u8,
    pk_init: [u8; PK_INIT_LEN],
}

fuzz_target!(|input: FuzzInput| {
    let dev = common::open_emu_dev();
    let req = TborSessionOpenInitReq {
        psk_id: input.psk_id,
        session_type: input.session_type,
        suite_id: input.suite_id,
        pk_init: input.pk_init,
    };
    let mut cookie = None;
    // If session open succeeds, close it afterwards.
    if let Ok(resp) = dev.exec_op_tbor::<TborSessionOpenInitReq>(&req, None, &mut cookie) {
        let close_req = TborSessionCloseReq {
            session_id: resp.session_id,
        };
        let mut close_cookie = None;
        let _: Result<TborSessionCloseResp, _> =
            dev.exec_op_tbor(&close_req, None, &mut close_cookie);
    }
});
