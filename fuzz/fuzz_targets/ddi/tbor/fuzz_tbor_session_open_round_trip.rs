// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_tbor_types::MAC_FIN_LEN;
use azihsm_ddi_tbor_types::PK_INIT_LEN;
use azihsm_ddi_tbor_types::SEED_ENVELOPE_LEN;
use azihsm_ddi_tbor_types::TborSessionCloseReq;
use azihsm_ddi_tbor_types::TborSessionCloseResp;
use azihsm_ddi_tbor_types::TborSessionOpenFinishReq;
use azihsm_ddi_tbor_types::TborSessionOpenInitReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    // input for SessionOpenInit
    psk_id: u8,
    session_type: u8,
    suite_id: u8,
    pk_init: [u8; PK_INIT_LEN],

    // input for SessionOpenFinish
    mac_fin: [u8; MAC_FIN_LEN],
    seed_envelope: [u8; SEED_ENVELOPE_LEN],
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
    // If session open succeeds, finish then close it afterwards.
    if let Ok(resp) = dev.exec_op_tbor::<TborSessionOpenInitReq>(&req, None, &mut cookie) {
        // if init succeeded, attempt SessionOpenFinish
        let open_finish_req = TborSessionOpenFinishReq {
            session_id: resp.session_id,
            mac_fin: input.mac_fin,
            seed_envelope: input.seed_envelope,
        };
        let mut open_finish_cookie = None;
        let _ = dev.exec_op_tbor::<TborSessionOpenFinishReq>(&open_finish_req, None, &mut open_finish_cookie);

        // SessionClose afterwards to clean up
        let close_req = TborSessionCloseReq {
            session_id: resp.session_id,
        };
        let mut close_cookie = None;
        let _: Result<TborSessionCloseResp, _> =
            dev.exec_op_tbor(&close_req, None, &mut close_cookie);
    }
});
