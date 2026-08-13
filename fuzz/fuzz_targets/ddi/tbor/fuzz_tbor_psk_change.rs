// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_tbor_types::PSK_CHANGE_ENVELOPE_MAX_LEN;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborPskChangeReq;
use azihsm_ddi_tbor_types::TborSessionCloseReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// PSK id: 0 = CO, 1 = CU. Other values skip the iteration.
    psk_id: u8,
    /// Selects between PlainText (false) and Authenticated (true) session types.
    use_authenticated_session: bool,
    /// Fixed-length fuzzed PskChange envelope buffer.
    psk_envelope: [u8; PSK_CHANGE_ENVELOPE_MAX_LEN],
}

fuzz_target!(|input: FuzzInput| {
    let session_type = if input.use_authenticated_session {
        SessionType::Authenticated
    } else {
        SessionType::PlainText
    };

    // Open a device and establish a proper 2-phase TBOR session, mirroring
    // TestCtx::new() + ctx.session_open_init() + ctx.session_open_finish().
    let Some((dev, session_id)) = common::open_session(input.psk_id, session_type) else {
        return;
    };

    // Exercise PskChange with the fuzzed envelope.
    let psk_change_req = TborPskChangeReq {
        session_id,
        psk_envelope: input.psk_envelope.to_vec(),
    };
    let mut psk_cookie = None;
    let _ = dev.exec_op_tbor::<TborPskChangeReq>(&psk_change_req, None, &mut psk_cookie);

    // Clean up the session regardless of PskChange outcome.
    let close_req = TborSessionCloseReq { session_id };
    let mut close_cookie = None;
    let _ = dev.exec_op_tbor(&close_req, None, &mut close_cookie);
});
