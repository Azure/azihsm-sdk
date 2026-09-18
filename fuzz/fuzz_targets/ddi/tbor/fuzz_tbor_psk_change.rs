// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_types::PSK_CHANGE_ENVELOPE_MAX_LEN;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborPskChangeReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const CU: u8 = 1;
static CTX: std::sync::OnceLock<TestCtx> = std::sync::OnceLock::new();

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Fixed-length fuzzed PskChange envelope buffer.
    psk_envelope: [u8; PSK_CHANGE_ENVELOPE_MAX_LEN],
}

fuzz_target!(|input: FuzzInput| {
    let ctx = CTX.get_or_init(TestCtx::new);
    ctx.erase().expect("erase should succeed");

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("session open should succeed");

    let psk_change_req = TborPskChangeReq {
        session_id: session.session_id(),
        psk_envelope: input.psk_envelope.to_vec(),
    };
    let _ = ctx.tbor(&psk_change_req);

    session.close().expect("session close should succeed");
});
