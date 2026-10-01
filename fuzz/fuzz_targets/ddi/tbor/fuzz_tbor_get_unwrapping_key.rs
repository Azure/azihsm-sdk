// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborGetUnwrappingKeyReq;
use libfuzzer_sys::fuzz_target;

const CU: u8 = 1;
static CTX: std::sync::OnceLock<TestCtx> = std::sync::OnceLock::new();

fuzz_target!(|_input: &[u8]| {
    let ctx = CTX.get_or_init(TestCtx::new);
    ctx.erase().expect("erase should succeed");

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("session open should succeed");

    let req = TborGetUnwrappingKeyReq {
        session_id: session.session_id(),
    };
    let _ = ctx.tbor(&req);

    session.close().expect("session close should succeed");
});
