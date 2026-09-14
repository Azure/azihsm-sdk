// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborAesGenerateKeyReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const CU: u8 = 1;
static CTX: std::sync::OnceLock<TestCtx> = std::sync::OnceLock::new();

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    scope: u8,
    key_size: u8,
}

fuzz_target!(|input: FuzzInput| {
    let ctx = CTX.get_or_init(TestCtx::new);
    ctx.erase().expect("erase should succeed");

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("session open should succeed");

    let req = TborAesGenerateKeyReq {
        session_id: session.session_id(),
        scope: input.scope,
        key_size: input.key_size,
    };
    let _ = ctx.tbor(&req);

    session.close().expect("session close should succeed");
});
