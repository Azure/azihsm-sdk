// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborHmacGenerateKeyReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const CU: u8 = 1;
static CTX: std::sync::OnceLock<TestCtx> = std::sync::OnceLock::new();

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    scope: u8,
    hash_algo: u8,
    key_length: u8,
}

fuzz_target!(|input: FuzzInput| {
    let ctx = CTX.get_or_init(TestCtx::new);
    ctx.erase().expect("erase should succeed");

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("session open should succeed");

    let req = TborHmacGenerateKeyReq {
        session_id: session.session_id(),
        scope: input.scope,
        hash_algo: input.hash_algo,
        key_length: input.key_length,
    };
    let _ = ctx.tbor(&req);

    session.close().expect("session close should succeed");
});
