// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::UNWRAP_WRAPPED_BLOB_MAX_LEN;
use azihsm_ddi_tbor_types::TborUnwrapKeyReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const CU: u8 = 1;
static CTX: std::sync::OnceLock<TestCtx> = std::sync::OnceLock::new();

fn bounded_wrapped_blob(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let max = UNWRAP_WRAPPED_BLOB_MAX_LEN;
    let len = usize::arbitrary(u)? % (max + 1);
    Ok(u.bytes(len)?.to_vec())
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    scope: u8,
    key_class: u8,
    key_usage: u8,
    oaep_hash_algo: u8,
    #[arbitrary(with = bounded_wrapped_blob)]
    wrapped_blob: Vec<u8>,
}

fuzz_target!(|input: FuzzInput| {
    let ctx = CTX.get_or_init(TestCtx::new);
    ctx.erase().expect("erase should succeed");

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("session open should succeed");

    let req = TborUnwrapKeyReq {
        session_id: session.session_id(),
        scope: input.scope,
        key_class: input.key_class,
        key_usage: input.key_usage,
        oaep_hash_algo: input.oaep_hash_algo,
        wrapped_blob: input.wrapped_blob,
    };
    let _ = ctx.tbor(&req);

    session.close().expect("session close should succeed");
});
