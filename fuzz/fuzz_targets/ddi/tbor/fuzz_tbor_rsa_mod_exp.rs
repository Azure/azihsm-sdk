// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_types::RSA_MASKED_KEY_MAX_LEN;
use azihsm_ddi_tbor_types::RSA_MOD_EXP_MAX_LEN;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborRsaModExpReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const CU: u8 = 1;
static CTX: std::sync::OnceLock<TestCtx> = std::sync::OnceLock::new();

fn bounded_masked_key(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let max = RSA_MASKED_KEY_MAX_LEN;
    let len = usize::arbitrary(u)? % (max + 1);
    Ok(u.bytes(len)?.to_vec())
}

fn bounded_y(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let max = RSA_MOD_EXP_MAX_LEN;
    let len = usize::arbitrary(u)? % (max + 1);
    Ok(u.bytes(len)?.to_vec())
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    #[arbitrary(with = bounded_masked_key)]
    masked_key: Vec<u8>,
    op_type: u8,
    #[arbitrary(with = bounded_y)]
    y: Vec<u8>,
}

fuzz_target!(|input: FuzzInput| {
    let ctx = CTX.get_or_init(TestCtx::new);
    ctx.erase().expect("erase should succeed");

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("session open should succeed");

    let req = TborRsaModExpReq {
        session_id: session.session_id(),
        masked_key: input.masked_key,
        op_type: input.op_type,
        y: input.y,
    };
    let _ = ctx.tbor(&req);

    session.close().expect("session close should succeed");
});
