// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_types::HMAC_HASH_SHA256;
use azihsm_ddi_tbor_types::HMAC_MSG_MAX_LEN;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborHmacGenerateKeyReq;
use azihsm_ddi_tbor_types::TborHmacReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const CU: u8 = 1;
static CTX: std::sync::OnceLock<TestCtx> = std::sync::OnceLock::new();

fn bounded_msg(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let max = HMAC_MSG_MAX_LEN;
    let len = usize::arbitrary(u)? % (max + 1);
    Ok(u.bytes(len)?.to_vec())
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    #[arbitrary(with = bounded_msg)]
    msg: Vec<u8>,
}

fuzz_target!(|input: FuzzInput| {
    let ctx = CTX.get_or_init(TestCtx::new);
    ctx.erase().expect("erase should succeed");

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("session open should succeed");

    // Generate an HMAC key to obtain a valid masked_key.
    let keygen_req = TborHmacGenerateKeyReq {
        session_id: session.session_id(),
        scope: 0b001, // KeyScope::Session
        hash_algo: HMAC_HASH_SHA256,
        key_length: 32,
    };
    let masked_key = match ctx.tbor(&keygen_req) {
        Ok(resp) => resp.masked_key,
        Err(_) => {
            session.close().expect("session close should succeed");
            return;
        }
    };

    let req = TborHmacReq {
        session_id: session.session_id(),
        masked_key,
        msg: input.msg,
    };
    let _ = ctx.tbor(&req);

    session.close().expect("session close should succeed");
});
