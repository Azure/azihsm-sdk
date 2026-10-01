// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_types::AES_IV_LEN;
use azihsm_ddi_tbor_types::AES_KEY_SIZE_256;
use azihsm_ddi_tbor_types::AES_MSG_MAX_LEN;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborAesEncryptDecryptReq;
use azihsm_ddi_tbor_types::TborAesGenerateKeyReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const CU: u8 = 1;
static CTX: std::sync::OnceLock<TestCtx> = std::sync::OnceLock::new();

fn bounded_msg(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let max = AES_MSG_MAX_LEN;
    let len = usize::arbitrary(u)? % (max + 1);
    Ok(u.bytes(len)?.to_vec())
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    op: u8,
    #[arbitrary(with = bounded_msg)]
    msg: Vec<u8>,
    iv: [u8; AES_IV_LEN],
}

fuzz_target!(|input: FuzzInput| {
    let ctx = CTX.get_or_init(TestCtx::new);
    ctx.erase().expect("erase should succeed");

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("session open should succeed");

    // Generate an AES key to obtain a valid masked_key.
    let keygen_req = TborAesGenerateKeyReq {
        session_id: session.session_id(),
        scope: 0b001, // KeyScope::Session
        key_size: AES_KEY_SIZE_256,
    };
    let masked_key = match ctx.tbor(&keygen_req) {
        Ok(resp) => resp.masked_key,
        Err(_) => {
            session.close().expect("session close should succeed");
            return;
        }
    };

    let req = TborAesEncryptDecryptReq {
        session_id: session.session_id(),
        masked_key,
        op: input.op,
        msg: input.msg,
        iv: input.iv,
    };
    let _ = ctx.tbor(&req);

    session.close().expect("session close should succeed");
});
