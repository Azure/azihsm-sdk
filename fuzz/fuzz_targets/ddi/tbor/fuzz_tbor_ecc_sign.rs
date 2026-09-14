// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_types::ECC_CURVE_P256;
use azihsm_ddi_tbor_types::ECC_DIGEST_MAX_LEN;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
use azihsm_ddi_tbor_types::TborEccSignReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const CU: u8 = 1;
static CTX: std::sync::OnceLock<TestCtx> = std::sync::OnceLock::new();

fn bounded_digest(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let max = ECC_DIGEST_MAX_LEN;
    let len = usize::arbitrary(u)? % (max + 1);
    Ok(u.bytes(len)?.to_vec())
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    #[arbitrary(with = bounded_digest)]
    digest: Vec<u8>,
}

fuzz_target!(|input: FuzzInput| {
    let ctx = CTX.get_or_init(TestCtx::new);
    ctx.erase().expect("erase should succeed");

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("session open should succeed");

    // Generate an ECC key to obtain a valid masked_key.
    let keygen_req = TborEccGenerateKeyReq {
        session_id: session.session_id(),
        scope: 0b001, // KeyScope::Session
        curve: ECC_CURVE_P256,
    };
    let masked_key = match ctx.tbor(&keygen_req) {
        Ok(resp) => resp.masked_key,
        Err(_) => {
            session.close().expect("session close should succeed");
            return;
        }
    };

    let req = TborEccSignReq {
        session_id: session.session_id(),
        masked_key,
        digest: input.digest,
    };
    let _ = ctx.tbor(&req);

    session.close().expect("session close should succeed");
});
