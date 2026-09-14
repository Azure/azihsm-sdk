// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_types::CONCAT_INFO_MAX_LEN;
use azihsm_ddi_tbor_types::ECC_CURVE_P256;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborConcatKdfDeriveReq;
use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
use azihsm_ddi_tbor_types::TborEcdhDeriveReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const CU: u8 = 1;
static CTX: std::sync::OnceLock<TestCtx> = std::sync::OnceLock::new();

fn bounded_info(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let len = usize::arbitrary(u)? % (CONCAT_INFO_MAX_LEN + 1);
    Ok(u.bytes(len)?.to_vec())
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    scope: u8,
    hash_algo: u8,
    kdf_alg: u8,
    key_type: u8,
    key_length: u8,
    #[arbitrary(with = bounded_info)]
    info: Vec<u8>,
}

fuzz_target!(|input: FuzzInput| {
    let ctx = CTX.get_or_init(TestCtx::new);
    ctx.erase().expect("erase should succeed");

    let session = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("session open should succeed");

    // Generate an ECC key pair for the ECDH derive.
    let keygen_req = TborEccGenerateKeyReq {
        session_id: session.session_id(),
        scope: 0b001, // KeyScope::Session
        curve: ECC_CURVE_P256,
    };
    let keygen_resp = match ctx.tbor(&keygen_req) {
        Ok(resp) => resp,
        Err(_) => {
            session.close().expect("session close should succeed");
            return;
        }
    };

    // Derive an ECDH shared secret using the key's own pub key as peer.
    let ecdh_req = TborEcdhDeriveReq {
        session_id: session.session_id(),
        scope: 0b001,
        masked_key: keygen_resp.masked_key,
        peer_pub_key: keygen_resp.pub_key,
    };
    let masked_secret = match ctx.tbor(&ecdh_req) {
        Ok(resp) => resp.masked_secret,
        Err(_) => {
            session.close().expect("session close should succeed");
            return;
        }
    };

    let req = TborConcatKdfDeriveReq {
        session_id: session.session_id(),
        scope: input.scope,
        hash_algo: input.hash_algo,
        kdf_alg: input.kdf_alg,
        key_type: input.key_type,
        key_length: input.key_length,
        masked_secret,
        info: input.info,
    };
    let _ = ctx.tbor(&req);

    session.close().expect("session close should succeed");
});
