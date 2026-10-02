// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_types::*;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Fuzz input for the TBOR `AesEncryptDecrypt` command.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Generate a valid masked AES key instead of using fuzzed bytes.
    use_valid_key: bool,
    /// AES key size for a generated key.
    key_size: common::AesKeySize,
    /// Fuzzed parameters for the AES operation.
    cmdreq_data: FuzzAesEncryptDecryptReq,
}

#[derive(Arbitrary, Debug)]
struct FuzzAesEncryptDecryptReq {
    masked_key: Vec<u8>,
    op: u8,
    msg: Vec<u8>,
    iv: [u8; AES_IV_LEN],
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);

        let masked_key = if input.use_valid_key {
            let key_req = TborAesGenerateKeyReq {
                session_id: session.session_id,
                scope: AES_KEY_SCOPE_SESSION,
                key_size: input.key_size.to_tbor(),
                key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
                key_label: Vec::new(),
            };
            ctx.tbor(&key_req)
                .expect("session-scoped AES key generation should succeed")
                .masked_key
        } else {
            input.cmdreq_data.masked_key.clone()
        };

        let msg = &input.cmdreq_data.msg;
        let op = input.cmdreq_data.op;
        let expect_success = input.use_valid_key
            && (op == AES_OP_ENCRYPT || op == AES_OP_DECRYPT)
            && !msg.is_empty()
            && msg.len().is_multiple_of(AES_IV_LEN)
            && msg.len() <= AES_MSG_MAX_LEN;

        let req = TborAesEncryptDecryptReq {
            session_id: session.session_id,
            masked_key: masked_key.clone(),
            op,
            msg: msg.clone(),
            iv: input.cmdreq_data.iv,
        };
        let result = ctx.tbor(&req);

        match (&result, expect_success) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash Detected: {err}"),
            (Ok(resp), true) => {
                assert_eq!(resp.msg.len(), msg.len(), "output length must match input");
                if op == AES_OP_ENCRYPT {
                    let decrypted = ctx
                        .tbor(&TborAesEncryptDecryptReq {
                            session_id: session.session_id,
                            masked_key,
                            op: AES_OP_DECRYPT,
                            msg: resp.msg.clone(),
                            iv: input.cmdreq_data.iv,
                        })
                        .expect("decrypting valid ciphertext should succeed");
                    assert_eq!(&decrypted.msg, msg, "AES round trip must recover plaintext");
                    assert_eq!(decrypted.iv, resp.iv, "decrypt chaining IV must match");
                } else {
                    // `op == AES_OP_DECRYPT`: re-encrypt the returned
                    // plaintext under the same key/IV and confirm it
                    // reproduces the original ciphertext (`msg`), so a
                    // regression that returns arbitrary same-length bytes
                    // for a decrypt can't pass on output length alone.
                    let re_encrypted = ctx
                        .tbor(&TborAesEncryptDecryptReq {
                            session_id: session.session_id,
                            masked_key,
                            op: AES_OP_ENCRYPT,
                            msg: resp.msg.clone(),
                            iv: input.cmdreq_data.iv,
                        })
                        .expect("re-encrypting decrypted plaintext should succeed");
                    assert_eq!(
                        &re_encrypted.msg, msg,
                        "AES round trip must reproduce original ciphertext"
                    );
                    assert_eq!(re_encrypted.iv, resp.iv, "encrypt chaining IV must match");
                }
            }
            (Ok(_), false) => panic!("invalid AES request unexpectedly succeeded"),
            (Err(err), true) => panic!("valid AES request failed: {err}"),
            (Err(_), false) => {}
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});

const AES_KEY_SCOPE_SESSION: u8 = 0b001;
