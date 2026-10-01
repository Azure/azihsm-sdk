// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_types::*;
use common::FuzzRole;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Fuzz input for the TBOR `AesEncryptDecrypt` command.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Session role used for the AES operation.
    role: FuzzRole,
    /// Generate a valid masked AES key instead of using fuzzed bytes.
    use_valid_key: bool,
    /// AES key size for a generated key.
    key_size: AesKeySize,
    /// Fuzzed parameters for the AES operation.
    cmdreq_data: FuzzAesEncryptDecryptReq,
}

#[derive(Arbitrary, Debug)]
enum AesKeySize {
    Aes128,
    Aes192,
    Aes256,
}

impl AesKeySize {
    fn to_tbor(&self) -> u8 {
        match self {
            Self::Aes128 => AES_KEY_SIZE_128,
            Self::Aes192 => AES_KEY_SIZE_192,
            Self::Aes256 => AES_KEY_SIZE_256,
        }
    }
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
        let session = ctx
            .open_session(input.role.psk_id(), input.role.session_type())
            .expect("session open should succeed");

        let masked_key = if input.use_valid_key {
            let key_req = TborAesGenerateKeyReq {
                session_id: session.session_id(),
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

        let req = TborAesEncryptDecryptReq {
            session_id: session.session_id(),
            masked_key,
            op: input.cmdreq_data.op,
            msg: input.cmdreq_data.msg.clone(),
            iv: input.cmdreq_data.iv,
        };
        let result = ctx.tbor(&req);

        if let Err(err) = &result {
            if matches!(err, DdiError::DriverError(_)) {
                panic!("Crash Detected: {err}");
            }
        }

        session.close().expect("session close should succeed");
    });
});

const AES_KEY_SCOPE_SESSION: u8 = 0b001;
