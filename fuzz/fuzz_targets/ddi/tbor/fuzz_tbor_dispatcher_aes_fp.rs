// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_test_harness::*;
use azihsm_ddi_tbor_types::*;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Clone, Copy, Debug)]
enum FuzzAesType {
    AesGcm,
    AesXts,
}

#[derive(Arbitrary, Clone, Copy, Debug)]
enum FuzzAesMode {
    Encrypt,
    Decrypt,
}

#[derive(Arbitrary, Debug)]
struct FuzzAesGcmRequest {
    key_id: u32,
    iv: [u8; 12],
    tag: Option<[u8; 16]>,
    session_id: u16,
    short_app_id: u8,
    aad: Option<Vec<u8>>,
}

#[derive(Arbitrary, Debug)]
struct FuzzAesXtsRequest {
    data_unit_len: usize,
    key_id1: u32,
    key_id2: u32,
    tweak: [u8; AES_IV_LEN],
    session_id: u16,
    short_app_id: u8,
}

/// Retains the legacy fast-path input shape where it can be represented by
/// TBOR's caller-held masked key and AES-CBC request.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    aes_type: FuzzAesType,
    aes_mode: FuzzAesMode,
    use_valid_key: bool,
    key_scope: common::KeyScope,
    key_size: common::AesKeySize,
    key_usage: u64,
    key_label: Vec<u8>,
    gcm_request: FuzzAesGcmRequest,
    xts_request: FuzzAesXtsRequest,
    source_buffers: Vec<Vec<u8>>,
    /// Retained only to preserve the legacy fuzz-input layout.
    #[allow(dead_code)]
    destination_buffers: Vec<Vec<u8>>,
    masked_key: Vec<u8>,
}

const MAX_FUZZ_MSG_LEN: usize = AES_MSG_MAX_LEN + 1;

/// Concatenate source buffers, retaining at most one byte beyond the TBOR
/// message limit so oversized inputs exercise length validation.
fn message_from_sources(source_buffers: &[Vec<u8>]) -> Vec<u8> {
    let mut msg = Vec::new();
    for source in source_buffers {
        let remaining = MAX_FUZZ_MSG_LEN - msg.len();
        msg.extend_from_slice(&source[..source.len().min(remaining)]);
        if msg.len() == MAX_FUZZ_MSG_LEN {
            break;
        }
    }
    msg
}

/// Derive an AES-CBC IV from the selected legacy GCM or XTS request fields
/// so those fields continue to influence the TBOR request.
fn iv_from_input(input: &FuzzInput) -> [u8; AES_IV_LEN] {
    /// XOR input bytes into the IV, wrapping at the AES block boundary.
    fn fold(iv: &mut [u8; AES_IV_LEN], bytes: &[u8]) {
        for (index, byte) in bytes.iter().enumerate() {
            iv[index % AES_IV_LEN] ^= byte;
        }
    }

    match input.aes_type {
        FuzzAesType::AesGcm => {
            let mut iv = input.xts_request.tweak;
            iv[..input.gcm_request.iv.len()].copy_from_slice(&input.gcm_request.iv);
            fold(&mut iv, &input.gcm_request.key_id.to_le_bytes());
            fold(&mut iv, &input.gcm_request.session_id.to_le_bytes());
            fold(&mut iv, &[input.gcm_request.short_app_id]);
            if let Some(tag) = input.gcm_request.tag {
                fold(&mut iv, &tag);
            }
            if let Some(aad) = &input.gcm_request.aad {
                fold(&mut iv, aad);
            }
            iv
        }
        FuzzAesType::AesXts => {
            let mut iv = input.xts_request.tweak;
            fold(&mut iv, &input.xts_request.data_unit_len.to_le_bytes());
            fold(&mut iv, &input.xts_request.key_id1.to_le_bytes());
            fold(&mut iv, &input.xts_request.key_id2.to_le_bytes());
            fold(&mut iv, &input.xts_request.session_id.to_le_bytes());
            fold(&mut iv, &[input.xts_request.short_app_id]);
            iv
        }
    }
}

/// Append the selected legacy GCM or XTS request fields to the fuzzed
/// masked-key bytes for requests that do not generate a valid key.
fn legacy_masked_key(input: &FuzzInput) -> Vec<u8> {
    let mut key = input.masked_key.clone();
    match input.aes_type {
        FuzzAesType::AesGcm => {
            key.extend_from_slice(&input.gcm_request.key_id.to_le_bytes());
            key.extend_from_slice(&input.gcm_request.session_id.to_le_bytes());
            key.push(input.gcm_request.short_app_id);
            if let Some(tag) = input.gcm_request.tag {
                key.extend_from_slice(&tag);
            }
            if let Some(aad) = &input.gcm_request.aad {
                key.extend_from_slice(aad);
            }
        }
        FuzzAesType::AesXts => {
            key.extend_from_slice(&input.xts_request.data_unit_len.to_le_bytes());
            key.extend_from_slice(&input.xts_request.key_id1.to_le_bytes());
            key.extend_from_slice(&input.xts_request.key_id2.to_le_bytes());
            key.extend_from_slice(&input.xts_request.session_id.to_le_bytes());
            key.push(input.xts_request.short_app_id);
        }
    }
    key
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        let key_scope_is_supported = matches!(
            input.key_scope,
            common::KeyScope::Session
                | common::KeyScope::Ephemeral
                | common::KeyScope::Local
                | common::KeyScope::SecurityDomain
        );
        let key_usage_is_valid = input.key_usage == (KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT);
        let key_label_is_valid = input.key_label.len() <= TBOR_KEY_LABEL_MAX_LEN;
        let key_generation_should_succeed =
            key_scope_is_supported && key_usage_is_valid && key_label_is_valid;

        if input.use_valid_key && key_generation_should_succeed {
            match input.key_scope {
                common::KeyScope::Ephemeral | common::KeyScope::Local => {
                    common::finalize_partition(ctx, &session)
                }
                common::KeyScope::SecurityDomain => {
                    common::create_test_security_domain(ctx, &session)
                }
                common::KeyScope::Unspecified
                | common::KeyScope::Session
                | common::KeyScope::Internal => {}
            }
        }

        let (masked_key, generated_key) = if input.use_valid_key {
            match ctx.tbor(&TborAesGenerateKeyReq {
                session_id: session.session_id,
                scope: input.key_scope.to_tbor(),
                key_size: input.key_size.to_tbor(),
                key_usage: input.key_usage,
                key_label: input.key_label.clone(),
            }) {
                Ok(resp) if key_generation_should_succeed => (resp.masked_key, true),
                Ok(_) => panic!("invalid AES key-generation request unexpectedly succeeded"),
                Err(err @ DdiError::DriverError(_)) => panic!("Crash Detected: {err}"),
                Err(_) if !key_generation_should_succeed => (Vec::new(), false),
                Err(err) => panic!("valid AES key-generation request failed: {err}"),
            }
        } else {
            (legacy_masked_key(&input), false)
        };

        let msg = message_from_sources(&input.source_buffers);
        let iv = iv_from_input(&input);
        let op = match input.aes_mode {
            FuzzAesMode::Encrypt => AES_OP_ENCRYPT,
            FuzzAesMode::Decrypt => AES_OP_DECRYPT,
        };
        let expect_success = generated_key
            && !msg.is_empty()
            && msg.len().is_multiple_of(AES_IV_LEN)
            && msg.len() <= AES_MSG_MAX_LEN;

        let result = ctx.tbor(&TborAesEncryptDecryptReq {
            session_id: session.session_id,
            masked_key: masked_key.clone(),
            op,
            msg: msg.clone(),
            iv,
        });

        match (&result, expect_success) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash Detected: {err}"),
            (Ok(response), true) => {
                assert_eq!(
                    response.msg.len(),
                    msg.len(),
                    "output length must match input"
                );
                let round_trip = ctx
                    .tbor(&TborAesEncryptDecryptReq {
                        session_id: session.session_id,
                        masked_key,
                        op: match input.aes_mode {
                            FuzzAesMode::Encrypt => AES_OP_DECRYPT,
                            FuzzAesMode::Decrypt => AES_OP_ENCRYPT,
                        },
                        msg: response.msg.clone(),
                        iv,
                    })
                    .expect("inverse AES operation should succeed");
                assert_eq!(
                    round_trip.msg, msg,
                    "AES round trip must recover the original input"
                );
                assert_eq!(
                    round_trip.iv, response.iv,
                    "AES round-trip chaining IV must match"
                );
            }
            (Ok(_), false) => panic!("invalid AES request unexpectedly succeeded"),
            (Err(err), true) => panic!("valid AES request failed: {err}"),
            (Err(_), false) => {}
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
