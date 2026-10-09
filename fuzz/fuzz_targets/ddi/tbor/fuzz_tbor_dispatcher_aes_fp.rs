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
    key_size: common::AesKeySize,
    gcm_request: FuzzAesGcmRequest,
    xts_request: FuzzAesXtsRequest,
    source_buffers: Vec<Vec<u8>>,
    destination_buffers: Vec<Vec<u8>>,
    masked_key: Vec<u8>,
}

const AES_KEY_SCOPE_SESSION: u8 = 0b001;
const MAX_FUZZ_MSG_LEN: usize = AES_MSG_MAX_LEN + 1;

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

fn iv_from_input(input: &FuzzInput) -> [u8; AES_IV_LEN] {
    fn fold(iv: &mut [u8; AES_IV_LEN], bytes: &[u8]) {
        for (index, byte) in bytes.iter().enumerate() {
            iv[index % AES_IV_LEN] ^= byte;
        }
    }

    match input.aes_type {
        FuzzAesType::AesGcm => {
            let mut iv = [0; AES_IV_LEN];
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
    if (MASKED_AES_KEY_MIN_LEN..=MASKED_AES_KEY_MAX_LEN).contains(&key.len()) {
        key.resize(MASKED_AES_KEY_MAX_LEN + 1, 0);
    }
    key
}

fn verify_response_buffers(response: &[u8], destination_buffers: &mut Vec<Vec<u8>>) {
    if destination_buffers.is_empty() {
        destination_buffers.push(Vec::new());
    }

    let mut offset = 0;
    for buffer in destination_buffers.iter_mut() {
        let count = buffer.len().min(response.len() - offset);
        buffer.clear();
        buffer.extend_from_slice(&response[offset..offset + count]);
        offset += count;
    }

    if offset < response.len() {
        destination_buffers
            .last_mut()
            .expect("a destination buffer was inserted above")
            .extend_from_slice(&response[offset..]);
    }

    let scattered: Vec<u8> = destination_buffers
        .iter()
        .flat_map(|buffer| buffer.iter().copied())
        .collect();
    assert_eq!(scattered, response, "scattered response must be preserved");
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        let mut destination_buffers = input.destination_buffers.clone();
        let masked_key = if input.use_valid_key {
            ctx.tbor(&TborAesGenerateKeyReq {
                session_id: session.session_id,
                scope: AES_KEY_SCOPE_SESSION,
                key_size: input.key_size.to_tbor(),
                key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
                key_label: Vec::new(),
            })
            .expect("session-scoped AES key generation should succeed")
            .masked_key
        } else {
            legacy_masked_key(&input)
        };

        let msg = message_from_sources(&input.source_buffers);
        let msg_len = msg.len();
        let op = match input.aes_mode {
            FuzzAesMode::Encrypt => AES_OP_ENCRYPT,
            FuzzAesMode::Decrypt => AES_OP_DECRYPT,
        };
        let expect_success = input.use_valid_key
            && !msg.is_empty()
            && msg.len().is_multiple_of(AES_IV_LEN)
            && msg.len() <= AES_MSG_MAX_LEN;

        let result = ctx.tbor(&TborAesEncryptDecryptReq {
            session_id: session.session_id,
            masked_key,
            op,
            msg,
            iv: iv_from_input(&input),
        });

        match (&result, expect_success) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash Detected: {err}"),
            (Ok(response), true) => {
                assert_eq!(
                    response.msg.len(),
                    msg_len,
                    "output length must match input"
                );
                verify_response_buffers(&response.msg, &mut destination_buffers);
            }
            (Ok(_), false) => panic!("invalid AES request unexpectedly succeeded"),
            (Err(err), true) => panic!("valid AES request failed: {err}"),
            (Err(_), false) => {}
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
