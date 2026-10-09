// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_types::*;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const MIN_NUMBER_OF_REQS: usize = 1;
const MAX_NUMBER_OF_REQS: usize = 32;
const KEY_SCOPE_SESSION: u8 = 0b001;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    /// Seed used to choose a deterministic sequence of TBOR requests.
    rand_seed: u64,
    /// Whether to bind requests to the open session or use an invalid id.
    use_valid_header: bool,
}

#[derive(Clone, Copy)]
enum Command {
    AesGenerateKey,
    EccGenerateKey,
    HmacGenerateKey,
}

fn next_random(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E3779B97F4A7C15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D049BB133111EB);
    value ^ (value >> 31)
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        let number_of_reqs = (input.rand_seed as usize
            % (MAX_NUMBER_OF_REQS - MIN_NUMBER_OF_REQS + 1))
            + MIN_NUMBER_OF_REQS;
        let mut state = input.rand_seed;

        for _ in 0..number_of_reqs {
            let command = match next_random(&mut state) % 3 {
                0 => Command::AesGenerateKey,
                1 => Command::EccGenerateKey,
                _ => Command::HmacGenerateKey,
            };
            let session_id = if input.use_valid_header {
                session.session_id
            } else {
                session.session_id ^ 0x8000
            };

            let succeeded = match command {
                Command::AesGenerateKey => {
                    let req = TborAesGenerateKeyReq {
                        session_id,
                        scope: KEY_SCOPE_SESSION,
                        key_size: AES_KEY_SIZE_128,
                        key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
                        key_label: Vec::new(),
                    };
                    match ctx.tbor(&req) {
                        Ok(resp) => {
                            assert!(
                                (MASKED_AES_KEY_MIN_LEN..=MASKED_AES_KEY_MAX_LEN)
                                    .contains(&resp.masked_key.len()),
                                "AES key generation returned an invalid masked-key length"
                            );
                            true
                        }
                        Err(err @ azihsm_ddi_interface::DdiError::DriverError(_)) => {
                            panic!("Crash Detected: {err}")
                        }
                        Err(_) => false,
                    }
                }
                Command::EccGenerateKey => {
                    let req = TborEccGenerateKeyReq {
                        session_id,
                        scope: KEY_SCOPE_SESSION,
                        curve: ECC_CURVE_P256,
                        key_usage: KEY_USAGE_SIGN,
                        key_label: Vec::new(),
                    };
                    match ctx.tbor(&req) {
                        Ok(resp) => {
                            assert_eq!(resp.pub_key.len(), 64);
                            assert!(
                                (MASKED_ECC_KEY_MIN_LEN..=MASKED_ECC_KEY_MAX_LEN)
                                    .contains(&resp.masked_key.len()),
                                "ECC key generation returned an invalid masked-key length"
                            );
                            true
                        }
                        Err(_) => false,
                    }
                }
                Command::HmacGenerateKey => {
                    let req = TborHmacGenerateKeyReq {
                        session_id,
                        scope: KEY_SCOPE_SESSION,
                        hash_algo: HMAC_HASH_SHA256,
                        key_length: 32,
                        key_label: Vec::new(),
                    };
                    match ctx.tbor(&req) {
                        Ok(resp) => {
                            assert_eq!(resp.masked_key.len(), MASKED_HMAC_KEY_MIN_LEN);
                            true
                        }
                        Err(_) => false,
                    }
                }
            };

            if input.use_valid_header {
                assert!(succeeded, "valid TBOR request unexpectedly failed");
            } else {
                assert!(!succeeded, "request with an invalid session id succeeded");
            }
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
