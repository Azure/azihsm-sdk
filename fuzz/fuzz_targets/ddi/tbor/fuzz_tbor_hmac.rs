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

/// MBOR key availability. TBOR key-generation responses are masked blobs,
/// not persistent key IDs, so only session-scoped valid keys are generated
/// (mirrors the `EccSign` fuzz target's reasoning).
#[derive(Arbitrary, Debug)]
enum KeyAvailability {
    App,
    Session,
}

/// HMAC hash variant selector. TBOR identifies the variant with a 1-byte
/// `HashAlgo` discriminant instead of the MBOR `HmacKeyType` key-type
/// enum, and derives both the tag length and the valid `HmacGenerateKey`
/// key-length range from it.
#[derive(Arbitrary, Debug)]
enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    fn to_tbor(&self) -> u8 {
        match self {
            Self::Sha256 => HMAC_HASH_SHA256,
            Self::Sha384 => HMAC_HASH_SHA384,
            Self::Sha512 => HMAC_HASH_SHA512,
        }
    }

    fn tag_len(&self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Map a fuzzed byte into this variant's valid `HmacGenerateKey`
    /// key-length range (SHA-256: 32-64, SHA-384: 48-128, SHA-512: 64-128).
    fn valid_key_length(&self, fuzzed_length: u8) -> u8 {
        let (min, max) = match self {
            Self::Sha256 => (32, 64),
            Self::Sha384 => (48, 128),
            Self::Sha512 => (64, 128),
        };
        min + (fuzzed_length % (max - min + 1))
    }
}

/// Fuzz input corresponding to the MBOR `Hmac` target.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Generate a valid session-scoped HMAC key when the legacy
    /// availability setting can be represented by TBOR.
    use_valid_key_id: bool,
    /// Legacy key availability; TBOR's caller-held masked keys have no App
    /// key-ID lifecycle equivalent.
    key_availability: KeyAvailability,
    /// Hash variant used for valid key generation; also folds in the
    /// legacy `hash_algorithm` field, since TBOR's `HmacGenerateKey`
    /// carries a single hash selector for both.
    hash_algorithm: HashAlgorithm,
    /// Request parameters corresponding to the MBOR request.
    cmdreq_data: FuzzHmacReq,
}

#[derive(Arbitrary, Debug)]
struct FuzzHmacReq {
    /// Legacy MBOR key ID, folded into the arbitrary masked-key bytes
    /// since TBOR carries the masked key itself instead.
    key_id: u16,
    /// Message to MAC.
    msg: Vec<u8>,
    /// Fuzzed byte mapped into the chosen hash variant's valid
    /// `HmacGenerateKey` key-length range.
    key_length: u8,
    /// Arbitrary masked-key bytes used when a valid key is not generated.
    masked_key: Vec<u8>,
}

/// `KeyScope::Session` discriminant.
const KEY_SCOPE_SESSION: u8 = 0b001;

fn fuzzed_masked_key(input: &FuzzHmacReq) -> Vec<u8> {
    let mut masked_key = input.masked_key.clone();
    masked_key.extend_from_slice(&input.key_id.to_le_bytes());
    masked_key
}

/// Bound a fuzzed message to the `Hmac` command's documented maximum
/// length ([`HMAC_MSG_MAX_LEN`]) so a valid request never overflows the
/// 4-KiB TBOR request buffer.
fn bounded_msg(msg: &[u8]) -> Vec<u8> {
    let len = msg.len() % (HMAC_MSG_MAX_LEN + 1);
    msg[..len].to_vec()
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        let generate_valid_key =
            input.use_valid_key_id && matches!(input.key_availability, KeyAvailability::Session);

        let masked_key = if generate_valid_key {
            ctx.tbor(&TborHmacGenerateKeyReq {
                session_id: session.session_id,
                scope: KEY_SCOPE_SESSION,
                hash_algo: input.hash_algorithm.to_tbor(),
                key_length: input
                    .hash_algorithm
                    .valid_key_length(input.cmdreq_data.key_length),
                key_label: Vec::new(),
            })
            .expect("session-scoped HMAC key generation should succeed")
            .masked_key
        } else {
            fuzzed_masked_key(&input.cmdreq_data)
        };

        let msg = bounded_msg(&input.cmdreq_data.msg);
        let expect_success = generate_valid_key;

        let req = TborHmacReq {
            session_id: session.session_id,
            masked_key,
            msg,
        };
        let result = ctx.tbor(&req);

        match (&result, expect_success) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash Detected: {err}"),
            (Ok(resp), true) => {
                assert_eq!(
                    resp.tag.len(),
                    input.hash_algorithm.tag_len(),
                    "tag length must match the hash variant's digest length"
                );
                let tag_again = ctx
                    .tbor(&req)
                    .expect("repeating a valid Hmac request should succeed")
                    .tag;
                assert_eq!(resp.tag, tag_again, "HMAC must be deterministic");
            }
            (Ok(_), false) => {
                panic!("invalid Hmac request unexpectedly succeeded")
            }
            (Err(err), true) => panic!("valid Hmac request failed: {err}"),
            (Err(_), false) => {}
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
