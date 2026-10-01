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

/// Key types generated as masked blobs for the TBOR `KeyReport` request.
#[derive(Arbitrary, Debug)]
enum KeySource {
    EccGenerated(EccCurve),
    GeneratedAesKey(AesKeySize),
    HmacKey(HmacHash),
}

#[derive(Arbitrary, Debug)]
enum EccCurve {
    P256,
    P384,
    P521,
}

impl EccCurve {
    fn to_tbor(&self) -> u8 {
        match self {
            Self::P256 => ECC_CURVE_P256,
            Self::P384 => ECC_CURVE_P384,
            Self::P521 => ECC_CURVE_P521,
        }
    }
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
enum HmacHash {
    Sha256,
    Sha384,
    Sha512,
}

impl HmacHash {
    fn to_tbor(&self) -> u8 {
        match self {
            Self::Sha256 => HMAC_HASH_SHA256,
            Self::Sha384 => HMAC_HASH_SHA384,
            Self::Sha512 => HMAC_HASH_SHA512,
        }
    }

    fn valid_key_length(&self, fuzzed_length: u8) -> u8 {
        let (min, max) = match self {
            Self::Sha256 => (32, 64),
            Self::Sha384 => (48, 128),
            Self::Sha512 => (64, 128),
        };
        min + (fuzzed_length % (max - min + 1))
    }
}

/// Fuzz input for TBOR `KeyReport` (the TBOR equivalent of MBOR `AttestKey`).
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Generate a supported TBOR key and use its masked blob.
    use_generated_key: bool,
    /// Selects the key generator used when `use_generated_key` is true.
    key_source: KeySource,
    /// Used as-is when generating is disabled; used to choose a valid
    /// HMAC key length when `key_source` selects HMAC.
    fuzzed_key_data: FuzzKeyReportData,
}

#[derive(Arbitrary, Debug)]
struct FuzzKeyReportData {
    masked_key: Vec<u8>,
    report_data: [u8; KEY_REPORT_DATA_LEN],
    hmac_key_length: u8,
}

const KEY_SCOPE_SESSION: u8 = 0b001;

fn generate_masked_key(ctx: &TestCtx, session_id: u16, input: &FuzzInput) -> Vec<u8> {
    match &input.key_source {
        KeySource::EccGenerated(curve) => {
            ctx.tbor(&TborEccGenerateKeyReq {
                session_id,
                scope: KEY_SCOPE_SESSION,
                curve: curve.to_tbor(),
                key_usage: KEY_USAGE_SIGN,
                key_label: Vec::new(),
            })
            .expect("session-scoped ECC key generation should succeed")
            .masked_key
        }
        KeySource::GeneratedAesKey(key_size) => {
            ctx.tbor(&TborAesGenerateKeyReq {
                session_id,
                scope: KEY_SCOPE_SESSION,
                key_size: key_size.to_tbor(),
                key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
                key_label: Vec::new(),
            })
            .expect("session-scoped AES key generation should succeed")
            .masked_key
        }
        KeySource::HmacKey(hash) => {
            ctx.tbor(&TborHmacGenerateKeyReq {
                session_id,
                scope: KEY_SCOPE_SESSION,
                hash_algo: hash.to_tbor(),
                key_length: hash.valid_key_length(input.fuzzed_key_data.hmac_key_length),
                key_label: Vec::new(),
            })
            .expect("session-scoped HMAC key generation should succeed")
            .masked_key
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        let masked_key = if input.use_generated_key {
            generate_masked_key(ctx, session.session_id, &input)
        } else {
            input.fuzzed_key_data.masked_key.clone()
        };
        let req = TborKeyReportReq {
            session_id: session.session_id,
            masked_key,
            report_data: input.fuzzed_key_data.report_data,
        };
        let result = ctx.tbor(&req);

        if let Err(err) = &result {
            if matches!(err, DdiError::DriverError(_)) {
                panic!("Crash Detected: {err}");
            }
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
