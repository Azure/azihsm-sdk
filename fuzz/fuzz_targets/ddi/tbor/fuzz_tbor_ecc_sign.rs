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
/// not persistent key IDs, so only session-scoped valid keys are generated.
#[derive(Arbitrary, Debug)]
enum KeyAvailability {
    App,
    Session,
}

/// Hash selector from the MBOR request; TBOR identifies the digest algorithm
/// by its byte length instead.
#[derive(Arbitrary, Debug)]
enum DigestAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Unknown(u32),
}

impl DigestAlgorithm {
    fn digest_len(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
            Self::Unknown(value) => *value as usize % (ECC_DIGEST_MAX_LEN + 1),
        }
    }
}

/// ECC curve for generated TBOR signing keys.
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

    /// Largest digest the firmware zero-extends into the ECDSA field.
    fn max_digest_len(&self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 64,
        }
    }

    /// Wire `r ‖ s` length, each component padded to the coordinate width.
    fn wire_sig_len(&self) -> usize {
        match self {
            Self::P256 => 64,
            Self::P384 => 96,
            Self::P521 => 136,
        }
    }
}

/// Fuzz input corresponding to the MBOR `EccSign` target.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Generate a valid session-scoped ECC key when the legacy availability
    /// setting can be represented by TBOR.
    use_valid_key_id: bool,
    /// Legacy key availability; TBOR's caller-held masked keys have no App
    /// key-ID lifecycle equivalent.
    key_availability: KeyAvailability,
    /// Curve for valid key generation.
    curve: EccCurve,
    /// Request parameters corresponding to the MBOR request.
    cmdreq_data: FuzzEccSignReq,
}

#[derive(Arbitrary, Debug)]
struct FuzzEccSignReq {
    /// Legacy MBOR key ID, folded into the arbitrary masked-key bytes since
    /// TBOR carries the masked key itself instead.
    key_id: u16,
    /// Host-order digest bytes.
    digest: Vec<u8>,
    /// MBOR hash selector, mapped to TBOR's digest-length selector.
    digest_algo: DigestAlgorithm,
    /// Arbitrary masked-key bytes used when a valid key is not generated.
    masked_key: Vec<u8>,
}

const KEY_SCOPE_SESSION: u8 = 0b001;

fn wire_digest(input: &FuzzEccSignReq) -> Vec<u8> {
    let digest_len = input.digest_algo.digest_len();
    let mut digest = input.digest.clone();
    digest.truncate(digest_len);
    digest.resize(digest_len, 0);
    digest.reverse();
    digest
}

fn fuzzed_masked_key(input: &FuzzEccSignReq) -> Vec<u8> {
    let mut masked_key = input.masked_key.clone();
    masked_key.extend_from_slice(&input.key_id.to_le_bytes());
    masked_key
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        let generate_valid_key =
            input.use_valid_key_id && matches!(input.key_availability, KeyAvailability::Session);

        let masked_key = if generate_valid_key {
            ctx.tbor(&TborEccGenerateKeyReq {
                session_id: session.session_id,
                scope: KEY_SCOPE_SESSION,
                curve: input.curve.to_tbor(),
                key_usage: KEY_USAGE_SIGN,
                key_label: Vec::new(),
            })
            .expect("session-scoped ECC key generation should succeed")
            .masked_key
        } else {
            fuzzed_masked_key(&input.cmdreq_data)
        };

        let digest = wire_digest(&input.cmdreq_data);
        let expect_success = generate_valid_key
            && matches!(digest.len(), 32 | 48 | 64)
            && digest.len() <= input.curve.max_digest_len();

        let req = TborEccSignReq {
            session_id: session.session_id,
            masked_key,
            digest,
        };
        let result = ctx.tbor(&req);

        match (&result, expect_success) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash Detected: {err}"),
            (Ok(resp), true) => assert_eq!(
                resp.signature.len(),
                input.curve.wire_sig_len(),
                "signature length must match the curve wire length"
            ),
            (Ok(resp), false) => {
                panic!("invalid ECC sign request unexpectedly succeeded: {resp:?}")
            }
            (Err(err), true) => panic!("valid ECC sign request failed: {err}"),
            (Err(_), false) => {}
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
