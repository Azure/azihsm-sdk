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
use common::EccCurve;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// TBOR key scopes. `bootstrap_rotated_co` guarantees a session masking key;
/// it does not provision the partition or security-domain scopes.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum KeyScope {
    Session,
    Ephemeral,
    Local,
    SecurityDomain,
}

impl KeyScope {
    fn to_tbor(self) -> u8 {
        match self {
            Self::Session => KEY_SCOPE_SESSION,
            Self::Ephemeral => KEY_SCOPE_EPHEMERAL,
            Self::Local => KEY_SCOPE_LOCAL,
            Self::SecurityDomain => KEY_SCOPE_SECURITY_DOMAIN,
        }
    }
}

/// Fuzzed fields corresponding to the TBOR `HkdfDerive` request. The MBOR
/// `key_id` is replaced with a masked ECDH secret, and `key_tag` maps to the
/// TBOR output `key_label`.
#[derive(Arbitrary, Debug)]
struct FuzzHkdfDeriveReq {
    masked_secret: Vec<u8>,
    hash_algo: u8,
    salt: Vec<u8>,
    info: Vec<u8>,
    key_type: u8,
    key_label: Vec<u8>,
    key_length: u8,
}

/// Fuzz input for the TBOR `HkdfDerive` command. TBOR has no independent
/// key-availability or key-properties fields; output scope and key type are
/// fuzzed in their place.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Generate a valid masked ECDH secret instead of using fuzzed bytes.
    use_valid_key_id: bool,
    /// Output scope, serving as TBOR's scope-level counterpart to MBOR key
    /// availability.
    key_availability: KeyScope,
    /// Selects the curve for the generated ECDH secret.
    key_curve: EccCurve,
    cmdreq_data: FuzzHkdfDeriveReq,
}

const KEY_SCOPE_SESSION: u8 = 0b001;
const KEY_SCOPE_EPHEMERAL: u8 = 0b010;
const KEY_SCOPE_LOCAL: u8 = 0b011;
const KEY_SCOPE_SECURITY_DOMAIN: u8 = 0b100;

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);

        let masked_secret = if input.use_valid_key_id {
            let key_a = ctx
                .tbor(&TborEccGenerateKeyReq {
                    session_id: session.session_id,
                    scope: KEY_SCOPE_SESSION,
                    curve: input.key_curve.to_tbor(),
                    key_usage: KEY_USAGE_DERIVE,
                    key_label: Vec::new(),
                })
                .expect("session-scoped ECC key generation should succeed");
            let key_b = ctx
                .tbor(&TborEccGenerateKeyReq {
                    session_id: session.session_id,
                    scope: KEY_SCOPE_SESSION,
                    curve: input.key_curve.to_tbor(),
                    key_usage: KEY_USAGE_DERIVE,
                    key_label: Vec::new(),
                })
                .expect("session-scoped ECC peer key generation should succeed");
            ctx.tbor(&TborEcdhDeriveReq {
                session_id: session.session_id,
                scope: KEY_SCOPE_SESSION,
                masked_key: key_a.masked_key,
                peer_pub_key: key_b.pub_key,
                key_label: Vec::new(),
            })
            .expect("session-scoped ECDH derive should succeed")
            .masked_secret
        } else {
            input.cmdreq_data.masked_secret.clone()
        };

        let scope = input.key_availability.to_tbor();
        let req = TborHkdfDeriveReq {
            session_id: session.session_id,
            scope,
            hash_algo: input.cmdreq_data.hash_algo,
            key_type: input.cmdreq_data.key_type,
            key_length: input.cmdreq_data.key_length,
            masked_secret,
            salt: input.cmdreq_data.salt.clone(),
            info: input.cmdreq_data.info.clone(),
            key_label: input.cmdreq_data.key_label.clone(),
        };
        let result = ctx.tbor(&req);

        let expect_success = input.use_valid_key_id
            && matches!(input.key_availability, KeyScope::Session)
            && matches!(input.cmdreq_data.hash_algo, 1..=3)
            && valid_key_length(input.cmdreq_data.key_type, input.cmdreq_data.key_length)
            && input.cmdreq_data.salt.len() <= HKDF_SALT_MAX_LEN
            && input.cmdreq_data.info.len() <= HKDF_INFO_MAX_LEN
            && input.cmdreq_data.key_label.len() <= TBOR_KEY_LABEL_MAX_LEN;

        match (&result, expect_success) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash Detected: {err}"),
            (Ok(resp), true) => {
                assert_eq!(
                    resp.masked_key.len(),
                    MASKED_KEY_OVERHEAD
                        + output_key_len(input.cmdreq_data.key_type, input.cmdreq_data.key_length,),
                    "masked derived-key envelope length must match the requested key type"
                );
            }
            (Ok(_), false) => panic!("invalid HKDF request unexpectedly succeeded"),
            (Err(err), true) => panic!("valid HKDF request failed: {err}"),
            (Err(_), false) => {}
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});

const MASKED_KEY_OVERHEAD: usize = 8 + 12 + 192 + 16;

fn valid_key_length(key_type: u8, key_length: u8) -> bool {
    match key_type {
        KDF_KEY_TYPE_AES128
        | KDF_KEY_TYPE_AES192
        | KDF_KEY_TYPE_AES256
        | KDF_KEY_TYPE_HMAC_SHA256
        | KDF_KEY_TYPE_HMAC_SHA384
        | KDF_KEY_TYPE_HMAC_SHA512 => true,
        KDF_KEY_TYPE_VAR_HMAC256 => (32..=64).contains(&key_length),
        KDF_KEY_TYPE_VAR_HMAC384 => (48..=128).contains(&key_length),
        KDF_KEY_TYPE_VAR_HMAC512 => (64..=128).contains(&key_length),
        _ => false,
    }
}

fn output_key_len(key_type: u8, key_length: u8) -> usize {
    match key_type {
        KDF_KEY_TYPE_AES128
        | KDF_KEY_TYPE_AES192
        | KDF_KEY_TYPE_AES256
        | KDF_KEY_TYPE_HMAC_SHA256
        | KDF_KEY_TYPE_HMAC_SHA384
        | KDF_KEY_TYPE_HMAC_SHA512 => fixed_key_len(key_type),
        KDF_KEY_TYPE_VAR_HMAC256 | KDF_KEY_TYPE_VAR_HMAC384 | KDF_KEY_TYPE_VAR_HMAC512 => {
            usize::from(key_length)
        }
        _ => 0,
    }
}

fn fixed_key_len(key_type: u8) -> usize {
    match key_type {
        KDF_KEY_TYPE_AES128 => 16,
        KDF_KEY_TYPE_AES192 => 24,
        KDF_KEY_TYPE_AES256 => 32,
        KDF_KEY_TYPE_HMAC_SHA256 => 32,
        KDF_KEY_TYPE_HMAC_SHA384 => 48,
        KDF_KEY_TYPE_HMAC_SHA512 => 64,
        _ => 0,
    }
}
