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

/// Elliptic curve selector mirroring the `EccCurve` wire discriminants.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum EccCurve {
    P256,
    P384,
    P521,
}

impl EccCurve {
    fn to_tbor(self) -> u8 {
        match self {
            Self::P256 => ECC_CURVE_P256,
            Self::P384 => ECC_CURVE_P384,
            Self::P521 => ECC_CURVE_P521,
        }
    }

    /// Raw shared-secret (X coordinate) length.
    fn secret_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }
}

/// Key scope selector mirroring the `KeyScope` wire discriminants.
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

/// Fuzzed parameters mirroring the TBOR `EcdhDerive` request fields (the
/// TBOR equivalent of the MBOR `EcdhKeyExchange` command).
#[derive(Arbitrary, Debug)]
struct FuzzEcdhDeriveReq {
    masked_key: Vec<u8>,
    peer_pub_key: Vec<u8>,
    key_label: Vec<u8>,
}

/// Fuzz input for the TBOR `EcdhDerive` command.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// If `true`, the fuzz test will generate a valid masked ECC private
    /// key (via `EccGenerateKey`) instead of using fuzzed bytes.
    use_valid_masked_key: bool,
    /// If `true`, the fuzz test will generate a valid peer ECC key pair
    /// and use its wire public key instead of fuzzed/seeded bytes.
    use_valid_peer_pub_key: bool,
    /// Seed used to deterministically fill the peer public-key buffer
    /// when `use_valid_peer_pub_key` is `false`.
    seed: u64,
    /// Requested key scope for the derived secret. Generated input/peer
    /// keys always use session scope, since `bootstrap_rotated_co` does
    /// not provision partition or security-domain masking keys.
    key_scope: KeyScope,
    /// Selects the elliptic curve used for ECC key generation.
    curve: EccCurve,
    /// A fuzzed `TborEcdhDeriveReq` structure that provides the base for
    /// request parameters for the ECDH operation.
    cmdreq_data: FuzzEcdhDeriveReq,
}

const KEY_SCOPE_SESSION: u8 = 0b001;
const KEY_SCOPE_EPHEMERAL: u8 = 0b010;
const KEY_SCOPE_LOCAL: u8 = 0b011;
const KEY_SCOPE_SECURITY_DOMAIN: u8 = 0b100;

/// Deterministically fill a buffer of `len` bytes from `seed` using a
/// small splitmix64-style generator (no external `rand` dependency).
fn seeded_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed;
    let mut buf = Vec::with_capacity(len);
    while buf.len() < len {
        state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        buf.extend_from_slice(&z.to_le_bytes());
    }
    buf.truncate(len);
    buf
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        let (masked_key, peer_pub_key) = if input.use_valid_masked_key {
            let key_req = TborEccGenerateKeyReq {
                session_id: session.session_id,
                scope: KEY_SCOPE_SESSION,
                curve: input.curve.to_tbor(),
                key_usage: KEY_USAGE_DERIVE,
                key_label: Vec::new(),
            };
            let masked_key = ctx
                .tbor(&key_req)
                .expect("session-scoped ECC key generation should succeed")
                .masked_key;

            let peer_pub_key = if input.use_valid_peer_pub_key {
                let peer_key_req = TborEccGenerateKeyReq {
                    session_id: session.session_id,
                    scope: KEY_SCOPE_SESSION,
                    curve: input.curve.to_tbor(),
                    key_usage: KEY_USAGE_DERIVE,
                    key_label: Vec::new(),
                };
                ctx.tbor(&peer_key_req)
                    .expect("session-scoped ECC peer key generation should succeed")
                    .pub_key
            } else {
                // Deterministically generate a buffer sized to the maximum
                // peer public-key length using the provided seed.
                seeded_bytes(input.seed, ECDH_PEER_PUB_MAX_LEN)
            };

            (masked_key, peer_pub_key)
        } else {
            (
                input.cmdreq_data.masked_key.clone(),
                input.cmdreq_data.peer_pub_key.clone(),
            )
        };

        let req = TborEcdhDeriveReq {
            session_id: session.session_id,
            scope: input.key_scope.to_tbor(),
            masked_key,
            peer_pub_key,
            key_label: input.cmdreq_data.key_label.clone(),
        };
        let result = ctx.tbor(&req);

        // Only generated key pairs with an encodable label can derive; of
        // those, only Session scope has a provisioned masking key after
        // `bootstrap_rotated_co`.
        let valid_keys = input.use_valid_masked_key
            && input.use_valid_peer_pub_key
            && input.cmdreq_data.key_label.len() <= TBOR_KEY_LABEL_MAX_LEN;
        let session_scope = matches!(input.key_scope, KeyScope::Session);

        match &result {
            Err(err @ DdiError::DriverError(_)) => panic!("Crash Detected: {err}"),
            Ok(resp) if valid_keys && session_scope => assert_eq!(
                resp.masked_secret.len(),
                MASKED_SECRET_MIN_LEN - 32 + input.curve.secret_len(),
                "masked secret length must match the curve secret length"
            ),
            Ok(resp) => panic!("invalid ECDH request unexpectedly succeeded: {resp:?}"),
            Err(err) if valid_keys && session_scope => panic!("valid ECDH request failed: {err}"),
            Err(err) if valid_keys => assert!(
                matches!(err, DdiError::TborStatus(TborStatus::UnsupportedKeyScope)),
                "unprovisioned scope must be rejected with UnsupportedKeyScope, got {err}"
            ),
            Err(_) => {}
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
