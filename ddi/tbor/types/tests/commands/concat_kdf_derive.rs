// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `ConcatKdfDerive` command.
//!
//! `ConcatKdfDerive` derives key material (AES / HMAC) from a caller-held
//! **masked** ECDH shared secret (from
//! [`EcdhDerive`](super::ecdh_derive)) via a single-step concatenation KDF
//! — ANSI X9.63 or NIST SP 800-56A one-step — returning the derived key
//! **masked** under the requested scope.
//!
//! Because the derived key is returned only in masked form (there is no
//! TBOR command to observe its plaintext), these tests validate the
//! command's plumbing: a well-formed masked key of the correct length for
//! each output type under each KDF variant, derivation under each
//! provisioned scope, optional info, and rejection of malformed requests
//! (unknown hash / KDF variant / key type, variable-length HMAC without /
//! out-of-range length, and a non-ECDH-secret IKM).  The concatenation
//! KDFs' byte-level correctness is covered by the `azihsm_crypto`
//! known-answer tests, which share the same primitive.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::TborConcatKdfDeriveReq;
use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
use azihsm_ddi_tbor_types::TborEcdhDeriveReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::CONCAT_KDF_ALG_SP800_56A;
use azihsm_ddi_tbor_types::CONCAT_KDF_ALG_X963;
use azihsm_ddi_tbor_types::ECC_CURVE_P256;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_AES128;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_AES192;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_AES256;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_HMAC_SHA256;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_HMAC_SHA384;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_HMAC_SHA512;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_VAR_HMAC256;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_VAR_HMAC512;

use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::harness::TestCtx;

/// `KeyScope::Session` discriminant.
const SCOPE_SESSION: u8 = 0b001;
/// `KeyScope::Ephemeral` discriminant.
const SCOPE_EPHEMERAL: u8 = 0b010;
/// `KeyScope::Local` discriminant.
const SCOPE_LOCAL: u8 = 0b011;

/// `HashAlgo::Sha256` discriminant.
const HASH_SHA256: u8 = 1;
/// `HashAlgo::Sha384` discriminant.
const HASH_SHA384: u8 = 2;
/// `HashAlgo::Sha512` discriminant.
const HASH_SHA512: u8 = 3;

/// AEAD-GCM-256 masked-key envelope overhead:
/// `header(8) ‖ iv(12) ‖ aad(96) ‖ tag(16)` = 132 B around the plaintext.
const MASK_OVERHEAD: usize = 8 + 12 + 96 + 16;

/// Derive a fresh masked ECDH shared secret (the KDF IKM) on-device.
fn fresh_masked_secret(ctx: &TestCtx, session_id: u16) -> Vec<u8> {
    let key_a = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
        })
        .expect("EccGenerateKey a");
    let key_b = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
        })
        .expect("EccGenerateKey b");
    ctx.tbor(&TborEcdhDeriveReq {
        session_id,
        scope: SCOPE_LOCAL,
        masked_key: key_a.masked_key,
        peer_pub_key: key_b.pub_key,
    })
    .expect("EcdhDerive")
    .masked_secret
}

/// Run `ConcatKdfDerive` with the given parameters, returning the masked key.
#[allow(clippy::too_many_arguments)]
fn concat_kdf(
    ctx: &TestCtx,
    session_id: u16,
    scope: u8,
    hash_algo: u8,
    kdf_alg: u8,
    key_type: u8,
    key_length: u8,
    masked_secret: Vec<u8>,
    info: Vec<u8>,
) -> Vec<u8> {
    ctx.tbor(&TborConcatKdfDeriveReq {
        session_id,
        scope,
        hash_algo,
        kdf_alg,
        key_type,
        key_length,
        masked_secret,
        info,
    })
    .expect("ConcatKdfDerive")
    .masked_key
}

#[test]
fn concat_kdf_all_key_types_both_algs_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // (key_type, key_length, expected OKM length).
    let cases: &[(u8, u8, usize)] = &[
        (KDF_KEY_TYPE_AES128, 0, 16),
        (KDF_KEY_TYPE_AES192, 0, 24),
        (KDF_KEY_TYPE_AES256, 0, 32),
        (KDF_KEY_TYPE_HMAC_SHA256, 0, 32),
        (KDF_KEY_TYPE_HMAC_SHA384, 0, 48),
        (KDF_KEY_TYPE_HMAC_SHA512, 0, 64),
        (KDF_KEY_TYPE_VAR_HMAC256, 40, 40),
        (KDF_KEY_TYPE_VAR_HMAC512, 128, 128),
    ];

    for kdf_alg in [CONCAT_KDF_ALG_X963, CONCAT_KDF_ALG_SP800_56A] {
        for &(key_type, key_length, okm_len) in cases {
            let ikm = fresh_masked_secret(&ctx, session.session_id);
            let masked = concat_kdf(
                &ctx,
                session.session_id,
                SCOPE_LOCAL,
                HASH_SHA384,
                kdf_alg,
                key_type,
                key_length,
                ikm,
                b"info".to_vec(),
            );
            assert_eq!(
                masked.len(),
                MASK_OVERHEAD + okm_len,
                "masked derived-key length must match the output type (alg {kdf_alg}, type {key_type})",
            );
            assert!(
                masked.iter().any(|&b| b != 0),
                "masked derived key must not be all-zero (alg {kdf_alg}, type {key_type})",
            );
        }
    }
}

#[test]
fn concat_kdf_all_hashes_and_scopes_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for hash in [HASH_SHA256, HASH_SHA384, HASH_SHA512] {
        for scope in [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL] {
            let ikm = fresh_masked_secret(&ctx, session.session_id);
            let masked = concat_kdf(
                &ctx,
                session.session_id,
                scope,
                hash,
                CONCAT_KDF_ALG_X963,
                KDF_KEY_TYPE_AES256,
                0,
                ikm,
                Vec::new(),
            );
            assert_eq!(masked.len(), MASK_OVERHEAD + 32);
            assert!(masked.iter().any(|&b| b != 0));
        }
    }
}

#[test]
fn concat_kdf_optional_info_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // Both present and absent (empty) info are accepted.
    for info in [Vec::new(), b"shared-info".to_vec()] {
        let ikm = fresh_masked_secret(&ctx, session.session_id);
        let masked = concat_kdf(
            &ctx,
            session.session_id,
            SCOPE_LOCAL,
            HASH_SHA256,
            CONCAT_KDF_ALG_SP800_56A,
            KDF_KEY_TYPE_HMAC_SHA256,
            0,
            ikm,
            info,
        );
        assert_eq!(masked.len(), MASK_OVERHEAD + 32);
        assert!(masked.iter().any(|&b| b != 0));
    }
}

#[test]
fn concat_kdf_unknown_hash_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    ctx.expect_fw_reject(
        &TborConcatKdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: 0,
            kdf_alg: CONCAT_KDF_ALG_X963,
            key_type: KDF_KEY_TYPE_AES256,
            key_length: 0,
            masked_secret: ikm,
            info: Vec::new(),
        },
        TborStatus::InvalidArg,
    );
}

#[test]
fn concat_kdf_unknown_alg_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    // KDF-variant discriminant `7` is neither X9.63 nor SP 800-56A.
    ctx.expect_fw_reject(
        &TborConcatKdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA256,
            kdf_alg: 7,
            key_type: KDF_KEY_TYPE_AES256,
            key_length: 0,
            masked_secret: ikm,
            info: Vec::new(),
        },
        TborStatus::InvalidArg,
    );
}

#[test]
fn concat_kdf_unknown_key_type_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    ctx.expect_fw_reject(
        &TborConcatKdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA384,
            kdf_alg: CONCAT_KDF_ALG_X963,
            key_type: 99,
            key_length: 0,
            masked_secret: ikm,
            info: Vec::new(),
        },
        TborStatus::InvalidKeyType,
    );
}

#[test]
fn concat_kdf_var_hmac_missing_length_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    ctx.expect_fw_reject(
        &TborConcatKdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA256,
            kdf_alg: CONCAT_KDF_ALG_SP800_56A,
            key_type: KDF_KEY_TYPE_VAR_HMAC256,
            key_length: 0,
            masked_secret: ikm,
            info: Vec::new(),
        },
        TborStatus::InvalidKeyType,
    );
}

#[test]
fn concat_kdf_var_hmac_out_of_range_length_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    // `VarHmac256` accepts 32..=64; `200` is above the maximum.
    ctx.expect_fw_reject(
        &TborConcatKdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA256,
            kdf_alg: CONCAT_KDF_ALG_X963,
            key_type: KDF_KEY_TYPE_VAR_HMAC256,
            key_length: 200,
            masked_secret: ikm,
            info: Vec::new(),
        },
        TborStatus::InvalidKeyLength,
    );
}

#[test]
fn concat_kdf_non_secret_ikm_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // Feed an ECC *private key* blob (kind `Ecc256Private`) where an ECDH
    // shared secret is required; the post-unmask kind check rejects it.
    let ecc = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
        })
        .expect("EccGenerateKey");

    ctx.expect_fw_reject(
        &TborConcatKdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA384,
            kdf_alg: CONCAT_KDF_ALG_X963,
            key_type: KDF_KEY_TYPE_AES256,
            key_length: 0,
            masked_secret: ecc.masked_key,
            info: Vec::new(),
        },
        TborStatus::InvalidKeyType,
    );
}
