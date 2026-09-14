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
//! out-of-range length, and invalid ECDH-secret input). The concatenation
//! KDFs' byte-level correctness is covered by the `azihsm_crypto`
//! known-answer tests, which share the same primitive.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::TborConcatKdfDeriveReq;
use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
use azihsm_ddi_tbor_types::TborEcdhDeriveReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::CONCAT_INFO_MAX_LEN;
use azihsm_ddi_tbor_types::CONCAT_KDF_ALG_SP800_56A;
use azihsm_ddi_tbor_types::CONCAT_KDF_ALG_X963;
use azihsm_ddi_tbor_types::ECC_CURVE_P256;
use azihsm_ddi_tbor_types::ECC_CURVE_P384;
use azihsm_ddi_tbor_types::ECC_CURVE_P521;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_AES128;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_AES192;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_AES256;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_HMAC_SHA256;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_HMAC_SHA384;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_HMAC_SHA512;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_VAR_HMAC256;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_VAR_HMAC384;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_VAR_HMAC512;
use azihsm_ddi_tbor_types::KEY_USAGE_DERIVE;

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
fn fresh_masked_secret_for_curve(ctx: &TestCtx, session_id: u16, curve: u8) -> Vec<u8> {
    let key_a = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id,
            scope: SCOPE_LOCAL,
            curve,
            key_usage: KEY_USAGE_DERIVE,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey a");

    let key_b = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id,
            scope: SCOPE_LOCAL,
            curve,
            key_usage: KEY_USAGE_DERIVE,
            key_label: Vec::new(),
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

/// Derive a fresh P-256 masked ECDH shared secret for tests that do not vary IKM size.
fn fresh_masked_secret(ctx: &TestCtx, session_id: u16) -> Vec<u8> {
    fresh_masked_secret_for_curve(ctx, session_id, ECC_CURVE_P256)
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

/// Derives every supported output key type with both concatenation-KDF algorithms.
#[test]
fn concat_kdf_all_key_types_both_algs() {
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

/// Derives successfully with every supported hash algorithm and key scope.
#[test]
fn concat_kdf_all_hashes_and_scopes() {
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

/// Accepts ECDH shared secrets from every supported curve size.
#[test]
fn concat_kdf_all_secret_sizes() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for curve in [ECC_CURVE_P256, ECC_CURVE_P384, ECC_CURVE_P521] {
        let ikm = fresh_masked_secret_for_curve(&ctx, session.session_id, curve);

        let masked = concat_kdf(
            &ctx,
            session.session_id,
            SCOPE_LOCAL,
            HASH_SHA384,
            CONCAT_KDF_ALG_X963,
            KDF_KEY_TYPE_AES256,
            0,
            ikm,
            Vec::new(),
        );

        assert_eq!(masked.len(), MASK_OVERHEAD + 32);
        assert!(
            masked.iter().any(|&b| b != 0),
            "masked derived key must not be all-zero for curve {curve}",
        );
    }
}

/// Accepts the maximum supported concatenation-KDF info length.
#[test]
fn concat_kdf_max_info_length() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
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
        vec![0x5a; CONCAT_INFO_MAX_LEN],
    );

    assert_eq!(masked.len(), MASK_OVERHEAD + 32);
    assert!(masked.iter().any(|&b| b != 0));
}

/// Exercises the fixed-size HMAC-SHA384 output type directly.
#[test]
fn concat_kdf_hmac_sha384() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret_for_curve(&ctx, session.session_id, ECC_CURVE_P384);

    let masked = concat_kdf(
        &ctx,
        session.session_id,
        SCOPE_LOCAL,
        HASH_SHA384,
        CONCAT_KDF_ALG_X963,
        KDF_KEY_TYPE_HMAC_SHA384,
        0,
        ikm,
        b"hmac384".to_vec(),
    );

    assert_eq!(masked.len(), MASK_OVERHEAD + 48);
    assert!(masked.iter().any(|&b| b != 0));
}

/// Derives a fixed-size HMAC-SHA512 key successfully.
#[test]
fn concat_kdf_hmac_sha512() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    let masked = concat_kdf(
        &ctx,
        session.session_id,
        SCOPE_LOCAL,
        HASH_SHA512,
        CONCAT_KDF_ALG_X963,
        KDF_KEY_TYPE_HMAC_SHA512,
        0,
        ikm,
        Vec::new(),
    );

    assert_eq!(masked.len(), MASK_OVERHEAD + 64);
    assert!(masked.iter().any(|&b| b != 0));
}

/// Accepts both empty and non-empty optional KDF info.
#[test]
fn concat_kdf_optional_info() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

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

/// Accepts the minimum supported `VarHmac256` output length.
#[test]
fn concat_kdf_var_hmac256_min_length() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    let masked = concat_kdf(
        &ctx,
        session.session_id,
        SCOPE_LOCAL,
        HASH_SHA256,
        CONCAT_KDF_ALG_X963,
        KDF_KEY_TYPE_VAR_HMAC256,
        32,
        ikm,
        Vec::new(),
    );

    assert_eq!(masked.len(), MASK_OVERHEAD + 32);
    assert!(masked.iter().any(|&b| b != 0));
}

/// Accepts the maximum supported `VarHmac256` output length.
#[test]
fn concat_kdf_var_hmac256_max_length() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    let masked = concat_kdf(
        &ctx,
        session.session_id,
        SCOPE_LOCAL,
        HASH_SHA512,
        CONCAT_KDF_ALG_SP800_56A,
        KDF_KEY_TYPE_VAR_HMAC256,
        64,
        ikm,
        b"boundary".to_vec(),
    );

    assert_eq!(masked.len(), MASK_OVERHEAD + 64);
    assert!(masked.iter().any(|&b| b != 0));
}

/// Rejects a `VarHmac256` output length immediately below the supported minimum.
#[test]
fn concat_kdf_var_hmac256_below_min_length_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    ctx.expect_fw_reject(
        &TborConcatKdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA256,
            kdf_alg: CONCAT_KDF_ALG_X963,
            key_type: KDF_KEY_TYPE_VAR_HMAC256,
            key_length: 31,
            masked_secret: ikm,
            info: Vec::new(),
        },
        TborStatus::InvalidKeyLength,
    );
}

/// Rejects a `VarHmac256` output length immediately above the supported maximum.
#[test]
fn concat_kdf_var_hmac256_above_max_length_rejected() {
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
            key_length: 65,
            masked_secret: ikm,
            info: Vec::new(),
        },
        TborStatus::InvalidKeyLength,
    );
}

/// Rejects an unsupported hash algorithm.
#[test]
fn concat_kdf_unknown_hash_rejected() {
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

/// Rejects an unsupported concatenation-KDF algorithm.
#[test]
fn concat_kdf_unknown_alg_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

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

/// Rejects an unsupported derived-key type.
#[test]
fn concat_kdf_unknown_key_type_rejected() {
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

/// Rejects an unknown derived-key scope.
#[test]
fn concat_kdf_unknown_scope_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    ctx.expect_fw_reject(
        &TborConcatKdfDeriveReq {
            session_id: session.session_id,
            scope: 0xff,
            hash_algo: HASH_SHA256,
            kdf_alg: CONCAT_KDF_ALG_X963,
            key_type: KDF_KEY_TYPE_AES256,
            key_length: 0,
            masked_secret: ikm,
            info: Vec::new(),
        },
        TborStatus::UnsupportedKeyScope,
    );
}

/// Rejects `VarHmac256` when its required output length is omitted.
#[test]
fn concat_kdf_var_hmac_missing_length_rejected() {
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

/// Rejects a `VarHmac256` output length far above the supported range.
#[test]
fn concat_kdf_var_hmac_out_of_range_length_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

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

/// Rejects a masked ECC private key when an ECDH shared secret is required.
#[test]
fn concat_kdf_non_secret_ikm_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let ecc = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_DERIVE,
            key_label: Vec::new(),
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

/// Rejects a truncated masked ECDH shared-secret envelope.
#[test]
fn concat_kdf_truncated_masked_secret_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let mut ikm = fresh_masked_secret(&ctx, session.session_id);

    ikm.pop();

    ctx.expect_fw_reject(
        &TborConcatKdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA384,
            kdf_alg: CONCAT_KDF_ALG_X963,
            key_type: KDF_KEY_TYPE_AES256,
            key_length: 0,
            masked_secret: ikm,
            info: Vec::new(),
        },
        TborStatus::TborInvalidFixedLength,
    );
}

/// Rejects a masked ECDH shared secret whose authenticated envelope is corrupted.
#[test]
fn concat_kdf_tampered_masked_secret_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let mut ikm = fresh_masked_secret(&ctx, session.session_id);

    let last = ikm
        .last_mut()
        .expect("masked ECDH secret must not be empty");
    *last ^= 0x01;

    ctx.expect_fw_reject(
        &TborConcatKdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA384,
            kdf_alg: CONCAT_KDF_ALG_X963,
            key_type: KDF_KEY_TYPE_AES256,
            key_length: 0,
            masked_secret: ikm,
            info: Vec::new(),
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
}

/// Accepts the minimum supported `VarHmac512` output length.
#[test]
fn concat_kdf_var_hmac512_min_length() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    let masked = concat_kdf(
        &ctx,
        session.session_id,
        SCOPE_LOCAL,
        HASH_SHA512,
        CONCAT_KDF_ALG_X963,
        KDF_KEY_TYPE_VAR_HMAC512,
        64,
        ikm,
        Vec::new(),
    );

    assert_eq!(masked.len(), MASK_OVERHEAD + 64);
    assert!(masked.iter().any(|&b| b != 0));
}

/// Accepts the maximum supported `VarHmac512` output length.
#[test]
fn concat_kdf_var_hmac512_max_length() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    let masked = concat_kdf(
        &ctx,
        session.session_id,
        SCOPE_LOCAL,
        HASH_SHA512,
        CONCAT_KDF_ALG_SP800_56A,
        KDF_KEY_TYPE_VAR_HMAC512,
        128,
        ikm,
        Vec::new(),
    );

    assert_eq!(masked.len(), MASK_OVERHEAD + 128);
    assert!(masked.iter().any(|&b| b != 0));
}

/// Rejects a `VarHmac512` length immediately below the supported minimum.
#[test]
fn concat_kdf_var_hmac512_below_min_length_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    ctx.expect_fw_reject(
        &TborConcatKdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA512,
            kdf_alg: CONCAT_KDF_ALG_X963,
            key_type: KDF_KEY_TYPE_VAR_HMAC512,
            key_length: 63,
            masked_secret: ikm,
            info: Vec::new(),
        },
        TborStatus::InvalidKeyLength,
    );
}

/// Rejects a `VarHmac512` length immediately above the supported maximum.
#[test]
fn concat_kdf_var_hmac512_above_max_length_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    ctx.expect_fw_reject(
        &TborConcatKdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA512,
            kdf_alg: CONCAT_KDF_ALG_SP800_56A,
            key_type: KDF_KEY_TYPE_VAR_HMAC512,
            key_length: 129,
            masked_secret: ikm,
            info: Vec::new(),
        },
        TborStatus::InvalidKeyLength,
    );
}

/// Rejects an empty masked ECDH shared secret.
#[test]
fn concat_kdf_empty_masked_secret_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    ctx.expect_fw_reject(
        &TborConcatKdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA256,
            kdf_alg: CONCAT_KDF_ALG_X963,
            key_type: KDF_KEY_TYPE_AES256,
            key_length: 0,
            masked_secret: Vec::new(),
            info: Vec::new(),
        },
        TborStatus::TborInvalidFixedLength,
    );
}

/// Rejects arbitrary bytes that are not a valid masked-secret envelope.
#[test]
fn concat_kdf_garbage_masked_secret_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let mut garbage = fresh_masked_secret(&ctx, session.session_id);
    // The masked-key metadata starts after the 8-byte envelope header and
    // 12-byte IV. Corrupt its magic while preserving valid TBOR/envelope
    // framing so firmware reaches masked-key metadata decoding.
    let metadata_magic = garbage
        .get_mut(8 + 12)
        .expect("masked ECDH secret must contain metadata");
    *metadata_magic ^= 0xff;

    ctx.expect_fw_reject(
        &TborConcatKdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA384,
            kdf_alg: CONCAT_KDF_ALG_X963,
            key_type: KDF_KEY_TYPE_AES256,
            key_length: 0,
            masked_secret: garbage,
            info: Vec::new(),
        },
        TborStatus::MaskedKeyDecodeFailed,
    );
}

/// Rejects derivation when the request session ID differs from the active session.
#[test]
fn concat_kdf_session_id_mismatch_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    ctx.expect_fw_reject(
        &TborConcatKdfDeriveReq {
            session_id: u16::MAX,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA256,
            kdf_alg: CONCAT_KDF_ALG_X963,
            key_type: KDF_KEY_TYPE_AES256,
            key_length: 0,
            masked_secret: ikm,
            info: Vec::new(),
        },
        TborStatus::FileHandleSessionIdDoesNotMatch,
    );
}

/// Ignores an explicit length for a fixed-size AES output type.
#[test]
fn concat_kdf_fixed_key_type_ignores_explicit_length() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    let masked = concat_kdf(
        &ctx,
        session.session_id,
        SCOPE_LOCAL,
        HASH_SHA256,
        CONCAT_KDF_ALG_X963,
        KDF_KEY_TYPE_AES256,
        17, // deliberately incorrect; fixed-size AES ignores key_length
        ikm,
        Vec::new(),
    );

    assert_eq!(masked.len(), MASK_OVERHEAD + 32);
    assert!(masked.iter().any(|&b| b != 0));
}

/// Accepts the minimum supported `VarHmac384` output length.
#[test]
fn concat_kdf_var_hmac384_min_length() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    let masked = concat_kdf(
        &ctx,
        session.session_id,
        SCOPE_LOCAL,
        HASH_SHA384,
        CONCAT_KDF_ALG_X963,
        KDF_KEY_TYPE_VAR_HMAC384,
        48,
        ikm,
        Vec::new(),
    );

    assert_eq!(masked.len(), MASK_OVERHEAD + 48);
    assert!(masked.iter().any(|&b| b != 0));
}

/// Accepts the maximum supported `VarHmac384` output length.
#[test]
fn concat_kdf_var_hmac384_max_length() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    let masked = concat_kdf(
        &ctx,
        session.session_id,
        SCOPE_LOCAL,
        HASH_SHA384,
        CONCAT_KDF_ALG_SP800_56A,
        KDF_KEY_TYPE_VAR_HMAC384,
        128,
        ikm,
        Vec::new(),
    );

    assert_eq!(masked.len(), MASK_OVERHEAD + 128);
    assert!(masked.iter().any(|&b| b != 0));
}

/// Rejects a `VarHmac384` length immediately below the supported minimum.
#[test]
fn concat_kdf_var_hmac384_below_min_length_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    ctx.expect_fw_reject(
        &TborConcatKdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA384,
            kdf_alg: CONCAT_KDF_ALG_X963,
            key_type: KDF_KEY_TYPE_VAR_HMAC384,
            key_length: 47,
            masked_secret: ikm,
            info: Vec::new(),
        },
        TborStatus::InvalidKeyLength,
    );
}

/// Rejects a `VarHmac384` length immediately above the supported maximum.
#[test]
fn concat_kdf_var_hmac384_above_max_length_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    ctx.expect_fw_reject(
        &TborConcatKdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA384,
            kdf_alg: CONCAT_KDF_ALG_SP800_56A,
            key_type: KDF_KEY_TYPE_VAR_HMAC384,
            key_length: 129,
            masked_secret: ikm,
            info: Vec::new(),
        },
        TborStatus::InvalidKeyLength,
    );
}
