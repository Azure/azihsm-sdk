// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `HkdfDerive` command.
//!
//! `HkdfDerive` derives key material (AES / HMAC) from a caller-held
//! **masked** ECDH shared secret (from
//! [`EcdhDerive`](super::ecdh_derive)) via HKDF (RFC 5869), returning the
//! derived key **masked** under the requested scope.
//!
//! Because the derived key is returned only in masked form (there is no
//! TBOR command to observe its plaintext), these tests validate the
//! command's plumbing: a well-formed masked key of the correct length for
//! each output type, derivation under each provisioned scope, optional
//! salt / info, and rejection of malformed requests (unknown hash / key
//! type, variable-length HMAC without / out-of-range length, and a
//! non-ECDH-secret IKM).  The underlying HKDF primitive's correctness is
//! covered by the MBOR `HkdfDerive` tests and the std-PAL KDF driver
//! tests, which share the same `pal.hkdf_extract` / `pal.hkdf_expand`.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
use azihsm_ddi_tbor_types::TborEcdhDeriveReq;
use azihsm_ddi_tbor_types::TborHkdfDeriveReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::ECC_CURVE_P256;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_AES128;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_AES192;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_AES256;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_HMAC_SHA256;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_HMAC_SHA384;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_HMAC_SHA512;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_VAR_HMAC256;
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

/// Derive a fresh masked ECDH shared secret (the HKDF IKM) on-device:
/// generate two P-256 keypairs and ECDH one against the other's public
/// key, returning the masked secret blob.
fn fresh_masked_secret(ctx: &TestCtx, session_id: u16) -> Vec<u8> {
    let key_a = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
            key_usage: KEY_USAGE_DERIVE,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey a");
    let key_b = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id,
            scope: SCOPE_LOCAL,
            curve: ECC_CURVE_P256,
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

/// Run `HkdfDerive` with the given parameters, returning the masked key.
#[allow(clippy::too_many_arguments)]
fn hkdf(
    ctx: &TestCtx,
    session_id: u16,
    scope: u8,
    hash_algo: u8,
    key_type: u8,
    key_length: u8,
    masked_secret: Vec<u8>,
    salt: Vec<u8>,
    info: Vec<u8>,
) -> Vec<u8> {
    ctx.tbor(&TborHkdfDeriveReq {
        session_id,
        scope,
        hash_algo,
        key_type,
        key_length,
        masked_secret,
        salt,
        info,
    })
    .expect("HkdfDerive")
    .masked_key
}

#[test]
fn hkdf_derive_all_key_types_emu() {
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

    for &(key_type, key_length, okm_len) in cases {
        let ikm = fresh_masked_secret(&ctx, session.session_id);
        let masked = hkdf(
            &ctx,
            session.session_id,
            SCOPE_LOCAL,
            HASH_SHA384,
            key_type,
            key_length,
            ikm,
            b"salt".to_vec(),
            b"info".to_vec(),
        );
        assert_eq!(
            masked.len(),
            MASK_OVERHEAD + okm_len,
            "masked derived-key envelope length must match the output type (type {key_type})",
        );
        assert!(
            masked.iter().any(|&b| b != 0),
            "masked derived key must not be all-zero (type {key_type})",
        );
    }
}

#[test]
fn hkdf_derive_all_hashes_and_scopes_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // Every hash PRF works, and the derived key can be masked under any
    // provisioned scope.
    for hash in [HASH_SHA256, HASH_SHA384, HASH_SHA512] {
        for scope in [SCOPE_SESSION, SCOPE_EPHEMERAL, SCOPE_LOCAL] {
            let ikm = fresh_masked_secret(&ctx, session.session_id);
            let masked = hkdf(
                &ctx,
                session.session_id,
                scope,
                hash,
                KDF_KEY_TYPE_AES256,
                0,
                ikm,
                Vec::new(),
                Vec::new(),
            );
            assert_eq!(masked.len(), MASK_OVERHEAD + 32);
            assert!(masked.iter().any(|&b| b != 0));
        }
    }
}

#[test]
fn hkdf_derive_optional_salt_info_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // All four combinations of present / absent (empty) salt and info are
    // accepted and produce a well-formed masked key.
    for (salt, info) in [
        (Vec::new(), Vec::new()),
        (b"only-salt".to_vec(), Vec::new()),
        (Vec::new(), b"only-info".to_vec()),
        (b"salt".to_vec(), b"info".to_vec()),
    ] {
        let ikm = fresh_masked_secret(&ctx, session.session_id);
        let masked = hkdf(
            &ctx,
            session.session_id,
            SCOPE_LOCAL,
            HASH_SHA256,
            KDF_KEY_TYPE_HMAC_SHA256,
            0,
            ikm,
            salt,
            info,
        );
        assert_eq!(masked.len(), MASK_OVERHEAD + 32);
        assert!(masked.iter().any(|&b| b != 0));
    }
}

#[test]
fn hkdf_derive_unknown_hash_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    // Hash discriminant `0` is not one of SHA-256 / 384 / 512.
    ctx.expect_fw_reject(
        &TborHkdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: 0,
            key_type: KDF_KEY_TYPE_AES256,
            key_length: 0,
            masked_secret: ikm,
            salt: Vec::new(),
            info: Vec::new(),
        },
        TborStatus::InvalidArg,
    );
}

#[test]
fn hkdf_derive_unknown_key_type_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    // Key-type discriminant `99` is not a supported KDF output type.
    ctx.expect_fw_reject(
        &TborHkdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA384,
            key_type: 99,
            key_length: 0,
            masked_secret: ikm,
            salt: Vec::new(),
            info: Vec::new(),
        },
        TborStatus::InvalidKeyType,
    );
}

#[test]
fn hkdf_derive_var_hmac_missing_length_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    // A variable-length HMAC output with `key_length = 0` (absent) is
    // rejected as `InvalidKeyType` (the wire sentinel for "var HMAC with no
    // explicit length").
    ctx.expect_fw_reject(
        &TborHkdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA256,
            key_type: KDF_KEY_TYPE_VAR_HMAC256,
            key_length: 0,
            masked_secret: ikm,
            salt: Vec::new(),
            info: Vec::new(),
        },
        TborStatus::InvalidKeyType,
    );
}

#[test]
fn hkdf_derive_var_hmac_out_of_range_length_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    // `VarHmac256` accepts 32..=64; `16` is below the minimum.
    ctx.expect_fw_reject(
        &TborHkdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA256,
            key_type: KDF_KEY_TYPE_VAR_HMAC256,
            key_length: 16,
            masked_secret: ikm,
            salt: Vec::new(),
            info: Vec::new(),
        },
        TborStatus::InvalidKeyLength,
    );
}

#[test]
fn hkdf_derive_non_secret_ikm_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // Feed an ECC *private key* blob (kind `Ecc256Private`) where an ECDH
    // shared secret is required; the post-unmask kind check rejects it.
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
        &TborHkdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA384,
            key_type: KDF_KEY_TYPE_AES256,
            key_length: 0,
            masked_secret: ecc.masked_key,
            salt: Vec::new(),
            info: Vec::new(),
        },
        TborStatus::InvalidKeyType,
    );
}
