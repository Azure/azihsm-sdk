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
use azihsm_ddi_tbor_types::TborHmacReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::ECC_CURVE_P256;
use azihsm_ddi_tbor_types::ECC_CURVE_P384;
use azihsm_ddi_tbor_types::ECC_CURVE_P521;
use azihsm_ddi_tbor_types::HKDF_INFO_MAX_LEN;
use azihsm_ddi_tbor_types::HKDF_SALT_MAX_LEN;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_AES128;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_AES192;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_AES256;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_HMAC_SHA256;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_HMAC_SHA384;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_HMAC_SHA512;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_VAR_HMAC256;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_VAR_HMAC384;
use azihsm_ddi_tbor_types::KDF_KEY_TYPE_VAR_HMAC512;

use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::harness::TestCtx;

/// `KeyScope::Session` discriminant.
const SCOPE_SESSION: u8 = 0b001;
/// `KeyScope::Ephemeral` discriminant.
const SCOPE_EPHEMERAL: u8 = 0b010;
/// `KeyScope::Local` discriminant.
const SCOPE_LOCAL: u8 = 0b011;
/// `KeyScope::SecurityDomain` discriminant (not provisioned by this fixture).
const SCOPE_SECURITY_DOMAIN: u8 = 0b100;

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
    fresh_masked_secret_for_curve(ctx, session_id, ECC_CURVE_P256)
}

/// Derive a fresh masked ECDH shared secret on the requested curve.
fn fresh_masked_secret_for_curve(ctx: &TestCtx, session_id: u16, curve: u8) -> Vec<u8> {
    let key_a = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id,
            scope: SCOPE_LOCAL,
            curve,
        })
        .expect("EccGenerateKey a");
    let key_b = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id,
            scope: SCOPE_LOCAL,
            curve,
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

/// Derives every supported fixed and variable-length output key type.
#[test]
fn hkdf_derive_all_key_types() {
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
        (KDF_KEY_TYPE_VAR_HMAC256, 32, 32),
        (KDF_KEY_TYPE_VAR_HMAC256, 64, 64),
        (KDF_KEY_TYPE_VAR_HMAC384, 48, 48),
        (KDF_KEY_TYPE_VAR_HMAC384, 128, 128),
        (KDF_KEY_TYPE_VAR_HMAC512, 64, 64),
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

/// Accepts ECDH shared secrets produced by all supported ECC curves.
#[test]
fn hkdf_derive_accepts_all_ecdh_secret_sizes() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // P-256, P-384, and P-521 produce the minimum, intermediate, and maximum
    // masked-secret lengths accepted by the request schema.
    for curve in [ECC_CURVE_P256, ECC_CURVE_P384, ECC_CURVE_P521] {
        let ikm = fresh_masked_secret_for_curve(&ctx, session.session_id, curve);
        let masked = hkdf(
            &ctx,
            session.session_id,
            SCOPE_LOCAL,
            HASH_SHA384,
            KDF_KEY_TYPE_AES256,
            0,
            ikm,
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(masked.len(), MASK_OVERHEAD + 32, "curve {curve}");
    }
}

/// Derives successfully with every supported hash algorithm and provisioned key scope.
#[test]
fn hkdf_derive_all_hashes_and_scopes() {
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

/// Accepts all combinations of present and absent HKDF salt and info.
#[test]
fn hkdf_derive_optional_salt_info() {
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

/// Accepts salt and info at their maximum supported lengths.
#[test]
fn hkdf_derive_maximum_salt_and_info() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    let masked = hkdf(
        &ctx,
        session.session_id,
        SCOPE_LOCAL,
        HASH_SHA512,
        KDF_KEY_TYPE_HMAC_SHA512,
        0,
        ikm,
        vec![0xa5; HKDF_SALT_MAX_LEN],
        vec![0x5a; HKDF_INFO_MAX_LEN],
    );
    assert_eq!(masked.len(), MASK_OVERHEAD + 64);
}

/// Identical inputs are stable while changing salt or info changes the derived key.
#[test]
fn hkdf_derive_is_stable_and_salt_info_separate_outputs() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    let derive = |salt: &[u8], info: &[u8]| {
        hkdf(
            &ctx,
            session.session_id,
            SCOPE_LOCAL,
            HASH_SHA256,
            KDF_KEY_TYPE_HMAC_SHA256,
            0,
            ikm.clone(),
            salt.to_vec(),
            info.to_vec(),
        )
    };
    let tag = |masked_key: Vec<u8>| {
        ctx.tbor(&TborHmacReq {
            session_id: session.session_id,
            masked_key,
            msg: b"derived-key probe".to_vec(),
        })
        .expect("Hmac with HKDF-derived key")
        .tag
    };

    let baseline = tag(derive(b"salt", b"info"));
    assert_eq!(
        baseline,
        tag(derive(b"salt", b"info")),
        "identical HKDF inputs must derive identical key material",
    );
    assert_ne!(
        baseline,
        tag(derive(b"different salt", b"info")),
        "salt must affect the derived key",
    );
    assert_ne!(
        baseline,
        tag(derive(b"salt", b"different info")),
        "info must affect the derived key",
    );
}

#[test]
fn hkdf_derive_unknown_hash_rejected() {
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

/// Rejects an unsupported derived-key type.
#[test]
fn hkdf_derive_unknown_key_type_rejected() {
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

/// Rejects an unsupported key scope.
#[test]
fn hkdf_derive_unsupported_scope_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    ctx.expect_fw_reject(
        &TborHkdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_SECURITY_DOMAIN,
            hash_algo: HASH_SHA384,
            key_type: KDF_KEY_TYPE_AES256,
            key_length: 0,
            masked_secret: ikm,
            salt: Vec::new(),
            info: Vec::new(),
        },
        TborStatus::UnsupportedKeyScope,
    );
}

/// Rejects a variable-length HMAC key type when no explicit length is supplied.
#[test]
fn hkdf_derive_var_hmac_missing_length_rejected() {
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

/// Rejects a variable-length HMAC output below its minimum supported length.
#[test]
fn hkdf_derive_var_hmac_out_of_range_length_rejected() {
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

/// Rejects a masked ECC private key when an ECDH shared secret is required.
#[test]
fn hkdf_derive_non_secret_ikm_rejected() {
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

/// Rejects a tampered masked ECDH shared secret whose authentication tag no longer matches.
#[test]
fn hkdf_derive_tampered_masked_secret_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let mut ikm = fresh_masked_secret(&ctx, session.session_id);
    let last = ikm.len() - 1;
    ikm[last] ^= 1;

    ctx.expect_fw_reject(
        &TborHkdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA384,
            key_type: KDF_KEY_TYPE_AES256,
            key_length: 0,
            masked_secret: ikm,
            salt: Vec::new(),
            info: Vec::new(),
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
}

/// Fixed-size key types ignore `key_length` and derive their size from `key_type`.
#[test]
fn hkdf_derive_fixed_key_type_key_length_is_ignored() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    for key_length in [1, 16, 31, 32, 64, 255] {
        let masked = hkdf(
            &ctx,
            session.session_id,
            SCOPE_LOCAL,
            HASH_SHA384,
            KDF_KEY_TYPE_AES256,
            key_length,
            ikm.clone(),
            Vec::new(),
            Vec::new(),
        );

        assert_eq!(
            masked.len(),
            MASK_OVERHEAD + 32,
            "AES-256 output length must be fixed regardless of key_length={key_length}",
        );
    }
}

/// Rejects an HKDF request carrying an unknown session ID.
#[test]
fn hkdf_derive_invalid_session_id_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    ctx.expect_fw_reject(
        &TborHkdfDeriveReq {
            session_id: u16::MAX,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA384,
            key_type: KDF_KEY_TYPE_AES256,
            key_length: 0,
            masked_secret: ikm,
            salt: Vec::new(),
            info: Vec::new(),
        },
        TborStatus::FileHandleSessionIdDoesNotMatch,
    );
}

/// Different HKDF hash algorithms derive different key material from identical inputs.
#[test]
fn hkdf_derive_different_hashes_produce_different_keys() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    let derive_tag = |hash_algo| {
        let masked_key = hkdf(
            &ctx,
            session.session_id,
            SCOPE_LOCAL,
            hash_algo,
            KDF_KEY_TYPE_HMAC_SHA256,
            0,
            ikm.clone(),
            b"salt".to_vec(),
            b"info".to_vec(),
        );

        ctx.tbor(&TborHmacReq {
            session_id: session.session_id,
            masked_key,
            msg: b"derived-key probe".to_vec(),
        })
        .expect("Hmac")
        .tag
    };

    let sha256 = derive_tag(HASH_SHA256);
    let sha384 = derive_tag(HASH_SHA384);
    let sha512 = derive_tag(HASH_SHA512);

    assert_ne!(sha256, sha384);
    assert_ne!(sha256, sha512);
    assert_ne!(sha384, sha512);
}

/// Different ECDH shared secrets derive different key material with identical HKDF parameters.
#[test]
fn hkdf_derive_different_ikm_produces_different_keys() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let ikm_a = fresh_masked_secret(&ctx, session.session_id);
    let ikm_b = fresh_masked_secret(&ctx, session.session_id);

    let derive_tag = |ikm| {
        let masked_key = hkdf(
            &ctx,
            session.session_id,
            SCOPE_LOCAL,
            HASH_SHA256,
            KDF_KEY_TYPE_HMAC_SHA256,
            0,
            ikm,
            b"salt".to_vec(),
            b"info".to_vec(),
        );

        ctx.tbor(&TborHmacReq {
            session_id: session.session_id,
            masked_key,
            msg: b"derived-key probe".to_vec(),
        })
        .expect("Hmac")
        .tag
    };

    assert_ne!(
        derive_tag(ikm_a),
        derive_tag(ikm_b),
        "different ECDH secrets must derive different keys",
    );
}

/// Rejects a variable-length HMAC output above its maximum supported length.
#[test]
fn hkdf_derive_var_hmac_above_max_length_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let ikm = fresh_masked_secret(&ctx, session.session_id);

    // VarHmac256 accepts 32..=64.
    ctx.expect_fw_reject(
        &TborHkdfDeriveReq {
            session_id: session.session_id,
            scope: SCOPE_LOCAL,
            hash_algo: HASH_SHA256,
            key_type: KDF_KEY_TYPE_VAR_HMAC256,
            key_length: 65,
            masked_secret: ikm,
            salt: Vec::new(),
            info: Vec::new(),
        },
        TborStatus::InvalidKeyLength,
    );
}
