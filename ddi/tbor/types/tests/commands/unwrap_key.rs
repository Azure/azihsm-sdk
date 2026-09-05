// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `UnwrapKey` command.
//!
//! `UnwrapKey` RSA-AES-unwraps a host-supplied wrapped key with the
//! partition's unwrapping key (from `GetUnwrappingKey`) and returns it
//! masked under the requested scope.  These tests wrap a known key on the
//! host (RSA-OAEP a KEK against the unwrapping public key, AES-KWP the
//! key), unwrap it on-device, and check the result.
//!
//! Coverage:
//! * AES key — the masked blob is non-zero and there is no public key.
//! * HMAC key — the recovered key's kind is `VarLenHmacSha256` and it
//!   carries no public key.  (Using the recovered key via `Hmac` to
//!   compute a MAC is exercised by the HMAC command's own emu tests,
//!   which build on this command.)
//! * RSA-4096 (CRT and non-CRT) — the largest supported key and the
//!   tightest on the per-IO DMA budget; exercises the transient-vault
//!   unwrap path that keeps it within 8 KB.

#![cfg(feature = "emu")]

use azihsm_crypto::AesKey;
use azihsm_crypto::AesKeyWrapPadAlgo;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::Encrypter;
use azihsm_crypto::ExportableKey;
use azihsm_crypto::HashAlgo;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::KeyGenerationOp;
use azihsm_crypto::RsaEncryptAlgo;
use azihsm_crypto::RsaPrivateKey;
use azihsm_crypto::RsaPublicKey;
use azihsm_ddi_tbor_types::TborGetUnwrappingKeyReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::TborUnwrapKeyReq;
use azihsm_ddi_tbor_types::TborUnwrapKeyResp;
use azihsm_ddi_tbor_types::KEY_CLASS_AES;
use azihsm_ddi_tbor_types::KEY_CLASS_ECC;
use azihsm_ddi_tbor_types::KEY_CLASS_HMAC_SHA256;
use azihsm_ddi_tbor_types::KEY_CLASS_HMAC_SHA384;
use azihsm_ddi_tbor_types::KEY_CLASS_HMAC_SHA512;
use azihsm_ddi_tbor_types::KEY_CLASS_RSA;
use azihsm_ddi_tbor_types::KEY_CLASS_RSA_CRT;
use azihsm_ddi_tbor_types::KEY_USAGE_DECRYPT;
use azihsm_ddi_tbor_types::KEY_USAGE_ENCRYPT;
use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;
use azihsm_ddi_tbor_types::KEY_USAGE_VERIFY;

use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::harness::TestCtx;

/// OAEP hash discriminant (SHA-256) used for wrapping.
const OAEP_SHA256: u8 = 1;
/// `KeyScope::Local` discriminant — masks the recovered key under the
/// partition-local masking key.
const SCOPE_LOCAL: u8 = 0b011;
/// `HsmVaultKeyKind::VarLenHmacSha256` discriminant.
const KIND_HMAC_SHA256: u8 = 32;

/// RSA-AES-wrap `data` against the HSM-format unwrapping public key
/// (`n_le ‖ e_le`): RSA-OAEP(SHA-256) an ephemeral 32-byte KEK, then
/// AES-KWP the data under it, and concatenate.
fn rsa_aes_wrap(hsm_pub: &[u8], data: &[u8]) -> Vec<u8> {
    // `GetUnwrappingKey` returns the modulus / exponent little-endian
    // (`n_le(256) ‖ e_le(4)`), but `RsaPublicKey::from_hsm_bytes` parses
    // each component big-endian — reverse them per-component.
    assert_eq!(hsm_pub.len(), 260, "RSA-2048 HSM pubkey is 260 bytes");
    let mut be = Vec::with_capacity(260);
    be.extend(hsm_pub[..256].iter().rev());
    be.extend(hsm_pub[256..260].iter().rev());

    let ephemeral_kek = [0xA7u8; 32];
    let pub_key = RsaPublicKey::from_hsm_bytes(&be).expect("from_hsm_bytes");
    let mut enc_kek = Encrypter::encrypt_vec(
        &mut RsaEncryptAlgo::with_oaep_padding(HashAlgo::sha256(), None),
        &pub_key,
        &ephemeral_kek,
    )
    .expect("RSA-OAEP wrap KEK");
    // The device expects the OAEP ciphertext in wire-LE (it flips it to
    // big-endian internally for OpenSSL); OpenSSL emits big-endian, so
    // reverse the modulus-sized RSA ciphertext.
    enc_kek.reverse();

    let kek = AesKey::from_bytes(&ephemeral_kek).expect("AES KEK");
    let mut enc_data = Encrypter::encrypt_vec(&mut AesKeyWrapPadAlgo::default(), &kek, data)
        .expect("AES-KWP wrap data");

    let mut wrapped = Vec::with_capacity(enc_kek.len() + enc_data.len());
    wrapped.append(&mut enc_kek);
    wrapped.append(&mut enc_data);
    wrapped
}

/// Canonical valid `KeyUsage` for a wrapped-key `class`, used by the test
/// `unwrap` helper so callers need not spell out permissions.
fn usage_for_class(class: u8) -> u64 {
    match class {
        KEY_CLASS_AES => KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
        KEY_CLASS_RSA | KEY_CLASS_RSA_CRT => KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        KEY_CLASS_ECC => KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        KEY_CLASS_HMAC_SHA256 | KEY_CLASS_HMAC_SHA384 | KEY_CLASS_HMAC_SHA512 => {
            KEY_USAGE_SIGN | KEY_USAGE_VERIFY
        }
        _ => 0,
    }
}

/// Fetch the unwrapping public key, wrap `key` for `class`, and unwrap it
/// on-device under the `Local` scope with the class's canonical usage.
pub(crate) fn unwrap(ctx: &TestCtx, session_id: u16, class: u8, key: &[u8]) -> TborUnwrapKeyResp {
    unwrap_with_usage(ctx, session_id, class, usage_for_class(class), key)
}

/// Like [`unwrap`], but with an explicit `usage` — for exercising the
/// per-class permission validation.
pub(crate) fn unwrap_with_usage(
    ctx: &TestCtx,
    session_id: u16,
    class: u8,
    usage: u64,
    key: &[u8],
) -> TborUnwrapKeyResp {
    let hsm_pub = ctx
        .tbor(&TborGetUnwrappingKeyReq { session_id })
        .expect("GetUnwrappingKey")
        .pub_key;
    let wrapped = rsa_aes_wrap(&hsm_pub, key);
    ctx.tbor(&TborUnwrapKeyReq {
        session_id,
        scope: SCOPE_LOCAL,
        key_class: class,
        key_usage: usage,
        oaep_hash_algo: OAEP_SHA256,
        wrapped_blob: wrapped,
    })
    .expect("UnwrapKey")
}

/// Import a host-generated RSA-4096 key via `UnwrapKey` and assert the
/// recovered blob is well-formed.  RSA-4096 is the largest supported key
/// and the tightest on the per-IO DMA budget — this exercises the
/// transient-vault unwrap path that keeps it within 8 KB (both the CRT and
/// non-CRT vault forms).
fn rsa_4k_unwrap_roundtrip(crt: bool) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // `generate` takes the modulus size in bytes: 512 = RSA-4096.
    let key = RsaPrivateKey::generate(512).expect("generate RSA-4096 key");
    let der = key.to_vec().expect("RSA private DER export");
    let class = if crt {
        KEY_CLASS_RSA_CRT
    } else {
        KEY_CLASS_RSA
    };
    let resp = unwrap(&ctx, session.session_id, class, &der);

    assert!(
        resp.masked_key.iter().any(|&b| b != 0),
        "masked RSA key must not be all-zero",
    );
    // RSA-4096 wire public key is `n_le(512) ‖ e_le(4)`.
    assert_eq!(
        resp.pub_key.len(),
        516,
        "RSA-4096 recovered public key is n_le(512) ‖ e_le(4)",
    );
}

#[test]
fn unwrap_key_rsa_4k_emu() {
    rsa_4k_unwrap_roundtrip(false);
}

#[test]
fn unwrap_key_rsa_4k_crt_emu() {
    rsa_4k_unwrap_roundtrip(true);
}

#[test]
fn unwrap_key_aes_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let aes_key = [0x42u8; 32];
    let resp = unwrap(&ctx, session.session_id, KEY_CLASS_AES, &aes_key);

    assert!(
        resp.masked_key.iter().any(|&b| b != 0),
        "masked AES key must not be all-zero",
    );
    assert!(resp.pub_key.is_empty(), "a symmetric key has no public key");
}

#[test]
fn unwrap_key_ecc_p256_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // Import a host-generated P-256 key (PKCS#8 DER) and check the decode +
    // public-key re-derivation path.
    let key = EccPrivateKey::generate(32).expect("generate P-256 key");
    let der = key.to_vec().expect("ECC PKCS#8 DER export");
    let resp = unwrap(&ctx, session.session_id, KEY_CLASS_ECC, &der);

    assert!(
        resp.masked_key.iter().any(|&b| b != 0),
        "masked ECC key must not be all-zero",
    );
    // P-256 wire public key is `x(32) ‖ y(32)` = 64 bytes.
    assert_eq!(
        resp.pub_key.len(),
        64,
        "P-256 recovered public key is x(32) ‖ y(32)",
    );
}

#[test]
fn unwrap_key_hmac_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let hmac_key = [0x37u8; 32];
    let resp = unwrap(&ctx, session.session_id, KEY_CLASS_HMAC_SHA256, &hmac_key);

    // A 32-byte HMAC key decodes to variable-length HMAC-SHA-256; symmetric
    // keys carry no public key.  Exercising the recovered key via `Hmac` to
    // compute a MAC is covered by the HMAC command's own emu tests, which
    // build on this command.
    assert_eq!(
        resp.key_kind, KIND_HMAC_SHA256,
        "recovered kind = VarLenHmacSha256"
    );
    assert!(resp.pub_key.is_empty());
    assert!(
        resp.masked_key.iter().any(|&b| b != 0),
        "masked HMAC key must not be all-zero",
    );
}

#[test]
fn unwrap_key_rejects_invalid_usage_for_class_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // Request `sign`+`verify` for an AES key — AES only permits
    // `encrypt`+`decrypt`, so the device must reject the import.
    let aes_key = [0x42u8; 32];
    let hsm_pub = ctx
        .tbor(&TborGetUnwrappingKeyReq {
            session_id: session.session_id,
        })
        .expect("GetUnwrappingKey")
        .pub_key;
    let wrapped = rsa_aes_wrap(&hsm_pub, &aes_key);
    let req = TborUnwrapKeyReq {
        session_id: session.session_id,
        scope: SCOPE_LOCAL,
        key_class: KEY_CLASS_AES,
        key_usage: KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        oaep_hash_algo: OAEP_SHA256,
        wrapped_blob: wrapped,
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidPermissions);
}
