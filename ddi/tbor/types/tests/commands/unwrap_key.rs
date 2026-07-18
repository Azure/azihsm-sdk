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
//! * HMAC key — the recovered key's kind is `_HmacSha256` and it carries
//!   no public key.  (Using the recovered key via `Hmac` to compute a MAC
//!   is exercised by the HMAC command's own emu tests, which build on
//!   this command.)

#![cfg(feature = "emu")]

use azihsm_crypto::AesKey;
use azihsm_crypto::AesKeyWrapPadAlgo;
use azihsm_crypto::Encrypter;
use azihsm_crypto::HashAlgo;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::RsaEncryptAlgo;
use azihsm_crypto::RsaPublicKey;
use azihsm_ddi_tbor_types::TborGetUnwrappingKeyReq;
use azihsm_ddi_tbor_types::TborUnwrapKeyReq;
use azihsm_ddi_tbor_types::TborUnwrapKeyResp;
use azihsm_ddi_tbor_types::KEY_CLASS_AES;
use azihsm_ddi_tbor_types::KEY_CLASS_HMAC;

use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::harness::TestCtx;

/// OAEP hash discriminant (SHA-256) used for wrapping.
const OAEP_SHA256: u8 = 1;
/// `KeyScope::Local` discriminant — masks the recovered key under the
/// partition-local masking key.
const SCOPE_LOCAL: u8 = 0b011;
/// `HsmVaultKeyKind::_HmacSha256` discriminant.
const KIND_HMAC_SHA256: u8 = 28;

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

/// Fetch the unwrapping public key, wrap `key` for `class`, and unwrap it
/// on-device under the `Local` scope.
fn unwrap(ctx: &TestCtx, session_id: u16, class: u8, key: &[u8]) -> TborUnwrapKeyResp {
    let hsm_pub = ctx
        .tbor(&TborGetUnwrappingKeyReq { session_id })
        .expect("GetUnwrappingKey")
        .pub_key;
    let wrapped = rsa_aes_wrap(&hsm_pub, key);
    ctx.tbor(&TborUnwrapKeyReq {
        session_id,
        scope: SCOPE_LOCAL,
        key_class: class,
        oaep_hash: OAEP_SHA256,
        wrapped_blob: wrapped,
    })
    .expect("UnwrapKey")
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
fn unwrap_key_hmac_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let hmac_key = [0x37u8; 32];
    let resp = unwrap(&ctx, session.session_id, KEY_CLASS_HMAC, &hmac_key);

    // A 32-byte HMAC key decodes to HMAC-SHA-256; symmetric keys carry no
    // public key.  Exercising the recovered key via `Hmac` to compute a
    // MAC is covered by the HMAC command's own emu tests, which build on
    // this command.
    assert_eq!(
        resp.key_kind, KIND_HMAC_SHA256,
        "recovered kind = HMAC-SHA256"
    );
    assert!(resp.pub_key.is_empty());
    assert!(
        resp.masked_key.iter().any(|&b| b != 0),
        "masked HMAC key must not be all-zero",
    );
}
