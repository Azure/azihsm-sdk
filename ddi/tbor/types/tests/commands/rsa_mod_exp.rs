// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `RsaModExp` command.
//!
//! `RsaModExp` performs the RSA private-key primitive `x = y^d mod n`
//! using a caller-held **masked** RSA private key (imported via
//! [`UnwrapKey`](super::unwrap_key) with the RSA / RSA-CRT key class).
//! These tests import a host-generated RSA key on-device (RSA-AES-wrap its
//! DER, unwrap into a masked blob), run the modular exponentiation, and
//! verify the result on the host with `azihsm_crypto` (raw, unpadded RSA)
//! — exercising the full `UnwrapKey`(Rsa) → `RsaModExp` path for both CRT
//! and non-CRT vault forms.
//!
//! The device speaks the PKA-native **little-endian** wire format for the
//! `y` input and `x` output; `azihsm_crypto` (OpenSSL) is big-endian
//! native, so the tests reverse each operand at the boundary.

#![cfg(feature = "emu")]

use azihsm_crypto::Encrypter;
use azihsm_crypto::ExportableKey;
use azihsm_crypto::Key;
use azihsm_crypto::KeyGenerationOp;
use azihsm_crypto::PrivateKey;
use azihsm_crypto::RsaEncryptAlgo;
use azihsm_crypto::RsaPrivateKey;
use azihsm_crypto::RsaPublicKey;
use azihsm_crypto::RsaSignAlgo;
use azihsm_crypto::Verifier;
use azihsm_ddi_tbor_types::TborRsaModExpReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::KEY_CLASS_AES;
use azihsm_ddi_tbor_types::KEY_CLASS_RSA;
use azihsm_ddi_tbor_types::KEY_CLASS_RSA_CRT;
use azihsm_ddi_tbor_types::KEY_USAGE_DECRYPT;
use azihsm_ddi_tbor_types::KEY_USAGE_ENCRYPT;
use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;
use azihsm_ddi_tbor_types::KEY_USAGE_VERIFY;
use azihsm_ddi_tbor_types::RSA_OP_DECRYPT;
use azihsm_ddi_tbor_types::RSA_OP_SIGN;

use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::commands::unwrap_key::unwrap;
use crate::commands::unwrap_key::unwrap_with_usage;
use azihsm_ddi_tbor_test_harness::TestCtx;

/// Reverse `bytes` into a fresh vec (wire-LE ↔ OpenSSL-BE conversion).
fn rev(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().rev().copied().collect()
}

/// A non-palindrome big-endian integer of `modulus_len` bytes that stays
/// below the modulus (leading byte `0x01`, so `m < n`).  The non-symmetry
/// exercises the wire little-endian operand handling.
fn test_integer(modulus_len: usize) -> Vec<u8> {
    let mut m = vec![0x02u8; modulus_len];
    m[0] = 0x01;
    m
}

/// Generate a host RSA private key of `modulus_bytes` (256 / 384 / 512 for
/// RSA-2048 / 3072 / 4096), import it on-device via `UnwrapKey` under the
/// given CRT / non-CRT class, and return `(masked_key, host_public_key,
/// modulus_len)`.
fn import_rsa(
    ctx: &TestCtx,
    session_id: u16,
    modulus_bytes: usize,
    crt: bool,
    usage: u8,
) -> (Vec<u8>, RsaPublicKey, usize) {
    let key = RsaPrivateKey::generate(modulus_bytes).expect("generate host RSA key");
    let modulus_len = key.size();
    let der = key.to_vec().expect("RSA private DER export");
    let class = if crt {
        KEY_CLASS_RSA_CRT
    } else {
        KEY_CLASS_RSA
    };
    // The device grants exactly one usage group; `RsaModExp` Sign needs
    // `sign`, Decrypt needs `decrypt`, so the caller requests the group
    // matching the operation under test.
    let resp = unwrap_with_usage(ctx, session_id, class, usage, &der);
    assert!(
        !resp.pub_key.is_empty(),
        "an imported RSA key returns a re-derived public key",
    );
    let pubkey = key.public_key().expect("derive host public key");
    (resp.masked_key, pubkey, modulus_len)
}

/// Run `RsaModExp` and return the wire-LE `x` result.
fn mod_exp(
    ctx: &TestCtx,
    session_id: u16,
    masked_key: Vec<u8>,
    op_type: u8,
    y_le: Vec<u8>,
) -> Vec<u8> {
    ctx.tbor(&TborRsaModExpReq {
        session_id,
        masked_key,
        op_type,
        y: y_le,
    })
    .expect("RsaModExp")
    .x
}

/// Import an RSA key, produce `s = m^d mod n` via `RsaModExp { Sign }`, and
/// verify on the host that `s^e mod n == m`.
fn sign_roundtrip(ctx: &TestCtx, session_id: u16, modulus_bytes: usize, crt: bool) {
    let (masked_key, pubkey, modulus_len) = import_rsa(
        ctx,
        session_id,
        modulus_bytes,
        crt,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
    );
    let m = test_integer(modulus_len);

    // Device consumes wire-LE `y`, returns wire-LE `x`.
    let x_le = mod_exp(ctx, session_id, masked_key, RSA_OP_SIGN, rev(&m));
    assert_eq!(
        x_le.len(),
        modulus_len,
        "result length equals the modulus length"
    );
    let signature = rev(&x_le);

    let verified = Verifier::verify(&mut RsaSignAlgo::with_no_padding(), &pubkey, &m, &signature)
        .expect("raw RSA verify");
    assert!(
        verified,
        "RsaModExp Sign must produce a signature verifying over the message (crt={crt}, k={modulus_bytes})",
    );
}

/// Import an RSA key, raw-encrypt a message with the host public key, and
/// confirm `RsaModExp { Decrypt }` recovers it (`c^d mod n == m`).
fn decrypt_roundtrip(ctx: &TestCtx, session_id: u16, modulus_bytes: usize, crt: bool) {
    let (masked_key, pubkey, modulus_len) = import_rsa(
        ctx,
        session_id,
        modulus_bytes,
        crt,
        KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
    );
    let m = test_integer(modulus_len);

    // c = m^e mod n (big-endian), then fed to the device as wire-LE `y`.
    let ciphertext = Encrypter::encrypt_vec(&mut RsaEncryptAlgo::with_no_padding(), &pubkey, &m)
        .expect("raw RSA encrypt");
    let x_le = mod_exp(
        ctx,
        session_id,
        masked_key,
        RSA_OP_DECRYPT,
        rev(&ciphertext),
    );
    assert_eq!(
        rev(&x_le),
        m,
        "RsaModExp Decrypt must recover the original message"
    );
}

#[test]
fn rsa_mod_exp_sign_roundtrip_2k_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    sign_roundtrip(&ctx, session.session_id, 256, false);
}

#[test]
fn rsa_mod_exp_sign_roundtrip_3k_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    sign_roundtrip(&ctx, session.session_id, 384, false);
}

#[test]
fn rsa_mod_exp_sign_roundtrip_4k_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    sign_roundtrip(&ctx, session.session_id, 512, false);
}

#[test]
fn rsa_mod_exp_sign_roundtrip_4k_crt_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    sign_roundtrip(&ctx, session.session_id, 512, true);
}

#[test]
fn rsa_mod_exp_decrypt_roundtrip_4k_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    decrypt_roundtrip(&ctx, session.session_id, 512, false);
}

#[test]
fn rsa_mod_exp_sign_roundtrip_2k_crt_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    sign_roundtrip(&ctx, session.session_id, 256, true);
}

#[test]
fn rsa_mod_exp_decrypt_roundtrip_2k_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    decrypt_roundtrip(&ctx, session.session_id, 256, false);
}

#[test]
fn rsa_mod_exp_decrypt_roundtrip_2k_crt_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    decrypt_roundtrip(&ctx, session.session_id, 256, true);
}

#[test]
fn rsa_mod_exp_wrong_y_len_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _pub, modulus_len) = import_rsa(
        &ctx,
        session.session_id,
        256,
        false,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
    );

    // A `y` one byte short of the modulus length is rejected.
    ctx.expect_fw_reject(
        &TborRsaModExpReq {
            session_id: session.session_id,
            masked_key,
            op_type: RSA_OP_SIGN,
            y: vec![0x01u8; modulus_len - 1],
        },
        TborStatus::InvalidArg,
    );
}

#[test]
fn rsa_mod_exp_wrong_key_class_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // A masked AES key is not an RSA private key: `RsaModExp` must reject
    // it as `InvalidKeyType` after unmasking (key-class confusion guard).
    let aes = unwrap(&ctx, session.session_id, KEY_CLASS_AES, &[0x42u8; 32]);
    ctx.expect_fw_reject(
        &TborRsaModExpReq {
            session_id: session.session_id,
            masked_key: aes.masked_key,
            op_type: RSA_OP_SIGN,
            y: vec![0x01u8; 256],
        },
        TborStatus::InvalidKeyType,
    );
}
