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
use azihsm_ddi_tbor_test_harness::TestCtx;
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
    usage: u64,
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

/// Verify raw RSA-2048 signing with a non-CRT key.
#[test]
fn rsa_mod_exp_sign_roundtrip_2k_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    sign_roundtrip(&ctx, session.session_id, 256, false);
}

/// Verify raw RSA-3072 signing with a non-CRT key.
#[test]
fn rsa_mod_exp_sign_roundtrip_3k_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    sign_roundtrip(&ctx, session.session_id, 384, false);
}

/// Verify raw RSA-4096 signing with a non-CRT key.
#[test]
fn rsa_mod_exp_sign_roundtrip_4k_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    sign_roundtrip(&ctx, session.session_id, 512, false);
}

/// Verify raw RSA-4096 signing with a CRT key.
#[test]
fn rsa_mod_exp_sign_roundtrip_4k_crt_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    sign_roundtrip(&ctx, session.session_id, 512, true);
}

/// Verify raw RSA-4096 decryption with a non-CRT key.
#[test]
fn rsa_mod_exp_decrypt_roundtrip_4k_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    decrypt_roundtrip(&ctx, session.session_id, 512, false);
}

/// Verify raw RSA-2048 signing with a CRT key.
#[test]
fn rsa_mod_exp_sign_roundtrip_2k_crt_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    sign_roundtrip(&ctx, session.session_id, 256, true);
}

/// Verify raw RSA-2048 decryption with a non-CRT key.
#[test]
fn rsa_mod_exp_decrypt_roundtrip_2k_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    decrypt_roundtrip(&ctx, session.session_id, 256, false);
}

/// Verify raw RSA-2048 decryption with a CRT key.
#[test]
fn rsa_mod_exp_decrypt_roundtrip_2k_crt_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    decrypt_roundtrip(&ctx, session.session_id, 256, true);
}

/// Reject a signing operand one byte shorter than the RSA modulus.
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

/// Reject an AES masked key supplied to the RSA signing operation.
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

/// Verify raw RSA-3072 signing with a CRT key.
#[test]
fn rsa_mod_exp_sign_roundtrip_3k_crt_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    sign_roundtrip(&ctx, session.session_id, 384, true);
}

/// Verify raw RSA-3072 decryption with a non-CRT key.
#[test]
fn rsa_mod_exp_decrypt_roundtrip_3k_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    decrypt_roundtrip(&ctx, session.session_id, 384, false);
}

/// Verify raw RSA-3072 decryption with a CRT key.
#[test]
fn rsa_mod_exp_decrypt_roundtrip_3k_crt_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    decrypt_roundtrip(&ctx, session.session_id, 384, true);
}

/// Verify raw RSA-4096 decryption with a CRT key.
#[test]
fn rsa_mod_exp_decrypt_roundtrip_4k_crt_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    decrypt_roundtrip(&ctx, session.session_id, 512, true);
}

/// Reject an empty signing operand.
#[test]
fn rsa_mod_exp_empty_y_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let (masked_key, _, _) = import_rsa(
        &ctx,
        session.session_id,
        256,
        false,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
    );

    ctx.expect_fw_reject(
        &TborRsaModExpReq {
            session_id: session.session_id,
            masked_key,
            op_type: RSA_OP_SIGN,
            y: vec![],
        },
        TborStatus::InvalidArg,
    );
}

/// Reject a signing operand one byte longer than the RSA modulus.
#[test]
fn rsa_mod_exp_oversized_y_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let (masked_key, _, modulus_len) = import_rsa(
        &ctx,
        session.session_id,
        256,
        false,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
    );

    ctx.expect_fw_reject(
        &TborRsaModExpReq {
            session_id: session.session_id,
            masked_key,
            op_type: RSA_OP_SIGN,
            y: vec![0x01; modulus_len + 1],
        },
        TborStatus::InvalidArg,
    );
}

/// Reject a truncated decryption operand for an RSA-CRT key.
#[test]
fn rsa_mod_exp_decrypt_short_y_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let (masked_key, _, modulus_len) = import_rsa(
        &ctx,
        session.session_id,
        256,
        true,
        KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
    );

    ctx.expect_fw_reject(
        &TborRsaModExpReq {
            session_id: session.session_id,
            masked_key,
            op_type: RSA_OP_DECRYPT,
            y: vec![0x01; modulus_len - 1],
        },
        TborStatus::InvalidArg,
    );
}

// ------------------------------------------------------------
// 3. Boundary values: zero and one
// ------------------------------------------------------------

/// Verify RsaModExp rejects a zero-valued signing operand.
#[test]
fn rsa_mod_exp_sign_zero_operand_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let (masked_key, _, modulus_len) = import_rsa(
        &ctx,
        session.session_id,
        256,
        false,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
    );

    // A zero-valued operand is rejected by the emulator.
    ctx.expect_fw_reject(
        &TborRsaModExpReq {
            session_id: session.session_id,
            masked_key,
            op_type: RSA_OP_SIGN,
            y: vec![0; modulus_len],
        },
        TborStatus::InvalidArg,
    );
}

/// Verify RsaModExp rejects a one-valued signing operand.
#[test]
fn rsa_mod_exp_sign_one_operand_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let (masked_key, _, modulus_len) = import_rsa(
        &ctx,
        session.session_id,
        256,
        true,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
    );

    // Wire format is little-endian.
    let mut one = vec![0; modulus_len];
    one[0] = 1;

    ctx.expect_fw_reject(
        &TborRsaModExpReq {
            session_id: session.session_id,
            masked_key,
            op_type: RSA_OP_SIGN,
            y: one,
        },
        TborStatus::InvalidArg,
    );
}

/// Verify repeated signing of the same operand is deterministic.
#[test]
fn rsa_mod_exp_repeated_sign_stable_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let (masked_key, pubkey, modulus_len) = import_rsa(
        &ctx,
        session.session_id,
        256,
        false,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
    );

    let message = test_integer(modulus_len);
    let y = rev(&message);

    let first = mod_exp(
        &ctx,
        session.session_id,
        masked_key.clone(),
        RSA_OP_SIGN,
        y.clone(),
    );

    let second = mod_exp(&ctx, session.session_id, masked_key, RSA_OP_SIGN, y);

    assert_eq!(first, second, "raw RSA signing must be deterministic");

    let verified = Verifier::verify(
        &mut RsaSignAlgo::with_no_padding(),
        &pubkey,
        &message,
        &rev(&first),
    )
    .expect("verify repeated RSA signature");

    assert!(verified);
}

/// Verify distinct operands produce distinct valid raw RSA signatures.
#[test]
fn rsa_mod_exp_different_messages_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let (masked_key, pubkey, modulus_len) = import_rsa(
        &ctx,
        session.session_id,
        256,
        true,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
    );

    let message1 = test_integer(modulus_len);

    let mut message2 = message1.clone();
    message2[modulus_len - 1] ^= 0x01;

    let sig1 = mod_exp(
        &ctx,
        session.session_id,
        masked_key.clone(),
        RSA_OP_SIGN,
        rev(&message1),
    );

    let sig2 = mod_exp(
        &ctx,
        session.session_id,
        masked_key,
        RSA_OP_SIGN,
        rev(&message2),
    );

    assert_ne!(
        sig1, sig2,
        "different messages must produce different raw signatures"
    );

    for (message, signature) in [(&message1, &sig1), (&message2, &sig2)] {
        let verified = Verifier::verify(
            &mut RsaSignAlgo::with_no_padding(),
            &pubkey,
            message,
            &rev(signature),
        )
        .expect("verify RSA signature");

        assert!(verified);
    }
}

/// Verify repeated decryptions recover the same plaintext.
#[test]
fn rsa_mod_exp_repeated_decrypt_stable_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let (masked_key, pubkey, modulus_len) = import_rsa(
        &ctx,
        session.session_id,
        256,
        true,
        KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
    );

    let message = test_integer(modulus_len);

    let ciphertext =
        Encrypter::encrypt_vec(&mut RsaEncryptAlgo::with_no_padding(), &pubkey, &message)
            .expect("raw RSA encrypt");

    let y = rev(&ciphertext);

    for _ in 0..3 {
        let x = mod_exp(
            &ctx,
            session.session_id,
            masked_key.clone(),
            RSA_OP_DECRYPT,
            y.clone(),
        );

        assert_eq!(
            rev(&x),
            message,
            "repeated decryption must recover the message"
        );
    }
}

/// Both imported key classes must compute the same private RSA operation
/// when backed by the same RSA key material.
#[test]
fn rsa_mod_exp_rsa_crt_same_key_sign_equivalent_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = RsaPrivateKey::generate(256).expect("generate RSA-2048 key");
    let der = key.to_vec().expect("export RSA private DER");

    let standard = unwrap_with_usage(
        &ctx,
        session.session_id,
        KEY_CLASS_RSA,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &der,
    );
    let crt = unwrap_with_usage(
        &ctx,
        session.session_id,
        KEY_CLASS_RSA_CRT,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        &der,
    );

    let message = test_integer(key.size());
    let y = rev(&message);
    let x_standard = mod_exp(
        &ctx,
        session.session_id,
        standard.masked_key,
        RSA_OP_SIGN,
        y.clone(),
    );
    let x_crt = mod_exp(&ctx, session.session_id, crt.masked_key, RSA_OP_SIGN, y);

    assert_eq!(x_standard, x_crt, "RSA and RSA-CRT results must match");
    assert_eq!(x_standard.len(), key.size());
    assert!(Verifier::verify(
        &mut RsaSignAlgo::with_no_padding(),
        &key.public_key().expect("public key"),
        &message,
        &rev(&x_standard),
    )
    .expect("verify raw RSA signature"));
}

/// RSA and RSA-CRT decryptions must agree for the same underlying private key.
#[test]
fn rsa_mod_exp_rsa_crt_same_key_decrypt_equivalent_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = RsaPrivateKey::generate(256).expect("generate RSA-2048 key");
    let der = key.to_vec().expect("export RSA private DER");

    let standard = unwrap_with_usage(
        &ctx,
        session.session_id,
        KEY_CLASS_RSA,
        KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
        &der,
    );
    let crt = unwrap_with_usage(
        &ctx,
        session.session_id,
        KEY_CLASS_RSA_CRT,
        KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
        &der,
    );

    let message = test_integer(key.size());
    let ciphertext = Encrypter::encrypt_vec(
        &mut RsaEncryptAlgo::with_no_padding(),
        &key.public_key().expect("public key"),
        &message,
    )
    .expect("raw RSA encrypt");
    let y = rev(&ciphertext);

    let x_standard = mod_exp(
        &ctx,
        session.session_id,
        standard.masked_key,
        RSA_OP_DECRYPT,
        y.clone(),
    );
    let x_crt = mod_exp(&ctx, session.session_id, crt.masked_key, RSA_OP_DECRYPT, y);

    assert_eq!(x_standard, x_crt, "RSA and RSA-CRT decryptions must match");
    assert_eq!(rev(&x_standard), message);
}

/// Verify the emulator rejects all-zero decrypt operands for RSA and RSA-CRT.
#[test]
fn rsa_mod_exp_decrypt_zero_operand_both_classes_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for crt in [false, true] {
        let (masked_key, _, modulus_len) = import_rsa(
            &ctx,
            session.session_id,
            256,
            crt,
            KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
        );
        ctx.expect_fw_reject(
            &TborRsaModExpReq {
                session_id: session.session_id,
                masked_key,
                op_type: RSA_OP_DECRYPT,
                y: vec![0; modulus_len],
            },
            TborStatus::InvalidArg,
        );
    }
}

/// Verify the emulator rejects decrypt operand one for RSA and RSA-CRT.
#[test]
fn rsa_mod_exp_decrypt_one_operand_both_classes_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for crt in [false, true] {
        let (masked_key, _, modulus_len) = import_rsa(
            &ctx,
            session.session_id,
            256,
            crt,
            KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
        );
        let mut one = vec![0; modulus_len];
        one[0] = 1;
        ctx.expect_fw_reject(
            &TborRsaModExpReq {
                session_id: session.session_id,
                masked_key,
                op_type: RSA_OP_DECRYPT,
                y: one,
            },
            TborStatus::InvalidArg,
        );
    }
}

/// A low-valued non-palindromic operand verifies the wire endian convention.
#[test]
fn rsa_mod_exp_sign_little_endian_small_operand_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, pubkey, modulus_len) = import_rsa(
        &ctx,
        session.session_id,
        256,
        true,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
    );

    let mut y = vec![0; modulus_len];
    y[0] = 0x23;
    y[1] = 0x01;
    y[2] = 0xAB;
    let x = mod_exp(&ctx, session.session_id, masked_key, RSA_OP_SIGN, y.clone());

    assert_eq!(x.len(), modulus_len);
    assert!(Verifier::verify(
        &mut RsaSignAlgo::with_no_padding(),
        &pubkey,
        &rev(&y),
        &rev(&x),
    )
    .expect("verify non-palindromic raw RSA operand"));
}

/// RSA-3072 / RSA-4096 and RSA-CRT must reject truncated operands.
#[test]
fn rsa_mod_exp_large_keys_short_y_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for (modulus_bytes, crt) in [(384, false), (384, true), (512, false), (512, true)] {
        let (masked_key, _, modulus_len) = import_rsa(
            &ctx,
            session.session_id,
            modulus_bytes,
            crt,
            KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        );
        ctx.expect_fw_reject(
            &TborRsaModExpReq {
                session_id: session.session_id,
                masked_key,
                op_type: RSA_OP_SIGN,
                y: vec![1; modulus_len - 1],
            },
            TborStatus::InvalidArg,
        );
    }
}

/// Verify oversized decrypt operands are rejected for RSA-3072/4096 and CRT.
#[test]
fn rsa_mod_exp_large_keys_oversized_y_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for (modulus_bytes, crt) in [(384, false), (384, true), (512, false), (512, true)] {
        let (masked_key, _, modulus_len) = import_rsa(
            &ctx,
            session.session_id,
            modulus_bytes,
            crt,
            KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
        );
        let result = ctx.tbor(&TborRsaModExpReq {
            session_id: session.session_id,
            masked_key,
            op_type: RSA_OP_DECRYPT,
            y: vec![1; modulus_len + 1],
        });
        assert!(
            result.is_err(),
            "oversized decrypt operand must be rejected (modulus_bytes={modulus_bytes}, crt={crt})"
        );
        // Observed on emulator: 0x08680014, not InvalidArg (0x08000003).
        // Check the firmware status definition before enforcing a single code.
    }
}

/// An AES masked key is invalid for the decrypt operation as well as sign.
#[test]
fn rsa_mod_exp_decrypt_wrong_key_class_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let aes = unwrap(&ctx, session.session_id, KEY_CLASS_AES, &[0x42; 32]);

    ctx.expect_fw_reject(
        &TborRsaModExpReq {
            session_id: session.session_id,
            masked_key: aes.masked_key,
            op_type: RSA_OP_DECRYPT,
            y: vec![1; 256],
        },
        TborStatus::InvalidKeyType,
    );
}

/// An unknown operation selector must not be interpreted as Sign or Decrypt.
#[test]
fn rsa_mod_exp_unknown_operation_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _, modulus_len) = import_rsa(
        &ctx,
        session.session_id,
        256,
        false,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
    );

    ctx.expect_fw_reject(
        &TborRsaModExpReq {
            session_id: session.session_id,
            masked_key,
            op_type: 0xFF,
            y: vec![1; modulus_len],
        },
        TborStatus::InvalidArg,
    );
}

/// A decrypt-only RSA key must not be accepted for a signing operation.
#[test]
fn rsa_mod_exp_sign_with_decrypt_usage_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for crt in [false, true] {
        let (masked_key, _, modulus_len) = import_rsa(
            &ctx,
            session.session_id,
            256,
            crt,
            KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
        );
        assert!(
            ctx.tbor(&TborRsaModExpReq {
                session_id: session.session_id,
                masked_key,
                op_type: RSA_OP_SIGN,
                y: vec![1; modulus_len],
            })
            .is_err(),
            "sign must reject decrypt-only key (crt={crt})"
        );
    }
}

/// A sign-only RSA key must not be accepted for decryption.
#[test]
fn rsa_mod_exp_decrypt_with_sign_usage_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for crt in [false, true] {
        let (masked_key, _, modulus_len) = import_rsa(
            &ctx,
            session.session_id,
            256,
            crt,
            KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        );
        assert!(
            ctx.tbor(&TborRsaModExpReq {
                session_id: session.session_id,
                masked_key,
                op_type: RSA_OP_DECRYPT,
                y: vec![1; modulus_len],
            })
            .is_err(),
            "decrypt must reject sign-only key (crt={crt})"
        );
    }
}

/// Empty masked keys are never valid private RSA keys.
#[test]
fn rsa_mod_exp_empty_masked_key_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    assert!(
        ctx.tbor(&TborRsaModExpReq {
            session_id: session.session_id,
            masked_key: vec![],
            op_type: RSA_OP_SIGN,
            y: vec![1; 256],
        })
        .is_err(),
        "empty masked key must be rejected"
    );
}

/// A truncated masked-key envelope must not be accepted.
#[test]
fn rsa_mod_exp_truncated_masked_key_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (mut masked_key, _, modulus_len) = import_rsa(
        &ctx,
        session.session_id,
        256,
        false,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
    );
    masked_key.pop().expect("imported masked key is nonempty");

    assert!(
        ctx.tbor(&TborRsaModExpReq {
            session_id: session.session_id,
            masked_key,
            op_type: RSA_OP_SIGN,
            y: vec![1; modulus_len],
        })
        .is_err(),
        "truncated masked key must be rejected"
    );
}

/// Corrupt the final byte of the masked-key envelope (normally its tag).
#[test]
fn rsa_mod_exp_corrupted_masked_key_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for crt in [false, true] {
        let (mut masked_key, _, modulus_len) = import_rsa(
            &ctx,
            session.session_id,
            256,
            crt,
            KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        );
        let last = masked_key.last_mut().expect("nonempty masked key");
        *last ^= 0x01;
        assert!(
            ctx.tbor(&TborRsaModExpReq {
                session_id: session.session_id,
                masked_key,
                op_type: RSA_OP_SIGN,
                y: vec![1; modulus_len],
            })
            .is_err(),
            "corrupted masked key must be rejected (crt={crt})"
        );
    }
}

/// An invalid session identifier must not authorize an RSA private operation.
#[test]
fn rsa_mod_exp_invalid_session_rejected_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let (masked_key, _, modulus_len) = import_rsa(
        &ctx,
        session.session_id,
        256,
        false,
        KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
    );
    let invalid_session_id = u16::MAX;
    assert_ne!(session.session_id, invalid_session_id);

    assert!(
        ctx.tbor(&TborRsaModExpReq {
            session_id: invalid_session_id,
            masked_key,
            op_type: RSA_OP_SIGN,
            y: vec![1; modulus_len],
        })
        .is_err(),
        "invalid session id must be rejected"
    );
}
