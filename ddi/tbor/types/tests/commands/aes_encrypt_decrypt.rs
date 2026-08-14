// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `AesEncryptDecrypt` command.
//!
//! `AesEncryptDecrypt` AES-CBC transforms a host message using a
//! caller-held **masked** AES key (from `AesGenerateKey` or imported via
//! `UnwrapKey`). The device unmasks the key on-device, runs the
//! transform, and returns the result plus the updated chaining IV.
//!
//! Coverage:
//! * Encrypt → decrypt round-trip for AES-128/192/256.
//! * Returned CBC chaining IV for AES-128/192/256.
//! * Single-block round-trip for AES-128/192/256.
//! * Deterministic output for identical inputs for AES-128/192/256.
//! * Different IVs produce different ciphertext for AES-128/192/256.
//! * Different keys produce different ciphertext for AES-128/192/256.
//! * Wrong IVs do not recover the original plaintext for AES-128/192/256.
//! * Returned IV supports continued encryption/decryption for AES-128/192/256.
//! * Tampered masked keys are rejected for AES-128/192/256.
//! * Imported AES-128/192/256 keys encrypt/decrypt successfully.
//! * Non-block-aligned encrypt/decrypt messages are rejected.

#![cfg(feature = "emu")]

use std::fs::File;
use std::io::Read;

use azihsm_ddi_tbor_types::TborAesEncryptDecryptReq;
use azihsm_ddi_tbor_types::TborAesEncryptDecryptResp;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::AES_KEY_SIZE_128;
use azihsm_ddi_tbor_types::AES_KEY_SIZE_192;
use azihsm_ddi_tbor_types::AES_KEY_SIZE_256;
use azihsm_ddi_tbor_types::AES_OP_DECRYPT;
use azihsm_ddi_tbor_types::AES_OP_ENCRYPT;
use azihsm_ddi_tbor_types::KEY_CLASS_AES;

use crate::commands::aes_generate_key::generate_key;
use crate::commands::aes_generate_key::SCOPE_LOCAL;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::commands::unwrap_key::unwrap;
use crate::harness::TestCtx;

/// AES block / IV length.
const IV_LEN: usize = azihsm_ddi_tbor_types::AES_IV_LEN;

/// Generates cryptographically random bytes from the operating system for test inputs.
fn os_random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];

    File::open("/dev/urandom")
        .expect("open /dev/urandom")
        .read_exact(&mut bytes)
        .expect("read random bytes from /dev/urandom");

    bytes
}

/// Generates a fresh AES-CBC IV for a test operation.
fn random_iv() -> [u8; IV_LEN] {
    os_random_bytes::<IV_LEN>()
}

/// Performs an AES-CBC transform using the supplied masked key, operation, message, and IV.
fn aes_op(
    ctx: &TestCtx,
    session_id: u16,
    masked_key: &[u8],
    op: u8,
    msg: &[u8],
    iv: &[u8],
) -> TborAesEncryptDecryptResp {
    let req = TborAesEncryptDecryptReq {
        session_id,
        masked_key: masked_key.to_vec(),
        op,
        msg: msg.to_vec(),
        iv: iv.try_into().expect("IV must be 16 bytes"),
    };

    ctx.tbor(&req).expect("AesEncryptDecrypt")
}

/// Verifies the returned encryption IV equals the final ciphertext block for a key size.
fn check_chaining_iv(key_size: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);

    let msg = [0x5Au8; 48];
    let iv = random_iv();

    let enc = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);

    assert_eq!(
        enc.iv,
        enc.msg[enc.msg.len() - IV_LEN..],
        "chaining IV must equal the last ciphertext block",
    );
}

/// Verifies a single AES block encrypts and decrypts successfully for a key size.
fn check_single_block_roundtrip(key_size: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);

    let msg = [0xA5u8; IV_LEN];
    let iv = random_iv();

    let enc = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);

    assert_eq!(enc.msg.len(), IV_LEN);
    assert_ne!(enc.msg, msg);
    assert_eq!(
        enc.iv,
        enc.msg.as_slice(),
        "single-block ciphertext must also be the chaining IV",
    );

    let dec = aes_op(
        &ctx,
        session.session_id,
        &key,
        AES_OP_DECRYPT,
        &enc.msg,
        &iv,
    );

    assert_eq!(dec.msg, msg);
}

/// Verifies identical key, IV, and plaintext produce identical ciphertext for a key size.
fn check_deterministic_output(key_size: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);

    let msg = [0x3Cu8; 32];
    let iv = random_iv();

    let enc_a = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);

    let enc_b = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);

    assert_eq!(
        enc_a.msg, enc_b.msg,
        "identical inputs must produce identical ciphertext",
    );

    assert_eq!(
        enc_a.iv, enc_b.iv,
        "identical inputs must produce identical chaining IVs",
    );
}

/// Verifies changing the IV changes the ciphertext for a key size.
fn check_different_iv_changes_ciphertext(key_size: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);

    let msg = [0x5Au8; 32];
    let iv_a = random_iv();
    let mut iv_b = random_iv();

    // Guarantee distinct IVs even in the extremely unlikely event of a collision.
    if iv_a == iv_b {
        iv_b[0] ^= 0x01;
    }

    let enc_a = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv_a);

    let enc_b = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv_b);

    assert_ne!(
        enc_a.msg, enc_b.msg,
        "changing the IV must change the ciphertext",
    );
}

/// Verifies independently generated keys produce different ciphertext for a key size.
fn check_different_keys_change_ciphertext(key_size: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let key_a = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);
    let key_b = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);

    let msg = [0x5Au8; 32];
    let iv = random_iv();

    let enc_a = aes_op(&ctx, session.session_id, &key_a, AES_OP_ENCRYPT, &msg, &iv);

    let enc_b = aes_op(&ctx, session.session_id, &key_b, AES_OP_ENCRYPT, &msg, &iv);

    assert_ne!(
        enc_a.msg, enc_b.msg,
        "different AES keys must produce different ciphertext",
    );
}

/// Verifies decrypting with the wrong IV does not recover the original plaintext.
fn check_wrong_iv_changes_plaintext(key_size: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);

    let msg = [0x6Au8; 32];
    let iv = random_iv();
    let mut wrong_iv = random_iv();

    // Guarantee the wrong IV differs from the encryption IV.
    if iv == wrong_iv {
        wrong_iv[0] ^= 0x01;
    }

    let enc = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);

    let dec = aes_op(
        &ctx,
        session.session_id,
        &key,
        AES_OP_DECRYPT,
        &enc.msg,
        &wrong_iv,
    );

    assert_ne!(
        dec.msg, msg,
        "decrypting with the wrong IV must not recover the original plaintext",
    );
}

/// Verifies the returned IV continues AES-CBC encryption correctly for a key size.
fn check_continued_encryption(key_size: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);

    let first = [0x11u8; IV_LEN];
    let second = [0x22u8; IV_LEN];
    let iv = random_iv();

    let mut combined = Vec::new();
    combined.extend_from_slice(&first);
    combined.extend_from_slice(&second);

    let one_shot = aes_op(
        &ctx,
        session.session_id,
        &key,
        AES_OP_ENCRYPT,
        &combined,
        &iv,
    );

    let first_enc = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &first, &iv);

    let second_enc = aes_op(
        &ctx,
        session.session_id,
        &key,
        AES_OP_ENCRYPT,
        &second,
        &first_enc.iv,
    );

    let mut split_ciphertext = Vec::new();
    split_ciphertext.extend_from_slice(&first_enc.msg);
    split_ciphertext.extend_from_slice(&second_enc.msg);

    assert_eq!(
        split_ciphertext, one_shot.msg,
        "split CBC encryption must match one-shot encryption",
    );

    assert_eq!(
        second_enc.iv, one_shot.iv,
        "final chaining IV must match one-shot encryption",
    );
}

/// Verifies the returned IV continues AES-CBC decryption correctly for a key size.
fn check_continued_decryption(key_size: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);

    let msg = [0x6Bu8; 32];
    let iv = random_iv();

    let enc = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);

    let first_ciphertext = &enc.msg[..IV_LEN];
    let second_ciphertext = &enc.msg[IV_LEN..];

    let first_dec = aes_op(
        &ctx,
        session.session_id,
        &key,
        AES_OP_DECRYPT,
        first_ciphertext,
        &iv,
    );

    let second_dec = aes_op(
        &ctx,
        session.session_id,
        &key,
        AES_OP_DECRYPT,
        second_ciphertext,
        &first_dec.iv,
    );

    let mut recovered = Vec::new();
    recovered.extend_from_slice(&first_dec.msg);
    recovered.extend_from_slice(&second_dec.msg);

    assert_eq!(
        recovered, msg,
        "split CBC decryption must recover the original plaintext",
    );

    assert_eq!(
        first_dec.iv, first_ciphertext,
        "first decrypt IV must equal the ciphertext block just consumed",
    );

    assert_eq!(
        second_dec.iv, second_ciphertext,
        "final decrypt IV must equal the final ciphertext block",
    );
}

/// Verifies tampering with a masked key causes its authentication check to fail.
fn check_tampered_key_rejected(key_size: u8) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let mut key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, key_size);
    let iv = random_iv();

    let last = key.len() - 1;
    key[last] ^= 0x01;

    let req = TborAesEncryptDecryptReq {
        session_id: session.session_id,
        masked_key: key,
        op: AES_OP_ENCRYPT,
        msg: vec![0u8; IV_LEN],
        iv,
    };

    ctx.expect_fw_reject(&req, TborStatus::AesGcmDecryptTagDoesNotMatch);
}

/// Verifies an imported AES key encrypts and decrypts successfully.
fn check_unwrapped_key_roundtrip(aes_key: &[u8]) {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let masked = unwrap(&ctx, session.session_id, KEY_CLASS_AES, aes_key).masked_key;

    let msg = [0x37u8; IV_LEN];
    let iv = random_iv();

    let enc = aes_op(&ctx, session.session_id, &masked, AES_OP_ENCRYPT, &msg, &iv);

    let dec = aes_op(
        &ctx,
        session.session_id,
        &masked,
        AES_OP_DECRYPT,
        &enc.msg,
        &iv,
    );

    assert_eq!(
        dec.msg, msg,
        "unwrapped AES key must encrypt/decrypt successfully",
    );
}

/// Verifies AES-CBC encrypt/decrypt round-trips for AES-128, AES-192, and AES-256 keys.
#[test]
fn aes_encrypt_decrypt_roundtrip_all_sizes() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let msg = [0xA5u8; 32];
    let iv = random_iv();

    for size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
        let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, size);

        let enc = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);

        assert_eq!(
            enc.msg.len(),
            msg.len(),
            "ciphertext length must match plaintext length",
        );

        assert_ne!(enc.msg, msg, "ciphertext must differ from plaintext");

        let dec = aes_op(
            &ctx,
            session.session_id,
            &key,
            AES_OP_DECRYPT,
            &enc.msg,
            &iv,
        );

        assert_eq!(dec.msg, msg, "decrypt must recover the plaintext");
    }
}

/// Verifies AES-128 encryption returns the final ciphertext block as the chaining IV.
#[test]
fn aes_encrypt_decrypt_chaining_iv_128() {
    check_chaining_iv(AES_KEY_SIZE_128);
}

/// Verifies AES-192 encryption returns the final ciphertext block as the chaining IV.
#[test]
fn aes_encrypt_decrypt_chaining_iv_192() {
    check_chaining_iv(AES_KEY_SIZE_192);
}

/// Verifies AES-256 encryption returns the final ciphertext block as the chaining IV.
#[test]
fn aes_encrypt_decrypt_chaining_iv_256() {
    check_chaining_iv(AES_KEY_SIZE_256);
}

/// Verifies AES-128 single-block encryption and decryption round-trip successfully.
#[test]
fn aes_encrypt_decrypt_single_block_roundtrip_128() {
    check_single_block_roundtrip(AES_KEY_SIZE_128);
}

/// Verifies AES-192 single-block encryption and decryption round-trip successfully.
#[test]
fn aes_encrypt_decrypt_single_block_roundtrip_192() {
    check_single_block_roundtrip(AES_KEY_SIZE_192);
}

/// Verifies AES-256 single-block encryption and decryption round-trip successfully.
#[test]
fn aes_encrypt_decrypt_single_block_roundtrip_256() {
    check_single_block_roundtrip(AES_KEY_SIZE_256);
}

/// Verifies identical AES-128 inputs produce identical AES-CBC output.
#[test]
fn aes_encrypt_decrypt_same_inputs_are_deterministic_128() {
    check_deterministic_output(AES_KEY_SIZE_128);
}

/// Verifies identical AES-192 inputs produce identical AES-CBC output.
#[test]
fn aes_encrypt_decrypt_same_inputs_are_deterministic_192() {
    check_deterministic_output(AES_KEY_SIZE_192);
}

/// Verifies identical AES-256 inputs produce identical AES-CBC output.
#[test]
fn aes_encrypt_decrypt_same_inputs_are_deterministic_256() {
    check_deterministic_output(AES_KEY_SIZE_256);
}

/// Verifies changing the IV changes AES-128 ciphertext.
#[test]
fn aes_encrypt_decrypt_different_iv_changes_ciphertext_128() {
    check_different_iv_changes_ciphertext(AES_KEY_SIZE_128);
}

/// Verifies changing the IV changes AES-192 ciphertext.
#[test]
fn aes_encrypt_decrypt_different_iv_changes_ciphertext_192() {
    check_different_iv_changes_ciphertext(AES_KEY_SIZE_192);
}

/// Verifies changing the IV changes AES-256 ciphertext.
#[test]
fn aes_encrypt_decrypt_different_iv_changes_ciphertext_256() {
    check_different_iv_changes_ciphertext(AES_KEY_SIZE_256);
}

/// Verifies different AES-128 keys produce different ciphertext.
#[test]
fn aes_encrypt_decrypt_different_keys_change_ciphertext_128() {
    check_different_keys_change_ciphertext(AES_KEY_SIZE_128);
}

/// Verifies different AES-192 keys produce different ciphertext.
#[test]
fn aes_encrypt_decrypt_different_keys_change_ciphertext_192() {
    check_different_keys_change_ciphertext(AES_KEY_SIZE_192);
}

/// Verifies different AES-256 keys produce different ciphertext.
#[test]
fn aes_encrypt_decrypt_different_keys_change_ciphertext_256() {
    check_different_keys_change_ciphertext(AES_KEY_SIZE_256);
}

/// Verifies decrypting AES-128 ciphertext with the wrong IV does not recover the plaintext.
#[test]
fn aes_encrypt_decrypt_wrong_iv_changes_plaintext_128() {
    check_wrong_iv_changes_plaintext(AES_KEY_SIZE_128);
}

/// Verifies decrypting AES-192 ciphertext with the wrong IV does not recover the plaintext.
#[test]
fn aes_encrypt_decrypt_wrong_iv_changes_plaintext_192() {
    check_wrong_iv_changes_plaintext(AES_KEY_SIZE_192);
}

/// Verifies decrypting AES-256 ciphertext with the wrong IV does not recover the plaintext.
#[test]
fn aes_encrypt_decrypt_wrong_iv_changes_plaintext_256() {
    check_wrong_iv_changes_plaintext(AES_KEY_SIZE_256);
}

/// Verifies the returned IV continues AES-128 CBC encryption correctly.
#[test]
fn aes_encrypt_decrypt_returned_iv_supports_continued_encryption_128() {
    check_continued_encryption(AES_KEY_SIZE_128);
}

/// Verifies the returned IV continues AES-192 CBC encryption correctly.
#[test]
fn aes_encrypt_decrypt_returned_iv_supports_continued_encryption_192() {
    check_continued_encryption(AES_KEY_SIZE_192);
}

/// Verifies the returned IV continues AES-256 CBC encryption correctly.
#[test]
fn aes_encrypt_decrypt_returned_iv_supports_continued_encryption_256() {
    check_continued_encryption(AES_KEY_SIZE_256);
}

/// Verifies the returned IV continues AES-128 CBC decryption correctly.
#[test]
fn aes_encrypt_decrypt_returned_iv_supports_continued_decryption_128() {
    check_continued_decryption(AES_KEY_SIZE_128);
}

/// Verifies the returned IV continues AES-192 CBC decryption correctly.
#[test]
fn aes_encrypt_decrypt_returned_iv_supports_continued_decryption_192() {
    check_continued_decryption(AES_KEY_SIZE_192);
}

/// Verifies the returned IV continues AES-256 CBC decryption correctly.
#[test]
fn aes_encrypt_decrypt_returned_iv_supports_continued_decryption_256() {
    check_continued_decryption(AES_KEY_SIZE_256);
}

/// Verifies a tampered AES-128 masked key is rejected.
#[test]
fn aes_encrypt_decrypt_rejects_tampered_key_128() {
    check_tampered_key_rejected(AES_KEY_SIZE_128);
}

/// Verifies a tampered AES-192 masked key is rejected.
#[test]
fn aes_encrypt_decrypt_rejects_tampered_key_192() {
    check_tampered_key_rejected(AES_KEY_SIZE_192);
}

/// Verifies a tampered AES-256 masked key is rejected.
#[test]
fn aes_encrypt_decrypt_rejects_tampered_key_256() {
    check_tampered_key_rejected(AES_KEY_SIZE_256);
}

/// Verifies an imported AES-128 key encrypts and decrypts successfully.
#[test]
fn aes_encrypt_decrypt_unwrapped_key_roundtrip_128() {
    let aes_key = os_random_bytes::<16>();
    check_unwrapped_key_roundtrip(&aes_key);
}

/// Verifies an imported AES-192 key encrypts and decrypts successfully.
#[test]
fn aes_encrypt_decrypt_unwrapped_key_roundtrip_192() {
    let aes_key = os_random_bytes::<24>();
    check_unwrapped_key_roundtrip(&aes_key);
}

/// Verifies an imported AES-256 key encrypts and decrypts successfully.
#[test]
fn aes_encrypt_decrypt_unwrapped_key_roundtrip_256() {
    let aes_key = os_random_bytes::<32>();
    check_unwrapped_key_roundtrip(&aes_key);
}

/// Verifies encryption rejects plaintext that is not an integral number of AES blocks.
#[test]
fn aes_encrypt_decrypt_rejects_bad_msg_len() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, AES_KEY_SIZE_256);
    let iv = random_iv();

    let req = TborAesEncryptDecryptReq {
        session_id: session.session_id,
        masked_key: key,
        op: AES_OP_ENCRYPT,
        msg: vec![0u8; 20],
        iv,
    };

    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

/// Verifies decryption rejects ciphertext that is not an integral number of AES blocks.
#[test]
fn aes_encrypt_decrypt_rejects_bad_decrypt_msg_len() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, AES_KEY_SIZE_256);
    let iv = random_iv();

    let req = TborAesEncryptDecryptReq {
        session_id: session.session_id,
        masked_key: key,
        op: AES_OP_DECRYPT,
        msg: vec![0u8; 31],
        iv,
    };

    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}
