// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `AesEncryptDecrypt` command.
//!
//! `AesEncryptDecrypt` AES-CBC transforms a host message using a
//! caller-held **masked** AES key (from `AesGenerateKey` or imported via
//! `UnwrapKey`).  The device unmasks the key on-device, runs the
//! transform, and returns the result plus the updated chaining IV.
//!
//! Coverage:
//! * Encrypt → decrypt round-trip per key size (128/192/256): the
//!   ciphertext differs from the plaintext and decrypt recovers it.
//! * The returned IV is the last ciphertext block (CBC chaining).
//! * Tampered masked key → `AesGcmDecryptTagDoesNotMatch`.
//! * A message that is not a whole number of AES blocks → `InvalidArg`.
//! * An AES key imported via `UnwrapKey` encrypts/decrypts (cross-command).

#![cfg(any(feature = "emu", feature = "mock", feature = "sock"))]
// The `aes_op` transform helper stays available under any backend (so the
// module isn't emu-limited); only the emu-gated tests exercise it today.
#![cfg_attr(not(feature = "emu"), allow(dead_code))]

use azihsm_ddi_tbor_types::TborAesEncryptDecryptReq;
use azihsm_ddi_tbor_types::TborAesEncryptDecryptResp;
// Test-only imports: the round-trip / reject tests need the emu FW handler
// plus the masked-key + unwrap helpers, so keep them emu-gated.
#[cfg(feature = "emu")]
use azihsm_ddi_tbor_types::TborStatus;
#[cfg(feature = "emu")]
use azihsm_ddi_tbor_types::AES_KEY_SIZE_128;
#[cfg(feature = "emu")]
use azihsm_ddi_tbor_types::AES_KEY_SIZE_192;
#[cfg(feature = "emu")]
use azihsm_ddi_tbor_types::AES_KEY_SIZE_256;
#[cfg(feature = "emu")]
use azihsm_ddi_tbor_types::AES_OP_DECRYPT;
#[cfg(feature = "emu")]
use azihsm_ddi_tbor_types::AES_OP_ENCRYPT;
#[cfg(feature = "emu")]
use azihsm_ddi_tbor_types::KEY_CLASS_AES;

#[cfg(feature = "emu")]
use crate::commands::aes_generate_key::generate_key;
#[cfg(feature = "emu")]
use crate::commands::aes_generate_key::SCOPE_LOCAL;
#[cfg(feature = "emu")]
use crate::commands::sd_sealing_key_gen::finalized_co_session;
#[cfg(feature = "emu")]
use crate::commands::unwrap_key::unwrap;
use crate::harness::TestCtx;

/// AES block / IV length.
const IV_LEN: usize = 16;

/// AES-CBC transform `msg` under the masked key + `iv`.
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

#[cfg(feature = "emu")]
#[test]
fn aes_encrypt_decrypt_roundtrip_all_sizes_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let msg = [0xA5u8; 32]; // two AES blocks
    let iv = [0x11u8; IV_LEN];

    for size in [AES_KEY_SIZE_128, AES_KEY_SIZE_192, AES_KEY_SIZE_256] {
        let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, size);

        let enc = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);
        assert_eq!(enc.msg.len(), msg.len(), "ciphertext length matches input");
        assert_ne!(enc.msg, msg, "ciphertext must differ from plaintext");

        // Decrypt the ciphertext with the *original* IV to recover the
        // plaintext (the returned chaining IV is for the next block).
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

#[cfg(feature = "emu")]
#[test]
fn aes_encrypt_decrypt_chaining_iv_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, AES_KEY_SIZE_256);
    let msg = [0x5Au8; 48]; // three AES blocks
    let iv = [0x22u8; IV_LEN];

    let enc = aes_op(&ctx, session.session_id, &key, AES_OP_ENCRYPT, &msg, &iv);
    // For CBC, the updated chaining IV is the last ciphertext block.
    assert_eq!(
        enc.iv,
        enc.msg[enc.msg.len() - IV_LEN..],
        "chaining IV must equal the last ciphertext block",
    );
}

#[cfg(feature = "emu")]
#[test]
fn aes_encrypt_decrypt_rejects_tampered_key_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let mut key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, AES_KEY_SIZE_256);

    // Flip a byte in the AEAD tag region (last 16 bytes) so the unmask tag
    // check fails without disturbing the cleartext scope metadata.
    let last = key.len() - 1;
    key[last] ^= 0x01;

    let req = TborAesEncryptDecryptReq {
        session_id: session.session_id,
        masked_key: key,
        op: AES_OP_ENCRYPT,
        msg: vec![0u8; 16],
        iv: [0u8; IV_LEN],
    };
    ctx.expect_fw_reject(&req, TborStatus::AesGcmDecryptTagDoesNotMatch);
}

#[cfg(feature = "emu")]
#[test]
fn aes_encrypt_decrypt_rejects_bad_msg_len_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let key = generate_key(&ctx, session.session_id, SCOPE_LOCAL, AES_KEY_SIZE_256);

    let req = TborAesEncryptDecryptReq {
        session_id: session.session_id,
        masked_key: key,
        op: AES_OP_ENCRYPT,
        // 20 bytes is not a whole number of 16-byte AES blocks.
        msg: vec![0u8; 20],
        iv: [0u8; IV_LEN],
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

#[cfg(feature = "emu")]
#[test]
fn aes_encrypt_decrypt_unwrapped_key_roundtrip_emu() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // Import an AES-256 key via UnwrapKey (RSA-AES key import), then use
    // the recovered masked key to encrypt and decrypt.
    let aes_key = [0x42u8; 32];
    let masked = unwrap(&ctx, session.session_id, KEY_CLASS_AES, &aes_key).masked_key;

    let msg = [0x37u8; 16];
    let iv = [0x88u8; IV_LEN];
    let enc = aes_op(&ctx, session.session_id, &masked, AES_OP_ENCRYPT, &msg, &iv);
    let dec = aes_op(
        &ctx,
        session.session_id,
        &masked,
        AES_OP_DECRYPT,
        &enc.msg,
        &iv,
    );
    assert_eq!(dec.msg, msg, "unwrapped AES key must round-trip");
}
