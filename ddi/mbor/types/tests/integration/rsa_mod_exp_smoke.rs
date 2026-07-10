// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RsaModExp smoke tests.
//!
//! Validates the `RsaModExp` firmware handler end-to-end against freshly
//! imported RSA-2K / 3K / 4K private keys:
//!
//! - **Decrypt round-trip:** import an `EncryptDecrypt` key, raw-encrypt a
//!   known message locally with the matching public key, run
//!   `RsaModExp { Decrypt }` on the device, and confirm the original
//!   message is recovered.
//! - **Sign round-trip:** import a `SignVerify` key, run
//!   `RsaModExp { Sign }` to produce `s = m^d mod n`, then verify locally
//!   that `s^e mod n == m`.
//! - **Wrong permission:** a `Decrypt` operation against a
//!   `SignVerify`-only key is rejected with `InvalidPermissions`.
//!
//! The round-trips feed a non-palindrome integer through the device so
//! they also exercise the wire little-endian operand handling.

#![cfg(test)]

use azihsm_crypto::*;
use azihsm_ddi::*;
use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

/// Derive the public key matching a known RSA private DER.
fn pub_from_priv(priv_der: &[u8]) -> RsaPublicKey {
    RsaPrivateKey::from_bytes(priv_der)
        .expect("parse known RSA private DER")
        .public_key()
        .expect("derive public key")
}

/// Import a known RSA private key with the given usage as either a CRT or
/// non-CRT vault key, returning the imported private-key id.
fn store_rsa(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    key_usage: DdiKeyUsage,
    crt: bool,
    rsa_key_size_in_k: u8,
) -> u16 {
    if crt {
        store_rsa_keys_crt(dev, session_id, key_usage, rsa_key_size_in_k, None).1
    } else {
        store_rsa_keys_no_crt(dev, session_id, key_usage, rsa_key_size_in_k, None).1
    }
}

/// Import an `EncryptDecrypt` key, raw-encrypt a known message with the
/// matching public key, decrypt it on the device via
/// `RsaModExp { Decrypt }`, and confirm the message round-trips.
fn decrypt_roundtrip(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    crt: bool,
    rsa_key_size_in_k: u8,
    modulus_len: usize,
    priv_der: &[u8],
) {
    let key_id = store_rsa(
        dev,
        session_id,
        DdiKeyUsage::EncryptDecrypt,
        crt,
        rsa_key_size_in_k,
    );

    // Non-palindrome message that stays below the modulus (leading byte
    // 0x01, so `m < n`).  Both `m` and the resulting ciphertext `c = m^e
    // mod n` (fed to the device as `y`) are non-palindrome, so the
    // round-trip exercises the wire little-endian operand handling.
    let mut msg = vec![0x02u8; modulus_len];
    msg[0] = 0x01;
    let ciphertext = Encrypter::encrypt_vec(
        &mut RsaEncryptAlgo::with_no_padding(),
        &pub_from_priv(priv_der),
        &msg,
    )
    .expect("raw RSA encrypt");

    let resp = helper_rsa_mod_exp(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
        MborByteArray::from_slice(&ciphertext).expect("ciphertext fits"),
        DdiRsaOpType::Decrypt,
    )
    .expect("RsaModExp Decrypt should succeed");

    assert_eq!(resp.hdr.op, DdiOp::RsaModExp);
    assert_eq!(resp.hdr.status, DdiStatus::Success);
    assert_eq!(
        &resp.data.x.data()[..resp.data.x.len()],
        msg.as_slice(),
        "RsaModExp Decrypt must recover the original message"
    );
}

/// Import a `SignVerify` key, produce `s = m^d mod n` via
/// `RsaModExp { Sign }`, and verify locally that `s^e mod n == m`.
fn sign_roundtrip(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    crt: bool,
    rsa_key_size_in_k: u8,
    modulus_len: usize,
    priv_der: &[u8],
) {
    let key_id = store_rsa(
        dev,
        session_id,
        DdiKeyUsage::SignVerify,
        crt,
        rsa_key_size_in_k,
    );

    // Non-palindrome message that stays below the modulus (leading byte
    // 0x01, so `m < n`).
    let mut msg = vec![0x02u8; modulus_len];
    msg[0] = 0x01;

    let resp = helper_rsa_mod_exp(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
        MborByteArray::from_slice(&msg).expect("message fits"),
        DdiRsaOpType::Sign,
    )
    .expect("RsaModExp Sign should succeed");
    assert_eq!(resp.hdr.status, DdiStatus::Success);
    let signature = &resp.data.x.data()[..resp.data.x.len()];

    // Verify the raw signature locally with the matching public key:
    // `s^e mod n == m`.
    let verified = Verifier::verify(
        &mut RsaSignAlgo::with_no_padding(),
        &pub_from_priv(priv_der),
        &msg,
        signature,
    )
    .expect("raw RSA verify");
    assert!(
        verified,
        "RsaModExp Sign must produce a signature that verifies over the message"
    );
}

#[test]
fn test_rsa_mod_exp_decrypt_roundtrip_2k_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            decrypt_roundtrip(
                dev,
                session_id,
                false,
                2,
                256,
                TEST_RSA_2K_PRIVATE_KEY.as_slice(),
            );
        },
    );
}

#[test]
fn test_rsa_mod_exp_decrypt_roundtrip_3k_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            decrypt_roundtrip(
                dev,
                session_id,
                false,
                3,
                384,
                TEST_RSA_3K_PRIVATE_KEY.as_slice(),
            );
        },
    );
}

#[test]
fn test_rsa_mod_exp_decrypt_roundtrip_4k_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            decrypt_roundtrip(
                dev,
                session_id,
                false,
                4,
                512,
                TEST_RSA_4K_PRIVATE_KEY.as_slice(),
            );
        },
    );
}

#[test]
fn test_rsa_mod_exp_decrypt_roundtrip_2k_crt_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            decrypt_roundtrip(
                dev,
                session_id,
                true,
                2,
                256,
                TEST_RSA_2K_PRIVATE_KEY.as_slice(),
            );
        },
    );
}

#[test]
fn test_rsa_mod_exp_decrypt_roundtrip_3k_crt_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            decrypt_roundtrip(
                dev,
                session_id,
                true,
                3,
                384,
                TEST_RSA_3K_PRIVATE_KEY.as_slice(),
            );
        },
    );
}

#[test]
fn test_rsa_mod_exp_decrypt_roundtrip_4k_crt_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            decrypt_roundtrip(
                dev,
                session_id,
                true,
                4,
                512,
                TEST_RSA_4K_PRIVATE_KEY.as_slice(),
            );
        },
    );
}

#[test]
fn test_rsa_mod_exp_sign_roundtrip_2k_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            sign_roundtrip(
                dev,
                session_id,
                false,
                2,
                256,
                TEST_RSA_2K_PRIVATE_KEY.as_slice(),
            );
        },
    );
}

#[test]
fn test_rsa_mod_exp_sign_roundtrip_3k_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            sign_roundtrip(
                dev,
                session_id,
                false,
                3,
                384,
                TEST_RSA_3K_PRIVATE_KEY.as_slice(),
            );
        },
    );
}

#[test]
fn test_rsa_mod_exp_sign_roundtrip_4k_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            sign_roundtrip(
                dev,
                session_id,
                false,
                4,
                512,
                TEST_RSA_4K_PRIVATE_KEY.as_slice(),
            );
        },
    );
}

#[test]
fn test_rsa_mod_exp_sign_roundtrip_2k_crt_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            sign_roundtrip(
                dev,
                session_id,
                true,
                2,
                256,
                TEST_RSA_2K_PRIVATE_KEY.as_slice(),
            );
        },
    );
}

#[test]
fn test_rsa_mod_exp_sign_roundtrip_3k_crt_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            sign_roundtrip(
                dev,
                session_id,
                true,
                3,
                384,
                TEST_RSA_3K_PRIVATE_KEY.as_slice(),
            );
        },
    );
}

#[test]
fn test_rsa_mod_exp_sign_roundtrip_4k_crt_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            sign_roundtrip(
                dev,
                session_id,
                true,
                4,
                512,
                TEST_RSA_4K_PRIVATE_KEY.as_slice(),
            );
        },
    );
}

#[test]
fn test_rsa_mod_exp_wrong_permission_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // A SignVerify-only key cannot perform a Decrypt primitive.
            let (_pub, key_id, _) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 2, None);

            let err = helper_rsa_mod_exp(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
                MborByteArray::new([0x01u8; 512], 256).expect("input fits"),
                DdiRsaOpType::Decrypt,
            )
            .expect_err("Decrypt with a SignVerify-only key must be rejected");

            assert!(
                matches!(err, DdiError::DdiStatus(DdiStatus::InvalidPermissions)),
                "expected InvalidPermissions, got {err:?}"
            );
        },
    );
}
