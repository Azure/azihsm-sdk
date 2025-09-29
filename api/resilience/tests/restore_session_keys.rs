// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;
use mcr_api_resilient::*;
use test_with_tracing::test;

use crate::common::*;

// Create a session key
// Trigger LM
// Check if the session key can be used after LM
#[test]
fn test_unmask_all_session_keys_aes() {
    let device_path = get_device_path_helper();
    let (_device, session, _api_rev) = setup_device_and_session(&device_path);

    // Create AES session key
    let aes_key = generate_session_aes_key(&session, "aes_generate failed");

    // Use this key to encrypt some data
    let plaintext = b"Hello, world!";
    // Must be multiple of 16
    let mut buffer = [0u8; 16];
    buffer[..plaintext.len()].copy_from_slice(plaintext);

    let result =
        session.aes_encrypt_decrypt(&aes_key, AesMode::Encrypt, buffer.to_vec(), [0u8; 16]);

    assert!(result.is_ok(), "failed to encrypt data: {:?}", result);

    let encrypted_data = result.unwrap();
    let ciphertext = encrypted_data.data.clone();

    // LM
    simulate_live_migration_helper(&device_path);

    // Use the same key to decrypt the same data
    let result = session.aes_encrypt_decrypt(&aes_key, AesMode::Decrypt, ciphertext, [0u8; 16]);

    assert!(result.is_ok(), "failed to decrypt data: {:?}", result);

    let decrypted_data = result.unwrap();
    assert_eq!(
        decrypted_data.data, buffer,
        "decrypted data does not match original"
    );

    common_cleanup(&device_path);
}

#[test]
fn test_unmask_all_session_keys_ecc() {
    let device_path = get_device_path_helper();
    let (_device, session, _api_rev) = setup_device_and_session(&device_path);

    // Generate ECC key
    let result = session.ecc_generate(
        EccCurve::P256,
        None,
        KeyProperties {
            key_usage: KeyUsage::SignVerify,
            key_availability: KeyAvailability::Session,
        },
    );
    assert!(result.is_ok(), "failed to generate ECC key: {:?}", result);
    let ecc_key = result.unwrap();

    // Sign some data
    let data_to_sign = b"Hello, world!";
    // 32 bytes for P256 key
    let mut buffer = [0u8; 32];
    buffer[..data_to_sign.len()].copy_from_slice(data_to_sign);

    // Signing before LM
    let result = session.ecc_sign(&ecc_key, buffer.to_vec());
    assert!(result.is_ok(), "failed to sign data: {:?}", result);
    let signature1 = result.unwrap();

    // LM
    simulate_live_migration_helper(&device_path);

    // Signing after LM
    let result = session.ecc_sign(&ecc_key, buffer.to_vec());
    assert!(result.is_ok(), "failed to sign data: {:?}", result);
    let signature2 = result.unwrap();

    // Verify both signatures
    let result = session.ecc_verify(&ecc_key, buffer.to_vec(), signature1);
    assert!(result.is_ok(), "failed to verify signature1: {:?}", result);

    let result = session.ecc_verify(&ecc_key, buffer.to_vec(), signature2);
    assert!(result.is_ok(), "failed to verify signature2: {:?}", result);

    common_cleanup(&device_path);
}
