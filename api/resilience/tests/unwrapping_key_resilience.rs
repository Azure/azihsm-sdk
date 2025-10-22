// Copyright (C) Microsoft Corporation. All rights reserved.
#![allow(dead_code)]
#![allow(unused_imports)] //remove this when tests unmarked for mock feature only

mod common;
use mcr_api_resilient::DigestKind;
use mcr_api_resilient::HsmDevice;
use mcr_api_resilient::HsmKeyHandle;
use mcr_api_resilient::HsmSession;
use mcr_api_resilient::KeyAvailability;
use mcr_api_resilient::KeyClass;
use mcr_api_resilient::KeyProperties;
use mcr_api_resilient::KeyUsage;
use mcr_api_resilient::RsaCryptoPadding;
use mcr_api_resilient::RsaUnwrapParams;
use test_with_tracing::test;

use crate::common::*;

// Helper function to get the unwrapping key with retry logic
fn get_unwrapping_key(session: &HsmSession) -> HsmKeyHandle {
    // For resilient API, we don't need retry logic as it's handled by the resilient layer
    session
        .get_unwrapping_key()
        .expect("Failed to get unwrapping key")
}

// Test ECC P-256 private key in DER format for import testing
#[allow(dead_code)]
const TEST_ECC_256_PRIVATE_KEY: [u8; 138] = [
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02,
    0x01, 0x01, 0x04, 0x20, 0x87, 0x59, 0x09, 0x7e, 0x21, 0xd7, 0xb2, 0x92, 0xce, 0x88, 0x13, 0xf2,
    0x19, 0x17, 0x8b, 0x57, 0xb1, 0x03, 0xcf, 0x6c, 0xf1, 0x9a, 0xee, 0xa7, 0x22, 0x44, 0xac, 0x43,
    0xd1, 0x1b, 0xd2, 0x86, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xb0, 0x51, 0x4f, 0x91, 0x20, 0x67,
    0x1e, 0xd0, 0xfd, 0xab, 0x69, 0x81, 0x8f, 0xd3, 0x67, 0xca, 0xc1, 0x8b, 0x4e, 0x8b, 0x20, 0xf2,
    0xa4, 0x3b, 0xb8, 0x08, 0xea, 0xa1, 0xcd, 0xc0, 0x1a, 0xa8, 0x22, 0x89, 0x40, 0x9a, 0xab, 0xc6,
    0x30, 0xe8, 0x0e, 0x4a, 0x16, 0x47, 0xbf, 0x94, 0x43, 0x2e, 0xd5, 0xa3, 0x41, 0x3a, 0xd4, 0x3e,
    0x79, 0x41, 0xc1, 0x20, 0xf1, 0x56, 0x23, 0x0f, 0x51, 0x0b,
];

// Get_unwrapping_key twice, before and after LM, verify it's the same type
#[test]
fn test_unwrapping_key_resilience_simple() {
    let device_path = get_device_path_helper();
    let (_device, session, _api_rev) = setup_device_and_session(&device_path);

    let unwrapping_key = session
        .get_unwrapping_key()
        .expect("Failed to get unwrapping key");

    let key_type_before = unwrapping_key.kind();

    simulate_live_migration_helper(&device_path);

    let unwrapping_key_after_lm_result = session
        .get_unwrapping_key()
        .expect("Failed to get unwrapping key");

    let key_type_after = unwrapping_key_after_lm_result.kind();
    assert_eq!(
        key_type_before, key_type_after,
        "Unwrapping key type changed after LM"
    );
}

// Basic test of unwrapping key: get_unwrapping_key, attest_key_and_obtain_cert, sim_lm, unwrap_key, encrypt/decrypt
#[test]
fn test_unwrapping_key_basic() {
    let device_path = get_device_path_helper();
    let (_device, session, _api_rev) = setup_device_and_session(&device_path);

    let wrapping_key = get_unwrapping_key(&session);

    let report_data = [0x42u8; 128];
    let attestation_result = session.attest_key_and_obtain_cert(&wrapping_key, &report_data);

    // Verify attestation succeeded
    assert!(
        attestation_result.is_ok(),
        "Failed to attest unwrapping key: {:?}",
        attestation_result
    );

    let (attestation_report, _cert) = attestation_result.unwrap();
    assert!(
        !attestation_report.is_empty(),
        "Attestation report should not be empty"
    );

    let result = session.export_public_key(&wrapping_key);
    assert!(result.is_ok(), "Failed to export public key: {:?}", result);
    let public_key_der = result.unwrap();

    simulate_live_migration_helper(&device_path);

    let (wrapped_blob, public_key_der_for_target) = generate_wrapped_data(public_key_der);

    let wrapped_blob_params = RsaUnwrapParams {
        key_class: KeyClass::Rsa,
        padding: RsaCryptoPadding::Oaep,
        hash_algorithm: DigestKind::Sha256,
    };

    let result = session.rsa_unwrap(
        &wrapping_key,
        wrapped_blob,
        wrapped_blob_params,
        None,
        KeyProperties {
            key_usage: KeyUsage::EncryptDecrypt,
            key_availability: KeyAvailability::App,
        },
    );
    assert!(result.is_ok(), "Failed to unwrap key: {:?}", result);
    let wrapped_key_handle = result.unwrap();

    let result = session.export_public_key(&wrapped_key_handle);
    assert!(
        result.is_ok(),
        "Failed to export public key from wrapped key handle: {:?}",
        result
    );
    let wrapped_key_pub = result.unwrap();
    assert_eq!(
        wrapped_key_pub, public_key_der_for_target,
        "Public key from wrapped handle should match the generated key"
    );

    let message = vec![0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF];
    let result = session.rsa_encrypt(
        &wrapped_key_handle,
        message.clone(),
        RsaCryptoPadding::Oaep,
        Some(DigestKind::Sha256),
        None,
    );
    assert!(
        result.is_ok(),
        "Failed to encrypt with wrapped key: {:?}",
        result
    );
    let encrypted_data = result.unwrap();

    let result = session.rsa_decrypt(
        &wrapped_key_handle,
        encrypted_data,
        RsaCryptoPadding::Oaep,
        Some(DigestKind::Sha256),
        None,
    );
    assert!(
        result.is_ok(),
        "Failed to decrypt with wrapped key: {:?}",
        result
    );
    let dec_data = result.unwrap();

    assert_eq!(dec_data, message, "Decrypted message should match original");
}

// get_unwrapping_key, attest_key, sim_lm, get_unwrapping_key, unwrap_key
#[test]
fn test_get_unwrapping_key_before_after_lm() {
    let device_path = get_device_path_helper();
    let (_device, session, _api_rev) = setup_device_and_session(&device_path);

    let wrapping_key = get_unwrapping_key(&session);

    let report_data = [0x42u8; 128];
    let attestation_result = session.attest_key_and_obtain_cert(&wrapping_key, &report_data);

    // Verify attestation succeeded
    assert!(
        attestation_result.is_ok(),
        "Failed to attest unwrapping key: {:?}",
        attestation_result
    );

    let (attestation_report, _cert) = attestation_result.unwrap();
    assert!(
        !attestation_report.is_empty(),
        "Attestation report should not be empty"
    );

    // LM 1
    simulate_live_migration_helper(&device_path);

    let wrapping_key_after_lm = get_unwrapping_key(&session);
    let result = session.export_public_key(&wrapping_key_after_lm);
    assert!(result.is_ok(), "Failed to export public key: {:?}", result);
    let public_key_der = result.unwrap();

    let (wrapped_blob, public_key_der_for_target) = generate_wrapped_data(public_key_der);

    let wrapped_blob_params = RsaUnwrapParams {
        key_class: KeyClass::Rsa,
        padding: RsaCryptoPadding::Oaep,
        hash_algorithm: DigestKind::Sha256,
    };

    let result = session.rsa_unwrap(
        &wrapping_key,
        wrapped_blob,
        wrapped_blob_params,
        None,
        KeyProperties {
            key_usage: KeyUsage::EncryptDecrypt,
            key_availability: KeyAvailability::App,
        },
    );
    assert!(result.is_ok(), "Failed to unwrap key: {:?}", result);
    let wrapped_key_handle = result.unwrap();

    let result = session.export_public_key(&wrapped_key_handle);
    assert!(
        result.is_ok(),
        "Failed to export public key from wrapped key handle: {:?}",
        result
    );
    let wrapped_key_pub = result.unwrap();
    assert_eq!(
        wrapped_key_pub, public_key_der_for_target,
        "Public key from wrapped handle should match the generated key"
    );

    let message = vec![0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF];
    let result = session.rsa_encrypt(
        &wrapped_key_handle,
        message.clone(),
        RsaCryptoPadding::Oaep,
        Some(DigestKind::Sha256),
        None,
    );
    assert!(
        result.is_ok(),
        "Failed to encrypt with wrapped key: {:?}",
        result
    );
    let encrypted_data = result.unwrap();

    let result = session.rsa_decrypt(
        &wrapped_key_handle,
        encrypted_data,
        RsaCryptoPadding::Oaep,
        Some(DigestKind::Sha256),
        None,
    );
    assert!(
        result.is_ok(),
        "Failed to decrypt with wrapped key: {:?}",
        result
    );
    let dec_data = result.unwrap();

    assert_eq!(dec_data, message, "Decrypted message should match original");
}

// get_unwrapping_key, sim_lm, attest_key, unwrap_key
#[test]
fn test_unwrapping_key_attest_before_lm() {
    let device_path = get_device_path_helper();
    let (_device, session, _api_rev) = setup_device_and_session(&device_path);

    let wrapping_key = get_unwrapping_key(&session);

    simulate_live_migration_helper(&device_path);

    let report_data = [0x42u8; 128];
    let attestation_result = session.attest_key_and_obtain_cert(&wrapping_key, &report_data);

    // Verify attestation succeeded
    assert!(
        attestation_result.is_ok(),
        "Failed to attest unwrapping key: {:?}",
        attestation_result
    );

    let (attestation_report, _cert) = attestation_result.unwrap();
    assert!(
        !attestation_report.is_empty(),
        "Attestation report should not be empty"
    );

    // Export the public key of the unwrapping key for later use
    let result = session.export_public_key(&wrapping_key);
    assert!(result.is_ok(), "Failed to export public key: {:?}", result);
    let public_key_der = result.unwrap();

    let (wrapped_blob, public_key_der_for_target) = generate_wrapped_data(public_key_der);

    let wrapped_blob_params = RsaUnwrapParams {
        key_class: KeyClass::Rsa,
        padding: RsaCryptoPadding::Oaep,
        hash_algorithm: DigestKind::Sha256,
    };

    let result = session.rsa_unwrap(
        &wrapping_key,
        wrapped_blob,
        wrapped_blob_params,
        None,
        KeyProperties {
            key_usage: KeyUsage::EncryptDecrypt,
            key_availability: KeyAvailability::App,
        },
    );
    assert!(result.is_ok(), "Failed to unwrap key: {:?}", result);
    let wrapped_key_handle = result.unwrap();

    let result = session.export_public_key(&wrapped_key_handle);
    assert!(
        result.is_ok(),
        "Failed to export public key from wrapped key handle: {:?}",
        result
    );
    let wrapped_key_pub = result.unwrap();
    assert_eq!(
        wrapped_key_pub, public_key_der_for_target,
        "Public key from wrapped handle should match the generated key"
    );
}

// get_unwrapping_key, attest_key, unwrap_key, sim_lm, rsa_decrypt/encrypt
#[test]
fn test_unwrapping_key_use_wrapped_key_after_lm() {
    let device_path = get_device_path_helper();
    let (_device, session, _api_rev) = setup_device_and_session(&device_path);

    let wrapping_key = get_unwrapping_key(&session);

    let report_data = [0x42u8; 128];
    let attestation_result = session.attest_key_and_obtain_cert(&wrapping_key, &report_data);

    // Verify attestation succeeded
    assert!(
        attestation_result.is_ok(),
        "Failed to attest unwrapping key: {:?}",
        attestation_result
    );

    let (attestation_report, _cert) = attestation_result.unwrap();
    assert!(
        !attestation_report.is_empty(),
        "Attestation report should not be empty"
    );

    // Export the public key of the unwrapping key for later use
    let result = session.export_public_key(&wrapping_key);
    assert!(result.is_ok(), "Failed to export public key: {:?}", result);
    let public_key_der = result.unwrap();

    let (wrapped_blob, public_key_der_for_target) = generate_wrapped_data(public_key_der);

    let wrapped_blob_params = RsaUnwrapParams {
        key_class: KeyClass::Rsa,
        padding: RsaCryptoPadding::Oaep,
        hash_algorithm: DigestKind::Sha256,
    };

    let result = session.rsa_unwrap(
        &wrapping_key,
        wrapped_blob,
        wrapped_blob_params,
        None,
        KeyProperties {
            key_usage: KeyUsage::EncryptDecrypt,
            key_availability: KeyAvailability::App,
        },
    );
    assert!(result.is_ok(), "Failed to unwrap key: {:?}", result);
    let wrapped_key_handle = result.unwrap();

    // LM
    simulate_live_migration_helper(&device_path);

    let result = session.export_public_key(&wrapped_key_handle);
    assert!(
        result.is_ok(),
        "Failed to export public key from wrapped key handle: {:?}",
        result
    );
    let wrapped_key_pub = result.unwrap();
    assert_eq!(
        wrapped_key_pub, public_key_der_for_target,
        "Public key from wrapped handle should match the generated key"
    );

    let message = vec![0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF];
    let result = session.rsa_encrypt(
        &wrapped_key_handle,
        message.clone(),
        RsaCryptoPadding::Oaep,
        Some(DigestKind::Sha256),
        None,
    );
    assert!(
        result.is_ok(),
        "Failed to encrypt with wrapped key: {:?}",
        result
    );
    let encrypted_data = result.unwrap();

    let result = session.rsa_decrypt(
        &wrapped_key_handle,
        encrypted_data,
        RsaCryptoPadding::Oaep,
        Some(DigestKind::Sha256),
        None,
    );
    assert!(
        result.is_ok(),
        "Failed to decrypt with wrapped key: {:?}",
        result
    );
    let dec_data = result.unwrap();

    assert_eq!(dec_data, message, "Decrypted message should match original");
}

// Test opening device and session in a loop.
// For each session, get unwrapping key, use it, delete it 5 times.
// No sessions leaked, unwrapping key can be accessed after "deleting" from sessions.
#[test]
fn test_unwrapping_key_repeated_device_open() {
    let device_path = get_device_path_helper();

    const ITERATIONS: usize = 20;

    for i in 1..=ITERATIONS {
        println!("Iteration {}/{}", i, ITERATIONS);

        // Open a new device
        let (device, api_rev) = setup_device(&device_path);

        // Open a new session
        let session = device
            .open_session(api_rev, TEST_CREDENTIALS)
            .expect("Failed to open session");

        // Loop 5 times: get unwrapping key, verify, delete
        // This ensures get_unwrapping_key works after delete
        for j in 1..=5 {
            // Get unwrapping key
            let unwrapping_key = session
                .get_unwrapping_key()
                .expect("Failed to get unwrapping key");

            // Verify we can export the public key (proves the key is valid)
            let result = session.export_public_key(&unwrapping_key);
            assert!(
                result.is_ok(),
                "Iteration {}.{}: Failed to export public key: {:?}",
                i,
                j,
                result
            );

            // Delete the unwrapping key
            let result = session.delete_key(&unwrapping_key);
            assert!(
                result.is_ok(),
                "Iteration {}.{}: Failed to delete unwrapping key: {:?}",
                i,
                j,
                result
            );
        }

        // Session and device are automatically dropped here
    }

    println!("Successfully completed {} iterations", ITERATIONS);
}
