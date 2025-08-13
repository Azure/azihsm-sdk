// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use winapi::shared::winerror::NTE_NOT_SUPPORTED;
use windows::core::HRESULT;
use windows::Win32::Security::Cryptography::*;

use crate::common::*;

#[test]
fn test_rsa4k_key_unwrap_with_ckm_rsa_aes_key_wrap() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa4k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::CKM_RSA_AES_KEY_WRAP,
        None, // don't touch `RsaCrtEnabled` property
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa4k_key_unwrap_with_ckm_rsa_aes_key_wrap_crt_enable() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa4k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::CKM_RSA_AES_KEY_WRAP,
        Some(true), // intentionally enable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa4k_key_unwrap_with_ckm_rsa_aes_key_wrap_crt_disable() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa4k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::CKM_RSA_AES_KEY_WRAP,
        Some(false), // intentionally disable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa4k_key_unwrap_with_rsa_aes_key_wrap_256() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa4k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        None, // don't touch `RsaCrtEnabled` property
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa4k_key_unwrap_with_rsa_aes_key_wrap_256_crt_enable() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa4k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        Some(true), // intentionally enable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa4k_key_unwrap_with_rsa_aes_key_wrap_256_crt_disable() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa4k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        Some(false), // intentionally disable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa4k_key_unwrap_with_rsa_aes_key_wrap_384() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa4k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        None, // don't touch `RsaCrtEnabled` property
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa4k_key_unwrap_with_rsa_aes_key_wrap_384_crt_enable() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa4k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        Some(true), // intentionally enable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa4k_key_unwrap_with_rsa_aes_key_wrap_384_crt_disable() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa4k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        Some(false), // intentionally disable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa3k_key_unwrap_with_ckm_rsa_aes_key_wrap() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa3k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::CKM_RSA_AES_KEY_WRAP,
        None, // don't touch `RsaCrtEnabled` property
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa3k_key_unwrap_with_ckm_rsa_aes_key_wrap_crt_enable() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa3k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::CKM_RSA_AES_KEY_WRAP,
        Some(true), // intentionally enable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa3k_key_unwrap_with_ckm_rsa_aes_key_wrap_crt_disable() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa3k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::CKM_RSA_AES_KEY_WRAP,
        Some(false), // intentionally disable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa3k_key_unwrap_with_rsa_aes_key_wrap_256() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa3k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        None, // don't touch `RsaCrtEnabled` property
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa3k_key_unwrap_with_rsa_aes_key_wrap_256_crt_enable() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa3k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        Some(true), // intentionally enable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa3k_key_unwrap_with_rsa_aes_key_wrap_256_crt_disable() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa3k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        Some(false), // intentionally disable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa3k_key_unwrap_with_rsa_aes_key_wrap_384() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa3k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        None, // don't touch `RsaCrtEnabled` property
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa3k_key_unwrap_with_rsa_aes_key_wrap_384_crt_enable() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa3k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        Some(true), // intentionally enable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa3k_key_unwrap_with_rsa_aes_key_wrap_384_crt_disable() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa3k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        Some(false), // intentionally disable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa2k_key_unwrap_with_ckm_rsa_aes_key_wrap() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa2k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::CKM_RSA_AES_KEY_WRAP,
        None, // don't touch `RsaCrtEnabled` property
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa2k_key_unwrap_with_ckm_rsa_aes_key_wrap_crt_enable() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa2k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::CKM_RSA_AES_KEY_WRAP,
        Some(true), // intentionally enable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa2k_key_unwrap_with_ckm_rsa_aes_key_wrap_crt_disable() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa2k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::CKM_RSA_AES_KEY_WRAP,
        Some(false), // intentionally disable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa2k_key_unwrap_with_rsa_aes_key_wrap_256() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa2k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        None, // don't touch `RsaCrtEnabled` property
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa2k_key_unwrap_with_rsa_aes_key_wrap_256_crt_enable() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa2k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        Some(true), // intentionally enable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa2k_key_unwrap_with_rsa_aes_key_wrap_256_crt_disable() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa2k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        Some(false), // intentionally disable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa2k_key_unwrap_with_rsa_aes_key_wrap_384() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa2k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        None, // don't touch `RsaCrtEnabled` property
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa2k_key_unwrap_with_rsa_aes_key_wrap_384_crt_enable() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa2k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        Some(true), // intentionally enable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa2k_key_unwrap_with_rsa_aes_key_wrap_384_crt_disable() {
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key_type = KeyType::Rsa2k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        Some(false), // intentionally disable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa4k_key_unwrap_with_rsa_aes_key_wrap_384_key_usage_mismatch() {
    let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
    let key_type = KeyType::Rsa4k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        None, // don't touch `RsaCrtEnabled` property
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        true,
    );
    test_helper_rsa_sign_verify(
        &key,
        &key_type,
        Some(NCryptPaddingType::Pkcs1),
        Some(NCryptPaddingType::Pkcs1),
        NCryptShaAlgorithm::Sha256,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa4k_key_unwrap_with_rsa_aes_key_wrap_384_key_usage_mismatch_crt_enable() {
    let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
    let key_type = KeyType::Rsa4k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        Some(true), // intentionally enable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        true,
    );
    test_helper_rsa_sign_verify(
        &key,
        &key_type,
        Some(NCryptPaddingType::Pkcs1),
        Some(NCryptPaddingType::Pkcs1),
        NCryptShaAlgorithm::Sha256,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

#[test]
fn test_rsa4k_key_unwrap_with_rsa_aes_key_wrap_384_key_usage_mismatch_crt_disable() {
    let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
    let key_type = KeyType::Rsa4k;
    let key = test_helper_rsa_key_unwrap(
        &key_type,
        KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        Some(false), // intentionally disable RSA-CRT
        key_usage,
    );
    test_helper_rsa_encrypt_decrypt(
        &key,
        &key_type,
        NCryptShaAlgorithm::Sha256,
        None,
        false,
        true,
    );
    test_helper_rsa_sign_verify(
        &key,
        &key_type,
        Some(NCryptPaddingType::Pkcs1),
        Some(NCryptPaddingType::Pkcs1),
        NCryptShaAlgorithm::Sha256,
        false,
        false,
    );
    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);
}

// Test Unsupported key kind BCRYPT_RNG_FIPS186_DSA_ALGORITHM
// This test is to add code coverage for macro_rules! key_kind
#[test]
fn test_invalid_key_kind_during_import() {
    let mut azihsm_provider = ProviderHandle::new();

    let key_type = KeyType::Rsa2k;

    let key_encryption_type = KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384;

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let mut import_key = KeyHandle::new();
        let mut target_key = KeyHandle::new();

        {
            // Open handle to the built-in import key
            let result = NCryptOpenKey(
                azihsm_provider.handle(),
                import_key.as_mut(),
                AZIHSM_BUILTIN_UNWRAP_KEY,
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_ok());

            // Export public key from the import key
            let mut pub_key = vec![0u8; 600];
            let mut pub_key_size = pub_key.len() as u32;
            let result = NCryptExportKey(
                import_key.handle(),
                None,
                NCRYPT_OPAQUETRANSPORT_BLOB,
                None,
                Some(&mut pub_key),
                std::ptr::addr_of_mut!(pub_key_size),
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_ok());
            pub_key.truncate(pub_key_size as usize);

            // Generate a 'key_type' RSA private key
            // Wrap it with the import public key using 'key_enc_algo' key encryption algorithm
            let private_key = generate_rsa_der(key_type).0;
            let encrypted_blob = wrap_data(pub_key, &private_key, key_encryption_type);
            let key_blob = create_pkcs11_rsa_aes_wrap_blob(&encrypted_blob, key_encryption_type);

            // Prepare paramlist for unwrapping
            // IMPORTANT: Using a unsupported type here to trigger error
            let param_buffers = [BCryptBuffer {
                cbBuffer: (BCRYPT_RNG_FIPS186_DSA_ALGORITHM.to_string().unwrap().len()
                    * std::mem::size_of::<u16>()) as u32,
                BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
                pvBuffer: BCRYPT_RNG_FIPS186_DSA_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
            }];

            let params = BCryptBufferDesc {
                ulVersion: NCRYPTBUFFER_VERSION,
                cBuffers: param_buffers.len() as u32,
                pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
            };

            // Import the wrapped key
            let result = NCryptImportKey(
                azihsm_provider.handle(),
                import_key.handle(),
                BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
                Some(&params),
                target_key.as_mut(),
                key_blob.as_slice(),
                NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
            );
            assert!(result.is_err(), "{:?}", result);
            let err = result.unwrap_err().code();
            assert_eq!(err, HRESULT(NTE_NOT_SUPPORTED));
        }
    }
}
