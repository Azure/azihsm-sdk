// Copyright (C) Microsoft Corporation. All rights reserved.
mod common;
use std::mem::size_of;
use std::ptr;

use openssl::rand::rand_bytes;
use widestring::*;
use winapi::shared::winerror::E_INVALIDARG;
use winapi::shared::winerror::E_UNEXPECTED;
use winapi::shared::winerror::NTE_BAD_KEY;
use winapi::shared::winerror::NTE_BAD_LEN;
use winapi::shared::winerror::NTE_INVALID_PARAMETER;
use winapi::shared::winerror::NTE_NOT_SUPPORTED;
use windows::core::*;
use windows::Win32::Security::Cryptography::*;

use crate::common::*;

enum BlobType {
    PublicKeyBlob,
    AzIHsmImportKeyBlob,
}

// HKDF tests
#[test]
fn test_ecc_p256_hkdf_derive_aes_128_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP256,
        AES_KEY_BIT_LENGTH_128,
        BCRYPT_HKDF_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_128 as u32,
    );
}

#[test]
fn test_ecc_p256_hkdf_derive_aes_192_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP256,
        AES_KEY_BIT_LENGTH_192,
        BCRYPT_HKDF_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_192 as u32,
    );
}

#[test]
fn test_ecc_p256_hkdf_derive_aes_256_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP256,
        AES_KEY_BIT_LENGTH_256,
        BCRYPT_HKDF_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_256 as u32,
    );
}

#[test]
fn test_ecc_p384_hkdf_derive_aes_128_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP384,
        AES_KEY_BIT_LENGTH_128,
        BCRYPT_HKDF_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_128 as u32,
    );
}

#[test]
fn test_ecc_p384_hkdf_derive_aes_192_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP384,
        AES_KEY_BIT_LENGTH_192,
        BCRYPT_HKDF_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_192 as u32,
    );
}

#[test]
fn test_ecc_p384_hkdf_derive_aes_256_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP384,
        AES_KEY_BIT_LENGTH_256,
        BCRYPT_HKDF_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_256 as u32,
    );
}

#[test]
fn test_ecc_p521_hkdf_derive_aes_128_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP521,
        AES_KEY_BIT_LENGTH_128,
        BCRYPT_HKDF_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_128 as u32,
    );
}

#[test]
fn test_ecc_p521_hkdf_derive_aes_192_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP521,
        AES_KEY_BIT_LENGTH_192,
        BCRYPT_HKDF_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_192 as u32,
    );
}

#[test]
fn test_ecc_p521_hkdf_derive_aes_256_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP521,
        AES_KEY_BIT_LENGTH_256,
        BCRYPT_HKDF_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_256 as u32,
    );
}

// KBKDF tests
#[test]
fn test_ecc_p256_kbkdf_derive_aes_128_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP256,
        AES_KEY_BIT_LENGTH_128,
        BCRYPT_SP800108_CTR_HMAC_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_128 as u32,
    );
}

#[test]
fn test_ecc_p256_kbkdf_derive_aes_192_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP256,
        AES_KEY_BIT_LENGTH_192,
        BCRYPT_SP800108_CTR_HMAC_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_192 as u32,
    );
}

#[test]
fn test_ecc_p256_kbkdf_derive_aes_256_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP256,
        AES_KEY_BIT_LENGTH_256,
        BCRYPT_SP800108_CTR_HMAC_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_256 as u32,
    );
}

#[test]
fn test_ecc_p384_kbkdf_derive_aes_128_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP384,
        AES_KEY_BIT_LENGTH_128,
        BCRYPT_SP800108_CTR_HMAC_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_128 as u32,
    );
}

#[test]
fn test_ecc_p384_kbkdf_derive_aes_192_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP384,
        AES_KEY_BIT_LENGTH_192,
        BCRYPT_SP800108_CTR_HMAC_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_192 as u32,
    );
}

#[test]
fn test_ecc_p384_kbkdf_derive_aes_256_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP384,
        AES_KEY_BIT_LENGTH_256,
        BCRYPT_SP800108_CTR_HMAC_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_256 as u32,
    );
}

#[test]
fn test_ecc_p521_kbkdf_derive_aes_128_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP521,
        AES_KEY_BIT_LENGTH_128,
        BCRYPT_SP800108_CTR_HMAC_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_128 as u32,
    );
}

#[test]
fn test_ecc_p521_kbkdf_derive_aes_192_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP521,
        AES_KEY_BIT_LENGTH_192,
        BCRYPT_SP800108_CTR_HMAC_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_192 as u32,
    );
}

#[test]
fn test_ecc_p521_kbkdf_derive_aes_256_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP521,
        AES_KEY_BIT_LENGTH_256,
        BCRYPT_SP800108_CTR_HMAC_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_256 as u32,
    );
}

// Create ECC Key without setting curve
#[test]
fn test_ecdh_without_curve() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut private_key = KeyHandle::new();

    unsafe {
        // Key Creation
        // Don't set ECC Curve
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            private_key.as_mut(),
            BCRYPT_ECDH_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(private_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BAD_KEY));
    }
}

// Create ECC Key with invalid flag
#[test]
fn test_ecdh_key_creation_invalid_flag() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut private_key = KeyHandle::new();

    unsafe {
        // Key Creation
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            private_key.as_mut(),
            BCRYPT_ECC_CURVE_NISTP521,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_NOT_SUPPORTED));
    }
}

// Test mismatch ECC Pub Key
// Alice use ECC 256, Bob use ECC 521, and they exchange pub key to generate secret
// Should fail
#[test]
fn test_secret_gen_mismatch_ecc_key() {
    let mut azihsm_provider = ProviderHandle::new();

    // Alice's parameters
    let mut alice_private_key = KeyHandle::new();

    // Bob's parameters
    let mut bob_private_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        // Key Creation and Public Key Export for Alice
        create_and_finalize_key(
            azihsm_provider.handle(),
            &mut alice_private_key,
            BCRYPT_ECDH_ALGORITHM,
            Some(BCRYPT_ECC_CURVE_NISTP256),
        );

        let alice_public_key = export_public_key(alice_private_key.handle());

        // Key Creation and Public Key Export for Bob
        create_and_finalize_key(
            azihsm_provider.handle(),
            &mut bob_private_key,
            BCRYPT_ECDH_ALGORITHM,
            Some(BCRYPT_ECC_CURVE_NISTP521),
        );

        let bob_public_key = export_public_key(bob_private_key.handle());

        // Public Key Exchange between Alice and Bob
        let alice_imported_bob_public_key = import_key(
            azihsm_provider.handle(),
            bob_public_key.as_ref(),
            BlobType::PublicKeyBlob,
        );

        let bob_imported_alice_public_key = import_key(
            azihsm_provider.handle(),
            alice_public_key.as_ref(),
            BlobType::PublicKeyBlob,
        );

        // Alice Secret Generation should fail
        let mut alice_secret = SecretHandle::new();

        let result = NCryptSecretAgreement(
            alice_private_key.handle(),
            alice_imported_bob_public_key.handle(),
            alice_secret.as_mut(),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(E_UNEXPECTED));

        // Bob Secret Generation should fail
        let mut bob_secret = SecretHandle::new();

        let result = NCryptSecretAgreement(
            bob_private_key.handle(),
            bob_imported_alice_public_key.handle(),
            bob_secret.as_mut(),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(E_UNEXPECTED));
    }
}

// Alice try to import a tampered Bob public key
#[test]
fn test_ecdh_import_tampered_pub_key() {
    let mut azihsm_provider = ProviderHandle::new();

    // Bob's parameters
    let mut bob_private_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        // Key Creation and Public Key Export for Bob
        create_and_finalize_key(
            azihsm_provider.handle(),
            &mut bob_private_key,
            BCRYPT_ECDH_ALGORITHM,
            Some(BCRYPT_ECC_CURVE_NISTP256),
        );

        let mut bob_public_key = export_public_key(bob_private_key.handle());

        // Tamper bob public key
        bob_public_key[0] = bob_public_key[0].wrapping_add(1);
        bob_public_key[1] = bob_public_key[1].wrapping_add(1);

        // Alice try to import tampered bob key
        let mut imported_key_handle = KeyHandle::new();

        let result = NCryptImportKey(
            azihsm_provider.handle(),
            NCRYPT_KEY_HANDLE(0),
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            imported_key_handle.as_mut(),
            &bob_public_key,
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}

#[test]
fn test_import_rsa_pub_key() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut unwrapping_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        // Get public key data for RSA unwrapping key
        let result = NCryptOpenKey(
            azihsm_provider.handle(),
            unwrapping_key.as_mut(),
            AZIHSM_BUILTIN_UNWRAP_KEY,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        let bob_public_key = export_public_key(unwrapping_key.handle());
        // Alice try to import incorrect pub key
        let mut imported_key_handle = KeyHandle::new();
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            NCRYPT_KEY_HANDLE(0),
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            imported_key_handle.as_mut(),
            &bob_public_key,
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}

// When Alice and Bob exchange their ECC public key
// Charlie sneaks in and replace Bob's public key with his
// Should fail at AES encryption/decryption step
#[test]
fn test_ecdh_p256_secret_gen_charlie_ecc_key() {
    let mut azihsm_provider = ProviderHandle::new();

    // Alice's parameters
    let mut alice_private_key = KeyHandle::new();

    // Bob's parameters
    let mut bob_private_key = KeyHandle::new();

    // Charlie's parameters
    let mut charlie_private_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        // Key Creation and Public Key Export for Alice
        create_and_finalize_key(
            azihsm_provider.handle(),
            &mut alice_private_key,
            BCRYPT_ECDH_ALGORITHM,
            Some(BCRYPT_ECC_CURVE_NISTP256),
        );

        let alice_public_key = export_public_key(alice_private_key.handle());

        // Key Creation and Public Key Export for Bob
        create_and_finalize_key(
            azihsm_provider.handle(),
            &mut bob_private_key,
            BCRYPT_ECDH_ALGORITHM,
            Some(BCRYPT_ECC_CURVE_NISTP256),
        );

        let _bob_public_key = export_public_key(bob_private_key.handle());

        // Key Creation and Public Key Export for Charlie
        create_and_finalize_key(
            azihsm_provider.handle(),
            &mut charlie_private_key,
            BCRYPT_ECDH_ALGORITHM,
            Some(BCRYPT_ECC_CURVE_NISTP256),
        );

        let charlie_public_key = export_public_key(charlie_private_key.handle());

        // Public Key Exchange between Alice and Bob
        // But Alice got Charlie's public key instead of Bob
        let alice_imported_charlie_public_key = import_key(
            azihsm_provider.handle(),
            &charlie_public_key,
            BlobType::PublicKeyBlob,
        );

        let bob_imported_alice_public_key = import_key(
            azihsm_provider.handle(),
            &alice_public_key,
            BlobType::PublicKeyBlob,
        );

        // Secret Generation
        let alice_secret = generate_secret(
            alice_private_key.handle(),
            alice_imported_charlie_public_key.handle(),
        );
        let bob_secret = generate_secret(
            bob_private_key.handle(),
            bob_imported_alice_public_key.handle(),
        );

        // Alice derive a 128bit key using alice_secret
        let alice_derived_key_buffer = derive_key(
            alice_secret.handle(),
            AES_KEY_BIT_LENGTH_128,
            BCRYPT_HKDF_ALGORITHM,
        );

        // Alice import derived key buffer to get the key handle
        let alice_derived_key = import_key(
            azihsm_provider.handle(),
            &alice_derived_key_buffer,
            BlobType::AzIHsmImportKeyBlob,
        );

        // Set encryption mode and key length for alice aes derived key
        set_property(
            alice_derived_key.handle(),
            Some(BCRYPT_CHAIN_MODE_CBC),
            Some(AES_KEY_BIT_LENGTH_128 as u32),
        );

        // Finalize Alice's derived key
        let result = NCryptFinalizeKey(alice_derived_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Derive key for bob using bob_secret
        let bob_derived_key_buffer = derive_key(
            bob_secret.handle(),
            AES_KEY_BIT_LENGTH_128,
            BCRYPT_HKDF_ALGORITHM,
        );

        // Import bob derived key buffer to get the key handle
        let bob_derived_key = import_key(
            azihsm_provider.handle(),
            &bob_derived_key_buffer,
            BlobType::AzIHsmImportKeyBlob,
        );

        // Set encryption mode and key length for bob aes derived key
        set_property(
            bob_derived_key.handle(),
            Some(BCRYPT_CHAIN_MODE_CBC),
            Some(AES_KEY_BIT_LENGTH_128 as u32),
        );

        // Finalize the Bob's derived key
        let result = NCryptFinalizeKey(bob_derived_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // use alice key for encrypting plain text and bob key
        // for decrypting and compare the data.
        // Data should be different
        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).unwrap();
        let mut iv_orig = iv;

        let mut padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: iv.as_mut_ptr(),
            cbIV: iv.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        let result = NCryptEncrypt(
            alice_derived_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        let mut decrypted = [0u8; 128];
        let mut decrypted_len = 0u32;
        padding_info.pbIV = iv_orig.as_mut_ptr();

        let result = NCryptDecrypt(
            bob_derived_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_ne!(plaintext, decrypted);
    }
}

// Derive key size incorrect
#[test]
fn test_ecdh_derive_key_incorrect_size() {
    let mut azihsm_provider = ProviderHandle::new();

    let curve_name = BCRYPT_ECC_CURVE_NISTP256;
    let derived_key_bitlen = AES_KEY_BIT_LENGTH_256 + 10;

    // Alice's parameters
    let mut alice_key = KeyHandle::new();
    let alice_imported_bob_key;

    // Bob's parameters
    let mut bob_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        // Alice Key Creation and Public Key Export
        create_and_finalize_key(
            azihsm_provider.handle(),
            &mut alice_key,
            BCRYPT_ECDH_ALGORITHM,
            Some(curve_name),
        );

        // Bob Key Creation and Public Key Export
        create_and_finalize_key(
            azihsm_provider.handle(),
            &mut bob_key,
            BCRYPT_ECDH_ALGORITHM,
            Some(curve_name),
        );

        let bob_exported_key = export_public_key(bob_key.handle());

        // Alice and Bob Public Key Exchange
        alice_imported_bob_key = import_key(
            azihsm_provider.handle(),
            &bob_exported_key,
            BlobType::PublicKeyBlob,
        );

        // Alice Secret Generation
        let alice_secret = generate_secret(alice_key.handle(), alice_imported_bob_key.handle());

        // Alice derive key using HKDF, incorrect key bit length
        {
            let mut salt_data = [0u8; 64];
            let salt_bytes = "salt".as_bytes();
            salt_data[..salt_bytes.len()].copy_from_slice(salt_bytes);

            let mut info = [0u8; 16];
            let info_bytes = "label".as_bytes();
            info[..info_bytes.len()].copy_from_slice(info_bytes);

            let param_buffers = [
                // digest kind
                BCryptBuffer {
                    cbBuffer: (BCRYPT_SHA256_ALGORITHM.to_string().unwrap().len()
                        * std::mem::size_of::<u16>()) as u32,
                    BufferType: KDF_HASH_ALGORITHM,
                    pvBuffer: BCRYPT_SHA256_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
                },
                // info
                BCryptBuffer {
                    cbBuffer: info_bytes.len() as u32,
                    BufferType: KDF_HKDF_INFO,
                    pvBuffer: info_bytes.as_ptr() as *mut std::ffi::c_void,
                },
                // salt
                BCryptBuffer {
                    cbBuffer: salt_data.len() as u32,
                    BufferType: KDF_HKDF_SALT,
                    pvBuffer: salt_data.as_ptr() as *mut std::ffi::c_void,
                },
                // key bit length
                BCryptBuffer {
                    cbBuffer: std::mem::size_of::<usize>() as u32,
                    BufferType: KDF_KEYBITLENGTH,
                    pvBuffer: &derived_key_bitlen as *const usize as *mut std::ffi::c_void,
                },
            ];

            let param_list = BCryptBufferDesc {
                ulVersion: NCRYPTBUFFER_VERSION,
                cBuffers: param_buffers.len() as u32,
                pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
            };

            let mut output_size = 0u32;
            let result = NCryptDeriveKey(
                alice_secret.handle(),
                BCRYPT_HKDF_ALGORITHM,
                Some(&param_list),
                None,
                ptr::addr_of_mut!(output_size),
                0,
            );
            // If pbderivedkey is null, we return before validate parameter list
            // Causing this to return ok
            assert!(result.is_ok());

            let mut derived_key_buf = vec![0u8; output_size as usize];
            let result = NCryptDeriveKey(
                alice_secret.handle(),
                BCRYPT_HKDF_ALGORITHM,
                Some(&param_list),
                Some(&mut derived_key_buf),
                ptr::addr_of_mut!(output_size),
                0,
            );
            assert!(result.is_err(), "result {:?}", result);
            assert_eq!(result.unwrap_err().code(), HRESULT(E_INVALIDARG));
        }
    }
}

// When Bob import the generated secret,
// 1. do not set key size
// 2. set incorrect key size
// 3. set incorrect key type
#[test]
fn test_ecdh_import_secret_incorrect_size_and_type() {
    let mut azihsm_provider = ProviderHandle::new();

    let curve_name = BCRYPT_ECC_CURVE_NISTP256;
    let derived_key_bitlen = AES_KEY_BIT_LENGTH_256;
    let kdf_type = BCRYPT_HKDF_ALGORITHM;
    let derived_key_encryption_mode = BCRYPT_CHAIN_MODE_CBC;
    let derived_key_length = AES_KEY_BIT_LENGTH_256 as u32;

    // Alice's parameters
    let mut alice_key = KeyHandle::new();
    let alice_imported_bob_key;
    let alice_secret;
    let alice_derived_key;

    // Bob's parameters
    let mut bob_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        // Alice Key Creation and Public Key Export
        create_and_finalize_key(
            azihsm_provider.handle(),
            &mut alice_key,
            BCRYPT_ECDH_ALGORITHM,
            Some(curve_name),
        );

        // Bob Key Creation and Public Key Export
        create_and_finalize_key(
            azihsm_provider.handle(),
            &mut bob_key,
            BCRYPT_ECDH_ALGORITHM,
            Some(curve_name),
        );

        let bob_exported_key = export_public_key(bob_key.handle());

        // Alice and Bob Public Key Exchange
        alice_imported_bob_key = import_key(
            azihsm_provider.handle(),
            &bob_exported_key,
            BlobType::PublicKeyBlob,
        );

        // Alice Secret Generation
        alice_secret = generate_secret(alice_key.handle(), alice_imported_bob_key.handle());

        // Alice derive key
        let alice_derived_key_buffer =
            derive_key(alice_secret.handle(), derived_key_bitlen, kdf_type);

        // Alice import derived key buffer to get the key handle
        alice_derived_key = import_key(
            azihsm_provider.handle(),
            &alice_derived_key_buffer,
            BlobType::AzIHsmImportKeyBlob,
        );

        // Do not set key property then finalize
        {
            let result = NCryptFinalizeKey(alice_derived_key.handle(), NCRYPT_FLAGS(0));
            assert!(result.is_err(), "result {:?}", result);
            assert_eq!(result.unwrap_err().code(), HRESULT(NTE_NOT_SUPPORTED));
        }

        // Set incorrect AES key size then finalize
        {
            set_property(
                alice_derived_key.handle(),
                Some(derived_key_encryption_mode),
                Some(AES_KEY_BIT_LENGTH_256 as u32 + 1),
            );

            let result = NCryptFinalizeKey(alice_derived_key.handle(), NCRYPT_FLAGS(0));
            assert!(result.is_err(), "result {:?}", result);
            assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BAD_LEN));
        }

        // Set incorrect AES Key encryption mode (GCM should be not supported)
        #[cfg(not(feature = "disable-fp"))]
        {
            set_property(
                alice_derived_key.handle(),
                Some(BCRYPT_CHAIN_MODE_GCM),
                Some(derived_key_length),
            );

            let result = NCryptFinalizeKey(alice_derived_key.handle(), NCRYPT_FLAGS(0));
            assert!(result.is_err(), "result {:?}", result);
            assert_eq!(result.unwrap_err().code(), HRESULT(NTE_NOT_SUPPORTED));
        }

        // Set encryption mode and key length for alice aes derived key
        set_property(
            alice_derived_key.handle(),
            Some(derived_key_encryption_mode),
            Some(derived_key_length),
        );

        // Finalize Alice's derived key
        let result = NCryptFinalizeKey(alice_derived_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());
    }
}

// Incorrect label and salt size for HKDF and KBKDF
#[test]
fn test_ecdh_kdf_incorrect_size_label_and_salt() {
    let mut azihsm_provider = ProviderHandle::new();

    let curve_name = BCRYPT_ECC_CURVE_NISTP256;
    let derived_key_bitlen = AES_KEY_BIT_LENGTH_256;

    // Alice's parameters
    let mut alice_key = KeyHandle::new();
    let alice_imported_bob_key;
    let alice_secret;

    // Bob's parameters
    let mut bob_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        // Alice Key Creation and Public Key Export
        create_and_finalize_key(
            azihsm_provider.handle(),
            &mut alice_key,
            BCRYPT_ECDH_ALGORITHM,
            Some(curve_name),
        );

        // Bob Key Creation and Public Key Export
        create_and_finalize_key(
            azihsm_provider.handle(),
            &mut bob_key,
            BCRYPT_ECDH_ALGORITHM,
            Some(curve_name),
        );

        let bob_exported_key = export_public_key(bob_key.handle());

        // Alice and Bob Public Key Exchange
        alice_imported_bob_key = import_key(
            azihsm_provider.handle(),
            &bob_exported_key,
            BlobType::PublicKeyBlob,
        );

        // Alice Secret Generation
        alice_secret = generate_secret(alice_key.handle(), alice_imported_bob_key.handle());

        // Alice derive key using HKDF, salt too long
        {
            let mut salt_data = [0u8; 256 + 1];
            let salt_bytes = "salt".as_bytes();
            salt_data[..salt_bytes.len()].copy_from_slice(salt_bytes);

            let mut info = [0u8; 16];
            let info_bytes = "label".as_bytes();
            info[..info_bytes.len()].copy_from_slice(info_bytes);

            let key_bit_length = derived_key_bitlen as u32;
            let param_buffers = [
                // digest kind
                BCryptBuffer {
                    cbBuffer: (BCRYPT_SHA256_ALGORITHM.to_string().unwrap().len()
                        * std::mem::size_of::<u16>()) as u32,
                    BufferType: KDF_HASH_ALGORITHM,
                    pvBuffer: BCRYPT_SHA256_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
                },
                // info
                BCryptBuffer {
                    cbBuffer: info_bytes.len() as u32,
                    BufferType: KDF_HKDF_INFO,
                    pvBuffer: info_bytes.as_ptr() as *mut std::ffi::c_void,
                },
                // salt
                BCryptBuffer {
                    cbBuffer: salt_data.len() as u32,
                    BufferType: KDF_HKDF_SALT,
                    pvBuffer: salt_data.as_ptr() as *mut std::ffi::c_void,
                },
                // key bit length
                BCryptBuffer {
                    cbBuffer: std::mem::size_of::<usize>() as u32,
                    BufferType: KDF_KEYBITLENGTH,
                    pvBuffer: &key_bit_length as *const u32 as *mut std::ffi::c_void,
                },
            ];

            let param_list = BCryptBufferDesc {
                ulVersion: NCRYPTBUFFER_VERSION,
                cBuffers: param_buffers.len() as u32,
                pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
            };

            let mut output_size = 0u32;
            let result = NCryptDeriveKey(
                alice_secret.handle(),
                BCRYPT_HKDF_ALGORITHM,
                Some(&param_list),
                None,
                ptr::addr_of_mut!(output_size),
                0,
            );
            assert!(result.is_ok());

            let mut derived_key_buf = vec![0u8; output_size as usize];
            let result = NCryptDeriveKey(
                alice_secret.handle(),
                BCRYPT_HKDF_ALGORITHM,
                Some(&param_list),
                Some(&mut derived_key_buf),
                ptr::addr_of_mut!(output_size),
                0,
            );
            assert!(result.is_ok());
            derived_key_buf = derived_key_buf[..output_size as usize].to_vec();

            // Alice import derived key buffer to get the key handle
            let alice_derived_key = import_key(
                azihsm_provider.handle(),
                &derived_key_buf,
                BlobType::AzIHsmImportKeyBlob,
            );

            // Set encryption mode and key length for alice aes derived key
            set_property(
                alice_derived_key.handle(),
                Some(BCRYPT_CHAIN_MODE_CBC),
                Some(256),
            );

            // Finalize Alice's derived key
            let result = NCryptFinalizeKey(alice_derived_key.handle(), NCRYPT_FLAGS(0));
            assert!(result.is_err(), "result {:?}", result);
            assert_eq!(result.unwrap_err().code(), HRESULT(E_INVALIDARG));
        }

        // Alice derive key using HKDF, salt ok to be too short
        {
            let mut salt_data = [0u8; 64 - 1];
            let salt_bytes = "salt".as_bytes();
            salt_data[..salt_bytes.len()].copy_from_slice(salt_bytes);

            let mut info = [0u8; 16];
            let info_bytes = "label".as_bytes();
            info[..info_bytes.len()].copy_from_slice(info_bytes);

            let key_bit_length = derived_key_bitlen as u32;
            let param_buffers = [
                // digest kind
                BCryptBuffer {
                    cbBuffer: (BCRYPT_SHA256_ALGORITHM.to_string().unwrap().len()
                        * std::mem::size_of::<u16>()) as u32,
                    BufferType: KDF_HASH_ALGORITHM,
                    pvBuffer: BCRYPT_SHA256_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
                },
                // info
                BCryptBuffer {
                    cbBuffer: info_bytes.len() as u32,
                    BufferType: KDF_HKDF_INFO,
                    pvBuffer: info_bytes.as_ptr() as *mut std::ffi::c_void,
                },
                // salt
                BCryptBuffer {
                    cbBuffer: salt_data.len() as u32,
                    BufferType: KDF_HKDF_SALT,
                    pvBuffer: salt_data.as_ptr() as *mut std::ffi::c_void,
                },
                // key bit length
                BCryptBuffer {
                    cbBuffer: std::mem::size_of::<usize>() as u32,
                    BufferType: KDF_KEYBITLENGTH,
                    pvBuffer: &key_bit_length as *const u32 as *mut std::ffi::c_void,
                },
            ];

            let param_list = BCryptBufferDesc {
                ulVersion: NCRYPTBUFFER_VERSION,
                cBuffers: param_buffers.len() as u32,
                pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
            };

            let mut output_size = 0u32;
            let result = NCryptDeriveKey(
                alice_secret.handle(),
                BCRYPT_HKDF_ALGORITHM,
                Some(&param_list),
                None,
                ptr::addr_of_mut!(output_size),
                0,
            );
            assert!(result.is_ok());

            let mut derived_key_buf = vec![0u8; output_size as usize];
            let result = NCryptDeriveKey(
                alice_secret.handle(),
                BCRYPT_HKDF_ALGORITHM,
                Some(&param_list),
                Some(&mut derived_key_buf),
                ptr::addr_of_mut!(output_size),
                0,
            );
            assert!(result.is_ok());
            derived_key_buf = derived_key_buf[..output_size as usize].to_vec();

            // Alice import derived key buffer to get the key handle
            let alice_derived_key = import_key(
                azihsm_provider.handle(),
                &derived_key_buf,
                BlobType::AzIHsmImportKeyBlob,
            );

            // Set encryption mode and key length for alice aes derived key
            set_property(
                alice_derived_key.handle(),
                Some(BCRYPT_CHAIN_MODE_CBC),
                Some(256),
            );

            // Finalize Alice's derived key
            let result = NCryptFinalizeKey(alice_derived_key.handle(), NCRYPT_FLAGS(0));
            assert!(result.is_ok());
        }

        // Alice derive key using HKDF, info too long
        {
            let mut salt_data = [0u8; 64];
            let salt_bytes = "salt".as_bytes();
            salt_data[..salt_bytes.len()].copy_from_slice(salt_bytes);

            let mut info = [0u8; 16 + 1];
            let info_bytes = "label".as_bytes();
            info[..info_bytes.len()].copy_from_slice(info_bytes);

            let key_bit_length = derived_key_bitlen as u32;
            let param_buffers = [
                // digest kind
                BCryptBuffer {
                    cbBuffer: (BCRYPT_SHA256_ALGORITHM.to_string().unwrap().len()
                        * std::mem::size_of::<u16>()) as u32,
                    BufferType: KDF_HASH_ALGORITHM,
                    pvBuffer: BCRYPT_SHA256_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
                },
                // info
                BCryptBuffer {
                    cbBuffer: info.len() as u32,
                    BufferType: KDF_HKDF_INFO,
                    pvBuffer: info.as_ptr() as *mut std::ffi::c_void,
                },
                // salt
                BCryptBuffer {
                    cbBuffer: salt_data.len() as u32,
                    BufferType: KDF_HKDF_SALT,
                    pvBuffer: salt_data.as_ptr() as *mut std::ffi::c_void,
                },
                // key bit length
                BCryptBuffer {
                    cbBuffer: std::mem::size_of::<usize>() as u32,
                    BufferType: KDF_KEYBITLENGTH,
                    pvBuffer: &key_bit_length as *const u32 as *mut std::ffi::c_void,
                },
            ];

            let param_list = BCryptBufferDesc {
                ulVersion: NCRYPTBUFFER_VERSION,
                cBuffers: param_buffers.len() as u32,
                pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
            };

            let mut output_size = 0u32;
            let result = NCryptDeriveKey(
                alice_secret.handle(),
                BCRYPT_HKDF_ALGORITHM,
                Some(&param_list),
                None,
                ptr::addr_of_mut!(output_size),
                0,
            );
            assert!(result.is_ok());

            let mut derived_key_buf = vec![0u8; output_size as usize];
            let result = NCryptDeriveKey(
                alice_secret.handle(),
                BCRYPT_HKDF_ALGORITHM,
                Some(&param_list),
                Some(&mut derived_key_buf),
                ptr::addr_of_mut!(output_size),
                0,
            );
            assert!(result.is_ok());
            derived_key_buf = derived_key_buf[..output_size as usize].to_vec();

            // Alice import derived key buffer to get the key handle
            let alice_derived_key = import_key(
                azihsm_provider.handle(),
                &derived_key_buf,
                BlobType::AzIHsmImportKeyBlob,
            );

            // Set encryption mode and key length for alice aes derived key
            set_property(
                alice_derived_key.handle(),
                Some(BCRYPT_CHAIN_MODE_CBC),
                Some(256),
            );

            // Finalize Alice's derived key
            let result = NCryptFinalizeKey(alice_derived_key.handle(), NCRYPT_FLAGS(0));
            assert!(result.is_err(), "result {:?}", result);
            assert_eq!(result.unwrap_err().code(), HRESULT(E_INVALIDARG));
        }

        // Alice derive key using HKDF, info ok to be too short
        {
            let mut salt_data = [0u8; 64];
            let salt_bytes = "salt".as_bytes();
            salt_data[..salt_bytes.len()].copy_from_slice(salt_bytes);

            let mut info = [0u8; 16 - 1];
            let info_bytes = "label".as_bytes();
            info[..info_bytes.len()].copy_from_slice(info_bytes);

            let key_bit_length = derived_key_bitlen as u32;
            let param_buffers = [
                // digest kind
                BCryptBuffer {
                    cbBuffer: (BCRYPT_SHA256_ALGORITHM.to_string().unwrap().len()
                        * std::mem::size_of::<u16>()) as u32,
                    BufferType: KDF_HASH_ALGORITHM,
                    pvBuffer: BCRYPT_SHA256_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
                },
                // info
                BCryptBuffer {
                    cbBuffer: info.len() as u32,
                    BufferType: KDF_HKDF_INFO,
                    pvBuffer: info.as_ptr() as *mut std::ffi::c_void,
                },
                // salt
                BCryptBuffer {
                    cbBuffer: salt_data.len() as u32,
                    BufferType: KDF_HKDF_SALT,
                    pvBuffer: salt_data.as_ptr() as *mut std::ffi::c_void,
                },
                // key bit length
                BCryptBuffer {
                    cbBuffer: std::mem::size_of::<usize>() as u32,
                    BufferType: KDF_KEYBITLENGTH,
                    pvBuffer: &key_bit_length as *const u32 as *mut std::ffi::c_void,
                },
            ];

            let param_list = BCryptBufferDesc {
                ulVersion: NCRYPTBUFFER_VERSION,
                cBuffers: param_buffers.len() as u32,
                pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
            };

            let mut output_size = 0u32;
            let result = NCryptDeriveKey(
                alice_secret.handle(),
                BCRYPT_HKDF_ALGORITHM,
                Some(&param_list),
                None,
                ptr::addr_of_mut!(output_size),
                0,
            );
            assert!(result.is_ok());

            let mut derived_key_buf = vec![0u8; output_size as usize];
            let result = NCryptDeriveKey(
                alice_secret.handle(),
                BCRYPT_HKDF_ALGORITHM,
                Some(&param_list),
                Some(&mut derived_key_buf),
                ptr::addr_of_mut!(output_size),
                0,
            );
            assert!(result.is_ok());
            derived_key_buf = derived_key_buf[..output_size as usize].to_vec();

            // Alice import derived key buffer to get the key handle
            let alice_derived_key = import_key(
                azihsm_provider.handle(),
                &derived_key_buf,
                BlobType::AzIHsmImportKeyBlob,
            );

            // Set encryption mode and key length for alice aes derived key
            set_property(
                alice_derived_key.handle(),
                Some(BCRYPT_CHAIN_MODE_CBC),
                Some(256),
            );

            // Finalize Alice's derived key
            let result = NCryptFinalizeKey(alice_derived_key.handle(), NCRYPT_FLAGS(0));
            assert!(result.is_ok());
        }
    }
}

fn equals(lhs: PCWSTR, rhs: PCWSTR) -> bool {
    unsafe {
        let lhs_str = WideCString::from_ptr_str(lhs.as_ptr());
        let rhs_str = WideCString::from_ptr_str(rhs.as_ptr());
        lhs_str == rhs_str
    }
}

unsafe fn derive_key(
    secret_handle: NCRYPT_SECRET_HANDLE,
    derived_key_bitlen: usize,
    kdf: PCWSTR,
) -> Vec<u8> {
    if equals(kdf, BCRYPT_HKDF_ALGORITHM) {
        return hkdf_derive(secret_handle, derived_key_bitlen);
    } else if equals(kdf, BCRYPT_SP800108_CTR_HMAC_ALGORITHM) {
        return kbkdf_derive(secret_handle, derived_key_bitlen);
    }

    unreachable!("Error: Unsupported KDF type {:?}", kdf);
}

unsafe fn hkdf_derive(secret_handle: NCRYPT_SECRET_HANDLE, derived_key_bitlen: usize) -> Vec<u8> {
    let mut salt_data = [0u8; 64];
    let salt_bytes = "salt".as_bytes();
    salt_data[..salt_bytes.len()].copy_from_slice(salt_bytes);

    let mut info = [0u8; 16];
    let info_bytes = "label".as_bytes();
    info[..info_bytes.len()].copy_from_slice(info_bytes);

    let key_bit_length = derived_key_bitlen as u32;
    let param_buffers = [
        // digest kind
        BCryptBuffer {
            cbBuffer: (BCRYPT_SHA256_ALGORITHM.to_string().unwrap().len()
                * std::mem::size_of::<u16>()) as u32,
            BufferType: KDF_HASH_ALGORITHM,
            pvBuffer: BCRYPT_SHA256_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
        },
        // info
        BCryptBuffer {
            cbBuffer: info.len() as u32,
            BufferType: KDF_HKDF_INFO,
            pvBuffer: info.as_ptr() as *mut std::ffi::c_void,
        },
        // salt
        BCryptBuffer {
            cbBuffer: salt_data.len() as u32,
            BufferType: KDF_HKDF_SALT,
            pvBuffer: salt_data.as_ptr() as *mut std::ffi::c_void,
        },
        // key bit length
        BCryptBuffer {
            cbBuffer: std::mem::size_of::<usize>() as u32,
            BufferType: KDF_KEYBITLENGTH,
            pvBuffer: &key_bit_length as *const u32 as *mut std::ffi::c_void,
        },
    ];

    let param_list = BCryptBufferDesc {
        ulVersion: NCRYPTBUFFER_VERSION,
        cBuffers: param_buffers.len() as u32,
        pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
    };

    let mut output_size = 0u32;
    let result = NCryptDeriveKey(
        secret_handle,
        BCRYPT_HKDF_ALGORITHM,
        Some(&param_list),
        None,
        ptr::addr_of_mut!(output_size),
        0,
    );
    assert!(result.is_ok());

    let mut derived_key_buf = vec![0u8; output_size as usize];
    let result = NCryptDeriveKey(
        secret_handle,
        BCRYPT_HKDF_ALGORITHM,
        Some(&param_list),
        Some(&mut derived_key_buf),
        ptr::addr_of_mut!(output_size),
        0,
    );
    assert!(result.is_ok(), "Unexpected failure: {:?}", result);
    derived_key_buf = derived_key_buf[..output_size as usize].to_vec();
    println!("HKDF Key buffer: {:?}", derived_key_buf);
    derived_key_buf
}

unsafe fn kbkdf_derive(secret_handle: NCRYPT_SECRET_HANDLE, derived_key_bitlen: usize) -> Vec<u8> {
    let mut label_data = [0u8; 16];
    let label_bytes = "label".as_bytes();
    label_data[..label_bytes.len()].copy_from_slice(label_bytes);

    let mut context = [0u8; 16];
    let context_bytes = "context".as_bytes();
    context[..context_bytes.len()].copy_from_slice(context_bytes);

    let key_bit_length = derived_key_bitlen as u32;
    let param_buffers = [
        // digest kind
        BCryptBuffer {
            cbBuffer: (BCRYPT_SHA256_ALGORITHM.to_string().unwrap().len()
                * std::mem::size_of::<u16>()) as u32,
            BufferType: KDF_HASH_ALGORITHM,
            pvBuffer: BCRYPT_SHA256_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
        },
        // context
        BCryptBuffer {
            cbBuffer: context.len() as u32,
            BufferType: KDF_CONTEXT,
            pvBuffer: context.as_ptr() as *mut std::ffi::c_void,
        },
        // label
        BCryptBuffer {
            cbBuffer: label_data.len() as u32,
            BufferType: KDF_LABEL,
            pvBuffer: label_data.as_ptr() as *mut std::ffi::c_void,
        },
        // key bit length
        BCryptBuffer {
            cbBuffer: std::mem::size_of::<usize>() as u32,
            BufferType: KDF_KEYBITLENGTH,
            pvBuffer: &key_bit_length as *const u32 as *mut std::ffi::c_void,
        },
    ];

    let param_list = BCryptBufferDesc {
        ulVersion: NCRYPTBUFFER_VERSION,
        cBuffers: param_buffers.len() as u32,
        pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
    };

    let mut output_size = 0u32;
    let result = NCryptDeriveKey(
        secret_handle,
        BCRYPT_SP800108_CTR_HMAC_ALGORITHM,
        Some(&param_list),
        None,
        ptr::addr_of_mut!(output_size),
        0,
    );
    assert!(result.is_ok());

    let mut derived_key_buf = vec![0u8; output_size as usize];
    let result = NCryptDeriveKey(
        secret_handle,
        BCRYPT_SP800108_CTR_HMAC_ALGORITHM,
        Some(&param_list),
        Some(&mut derived_key_buf),
        ptr::addr_of_mut!(output_size),
        0,
    );
    assert!(result.is_ok());
    derived_key_buf = derived_key_buf[..output_size as usize].to_vec();
    println!("KBKDF Key buffer: {:?}", derived_key_buf);
    derived_key_buf
}

#[allow(unused_assignments)]
fn test_derive_key_inner(
    curve_name: PCWSTR,
    derived_key_bitlen: usize,
    kdf_type: PCWSTR,
    derived_key_encryption_mode: PCWSTR,
    derived_key_length: u32,
) {
    let mut azihsm_provider = ProviderHandle::new();

    // Alice's parameters
    let mut alice_key = KeyHandle::new();
    let mut alice_imported_bob_key = KeyHandle::new();
    let mut alice_secret = SecretHandle::new();
    let mut alice_derived_key = KeyHandle::new();

    // Bob's parameters
    let mut bob_key = KeyHandle::new();
    let mut bob_imported_alice_key = KeyHandle::new();
    let mut bob_secret = SecretHandle::new();
    let mut bob_derived_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        // Alice Key Creation and Public Key Export
        create_and_finalize_key(
            azihsm_provider.handle(),
            &mut alice_key,
            BCRYPT_ECDH_ALGORITHM,
            Some(curve_name),
        );

        let alice_exported_key = export_public_key(alice_key.handle());

        // Bob Key Creation and Public Key Export
        create_and_finalize_key(
            azihsm_provider.handle(),
            &mut bob_key,
            BCRYPT_ECDH_ALGORITHM,
            Some(curve_name),
        );

        let bob_exported_key = export_public_key(bob_key.handle());

        // Alice and Bob Public Key Exchange
        alice_imported_bob_key = import_key(
            azihsm_provider.handle(),
            &bob_exported_key,
            BlobType::PublicKeyBlob,
        );

        bob_imported_alice_key = import_key(
            azihsm_provider.handle(),
            &alice_exported_key,
            BlobType::PublicKeyBlob,
        );

        // Alice and Bob Secret Generation
        alice_secret = generate_secret(alice_key.handle(), alice_imported_bob_key.handle());
        bob_secret = generate_secret(bob_key.handle(), bob_imported_alice_key.handle());

        // Alice derive key
        let alice_derived_key_buffer =
            derive_key(alice_secret.handle(), derived_key_bitlen, kdf_type);

        // Alice import derived key buffer to get the key handle
        alice_derived_key = import_key(
            azihsm_provider.handle(),
            &alice_derived_key_buffer,
            BlobType::AzIHsmImportKeyBlob,
        );

        // Set encryption mode and key length for alice aes derived key
        set_property(
            alice_derived_key.handle(),
            Some(derived_key_encryption_mode),
            Some(derived_key_length),
        );

        // Finalize Alice's derived key
        let result = NCryptFinalizeKey(alice_derived_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Bob Derive key using bob_secret
        let bob_derived_key_buffer = derive_key(bob_secret.handle(), derived_key_bitlen, kdf_type);

        // Bob import bob derived key buffer to get the key handle
        bob_derived_key = import_key(
            azihsm_provider.handle(),
            &bob_derived_key_buffer,
            BlobType::AzIHsmImportKeyBlob,
        );

        // Set encryption mode and key length for bob aes derived key
        set_property(
            bob_derived_key.handle(),
            Some(derived_key_encryption_mode),
            Some(derived_key_length),
        );

        // Finalize the Bob's derived key
        let result = NCryptFinalizeKey(bob_derived_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // use alice key for encrypting plain text and bob key
        // for decrypting and compare the data.
        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).unwrap();
        let mut iv_orig = iv;

        let mut padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: iv.as_mut_ptr(),
            cbIV: iv.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        let result = NCryptEncrypt(
            alice_derived_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        let mut decrypted = [0u8; 128];
        let mut decrypted_len = 0u32;
        padding_info.pbIV = iv_orig.as_mut_ptr();

        let result = NCryptDecrypt(
            bob_derived_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext, decrypted);
    }
}

unsafe fn create_and_finalize_key(
    azihsm_provider: NCRYPT_PROV_HANDLE,
    key_handle: &mut KeyHandle,
    algorithm: PCWSTR,
    curve: Option<PCWSTR>,
) {
    let result = NCryptCreatePersistedKey(
        azihsm_provider,
        key_handle.as_mut(),
        algorithm,
        None,
        CERT_KEY_SPEC(0),
        NCRYPT_FLAGS(0),
    );
    assert!(result.is_ok());

    if algorithm == BCRYPT_ECDH_ALGORITHM {
        if let Some(curve_name) = curve {
            let curve_type = std::slice::from_raw_parts(
                curve_name.as_ptr().cast::<u8>(),
                curve_name.to_string().unwrap().len() * std::mem::size_of::<u16>(),
            );

            let result = NCryptSetProperty(
                key_handle.handle(),
                NCRYPT_ECC_CURVE_NAME_PROPERTY,
                curve_type,
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_ok());
        }
    }

    let result = NCryptFinalizeKey(key_handle.handle(), NCRYPT_FLAGS(0));
    assert!(result.is_ok());
}

unsafe fn export_public_key(key_handle: NCRYPT_KEY_HANDLE) -> Vec<u8> {
    let mut export_buffer_size = 0u32;
    let result = NCryptExportKey(
        key_handle,
        None,
        NCRYPT_OPAQUETRANSPORT_BLOB,
        None,
        None,
        ptr::addr_of_mut!(export_buffer_size),
        NCRYPT_FLAGS(0),
    );
    assert!(result.is_ok());
    assert!(
        export_buffer_size > 0,
        "Expected non-zero export buffer size, but found {}",
        export_buffer_size
    );

    let mut export_buffer = vec![0u8; export_buffer_size as usize];
    let result = NCryptExportKey(
        key_handle,
        None,
        NCRYPT_OPAQUETRANSPORT_BLOB,
        None,
        Some(&mut export_buffer),
        ptr::addr_of_mut!(export_buffer_size),
        NCRYPT_FLAGS(0),
    );
    assert!(result.is_ok());
    assert!(!export_buffer.is_empty(), "Export buffer is empty!");

    export_buffer[..export_buffer_size as usize].to_vec()
}

unsafe fn import_key(
    azihsm_provider: NCRYPT_PROV_HANDLE,
    key_blob: &[u8],
    blob_type: BlobType,
) -> KeyHandle {
    let mut imported_key_handle = KeyHandle::new();
    let result = match blob_type {
        BlobType::PublicKeyBlob => NCryptImportKey(
            azihsm_provider,
            NCRYPT_KEY_HANDLE(0),
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            imported_key_handle.as_mut(),
            key_blob,
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        ),
        BlobType::AzIHsmImportKeyBlob => NCryptImportKey(
            azihsm_provider,
            NCRYPT_KEY_HANDLE(0),
            AZIHSM_DERIVED_KEY_IMPORT_BLOB,
            None,
            imported_key_handle.as_mut(),
            key_blob,
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        ),
    };
    assert!(result.is_ok());
    imported_key_handle
}

unsafe fn set_property(
    key_handle: NCRYPT_KEY_HANDLE,
    encryption_mode_name: Option<PCWSTR>,
    key_length: Option<u32>,
) {
    // Set encryption mode if provided
    if let Some(mode_name) = encryption_mode_name {
        let encryption_mode = std::slice::from_raw_parts(
            mode_name.as_ptr().cast::<u8>(),
            mode_name.to_string().unwrap().len() * std::mem::size_of::<u16>(),
        );
        let result = NCryptSetProperty(
            key_handle,
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok(), "Failed to set encryption mode property");
    }

    // Set key length if provided
    if let Some(length) = key_length {
        let length_bytes = length.to_le_bytes();
        let result = NCryptSetProperty(
            key_handle,
            NCRYPT_LENGTH_PROPERTY,
            &length_bytes,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok(), "Failed to set key length property");
    }
}

unsafe fn generate_secret(
    key_handle: NCRYPT_KEY_HANDLE,
    imported_key_handle: NCRYPT_KEY_HANDLE,
) -> SecretHandle {
    let mut secret_handle = SecretHandle::new();

    let result = NCryptSecretAgreement(
        key_handle,
        imported_key_handle,
        secret_handle.as_mut(),
        NCRYPT_FLAGS(0),
    );
    assert!(result.is_ok());

    secret_handle
}

#[test]
fn test_import_derived_key_without_finalize_flag() {
    let curve_name = BCRYPT_ECC_CURVE_NISTP256;
    let derived_key_bitlen = AES_KEY_BIT_LENGTH_128;
    let kdf_type = BCRYPT_HKDF_ALGORITHM;
    let derived_key_encryption_mode = BCRYPT_CHAIN_MODE_CBC;
    let derived_key_length = AES_KEY_BIT_LENGTH_128 as u32;

    let mut azihsm_provider = ProviderHandle::new();

    // Alice's parameters
    let mut alice_key = KeyHandle::new();
    let mut alice_derived_key = KeyHandle::new();

    // Bob's parameters
    let mut bob_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        // Alice Key Creation and Public Key Export
        create_and_finalize_key(
            azihsm_provider.handle(),
            &mut alice_key,
            BCRYPT_ECDH_ALGORITHM,
            Some(curve_name),
        );

        let alice_exported_key = export_public_key(alice_key.handle());

        // Bob Key Creation and Public Key Export
        create_and_finalize_key(
            azihsm_provider.handle(),
            &mut bob_key,
            BCRYPT_ECDH_ALGORITHM,
            Some(curve_name),
        );

        let bob_exported_key = export_public_key(bob_key.handle());

        // Alice and Bob Public Key Exchange
        let alice_imported_bob_key = import_key(
            azihsm_provider.handle(),
            &bob_exported_key,
            BlobType::PublicKeyBlob,
        );

        let bob_imported_alice_key = import_key(
            azihsm_provider.handle(),
            &alice_exported_key,
            BlobType::PublicKeyBlob,
        );

        // Alice and Bob Secret Generation
        let alice_secret = generate_secret(alice_key.handle(), alice_imported_bob_key.handle());
        let bob_secret = generate_secret(bob_key.handle(), bob_imported_alice_key.handle());

        // Alice derive key
        let alice_derived_key_buffer =
            derive_key(alice_secret.handle(), derived_key_bitlen, kdf_type);

        // Alice import derived key buffer to get the key handle
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            NCRYPT_KEY_HANDLE(0),
            AZIHSM_DERIVED_KEY_IMPORT_BLOB,
            None,
            alice_derived_key.as_mut(),
            &alice_derived_key_buffer,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Bob Derive key using bob_secret
        let bob_derived_key_buffer = derive_key(bob_secret.handle(), derived_key_bitlen, kdf_type);

        // Bob import bob derived key buffer to get the key handle
        let bob_derived_key = import_key(
            azihsm_provider.handle(),
            &bob_derived_key_buffer,
            BlobType::AzIHsmImportKeyBlob,
        );

        // Set encryption mode and key length for bob aes derived key
        set_property(
            bob_derived_key.handle(),
            Some(derived_key_encryption_mode),
            Some(derived_key_length),
        );

        // Finalize the Bob's derived key
        let result = NCryptFinalizeKey(bob_derived_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // use alice key for encrypting plain text and bob key
        // for decrypting and compare the data.
        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).unwrap();
        let mut iv_orig = iv;

        let mut padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: iv.as_mut_ptr(),
            cbIV: iv.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        // Encrypt with Alice's derived key
        let result = NCryptEncrypt(
            alice_derived_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        let mut decrypted = [0u8; 128];
        let mut decrypted_len = 0u32;
        padding_info.pbIV = iv_orig.as_mut_ptr();

        // Decrypt with Bob's derived key
        let result = NCryptDecrypt(
            bob_derived_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext, decrypted);
    }
}
