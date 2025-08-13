// Copyright (C) Microsoft Corporation. All rights reserved.
mod common;
use std::mem::size_of;
use std::ptr;

use openssl::rand::rand_bytes;
use winapi::shared::winerror::NTE_BAD_FLAGS;
use winapi::shared::winerror::NTE_BUFFER_TOO_SMALL;
use windows::core::HRESULT;
use windows::Win32::Security::Cryptography::*;

use crate::common::*;

#[test]
fn test_ecdsa_p256_sign_verify_valid_digest_sizes() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let curve_type = std::slice::from_raw_parts(
            BCRYPT_ECC_CURVE_NISTP256.as_ptr().cast::<u8>(),
            BCRYPT_ECC_CURVE_NISTP256.to_string().unwrap().len() * size_of::<u16>(),
        );
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_ECC_CURVE_NAME_PROPERTY,
            curve_type,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let valid_digest_sizes = [20, 32];
        for &digest_size in &valid_digest_sizes {
            let mut digest = vec![0u8; digest_size];
            rand_bytes(&mut digest).unwrap();
            let mut signature_size = 0u32;
            let result = NCryptSignHash(
                azihsm_key.handle(),
                None,
                &digest,
                None,
                ptr::addr_of_mut!(signature_size),
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_ok());
            assert_eq!(signature_size, 64);

            let mut signature = vec![0u8; signature_size as usize];
            let result = NCryptSignHash(
                azihsm_key.handle(),
                None,
                &digest,
                Some(&mut signature),
                ptr::addr_of_mut!(signature_size),
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_ok());

            let result = NCryptVerifySignature(
                azihsm_key.handle(),
                None,
                &digest,
                &signature,
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_ok());
        }
    }
}

#[test]
fn test_ecdsa_p256_sign_unsupported_digest_sizes() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let curve_type = std::slice::from_raw_parts(
            BCRYPT_ECC_CURVE_NISTP256.as_ptr().cast::<u8>(),
            BCRYPT_ECC_CURVE_NISTP256.to_string().unwrap().len() * size_of::<u16>(),
        );
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_ECC_CURVE_NAME_PROPERTY,
            curve_type,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // ECDSA P-256 only supports signing digest of sizes 20 (SHA-1) and 32 (SHA-256) bytes.
        // Because the digest size must be less than the curve size
        let digest_sizes = [48, 64];
        for &digest_size in &digest_sizes {
            let mut digest = vec![0u8; digest_size];
            rand_bytes(&mut digest).unwrap();
            let mut signature_size = 0u32;
            let result = NCryptSignHash(
                azihsm_key.handle(),
                None,
                &digest,
                None,
                ptr::addr_of_mut!(signature_size),
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_err(), "result {:?}", result);
        }
    }
}

#[test]
fn test_ecdsa_p256_sign_invalid_digest_sizes() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let curve_type = std::slice::from_raw_parts(
            BCRYPT_ECC_CURVE_NISTP256.as_ptr().cast::<u8>(),
            BCRYPT_ECC_CURVE_NISTP256.to_string().unwrap().len() * size_of::<u16>(),
        );
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_ECC_CURVE_NAME_PROPERTY,
            curve_type,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let invalid_digest_sizes = [25, 30]; // Invalid digest sizes
        for &digest_size in &invalid_digest_sizes {
            let mut digest = vec![0u8; digest_size];
            rand_bytes(&mut digest).unwrap();
            let mut signature_size = 0u32;
            let result = NCryptSignHash(
                azihsm_key.handle(),
                None,
                &digest,
                None,
                ptr::addr_of_mut!(signature_size),
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_err(), "result {:?}", result);
        }
    }
}

#[test]
fn test_ecdsa_p384_sign_verify_valid_digest_sizes() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_P384_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let valid_digest_sizes = [20, 32, 48];
        for &digest_size in &valid_digest_sizes {
            let mut digest = vec![0u8; digest_size];
            rand_bytes(&mut digest).unwrap();
            let mut signature_size = 0u32;
            let result = NCryptSignHash(
                azihsm_key.handle(),
                None,
                &digest,
                None,
                ptr::addr_of_mut!(signature_size),
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_ok());
            assert_eq!(signature_size, 96);

            let mut signature = vec![0u8; signature_size as usize];
            let result = NCryptSignHash(
                azihsm_key.handle(),
                None,
                &digest,
                Some(&mut signature),
                ptr::addr_of_mut!(signature_size),
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_ok());

            let result = NCryptVerifySignature(
                azihsm_key.handle(),
                None,
                &digest,
                &signature,
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_ok());
        }
    }
}

#[test]
fn test_ecdsa_p384_sign_unsupported_digest_sizes() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_P384_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // ECDSA P-384 only supports signing digest of sizes 20 (SHA-1), 32 (SHA-256) and 48 (SHA-384) bytes.
        // Because the digest size must be less than the curve size
        let digest_sizes = [64];
        for &digest_size in &digest_sizes {
            let mut digest = vec![0u8; digest_size];
            rand_bytes(&mut digest).unwrap();
            let mut signature_size = 0u32;
            let result = NCryptSignHash(
                azihsm_key.handle(),
                None,
                &digest,
                None,
                ptr::addr_of_mut!(signature_size),
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_err(), "result {:?}", result);
        }
    }
}

#[test]
fn test_ecdsa_p384_sign_invalid_digest_sizes() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_P384_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let digest_sizes = [25, 50]; // Invalid digest sizes
        for &digest_size in &digest_sizes {
            let mut digest = vec![0u8; digest_size];
            rand_bytes(&mut digest).unwrap();
            let mut signature_size = 0u32;
            let result = NCryptSignHash(
                azihsm_key.handle(),
                None,
                &digest,
                None,
                ptr::addr_of_mut!(signature_size),
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_err(), "result {:?}", result);
        }
    }
}

#[test]
fn test_ecdsa_p521_sign_verify_valid_digest_sizes() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_P521_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Test with all valid digest sizes
        let valid_digest_sizes = [20, 32, 48, 64];

        for &digest_size in &valid_digest_sizes {
            let mut digest = vec![0u8; digest_size];
            rand_bytes(&mut digest).unwrap();
            let mut signature_size = 0u32;
            let result = NCryptSignHash(
                azihsm_key.handle(),
                None,
                &digest,
                None,
                ptr::addr_of_mut!(signature_size),
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_ok());
            assert_eq!(signature_size, 132);

            let mut signature = vec![0u8; signature_size as usize];
            let result = NCryptSignHash(
                azihsm_key.handle(),
                None,
                &digest,
                Some(&mut signature),
                ptr::addr_of_mut!(signature_size),
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_ok());

            let result = NCryptVerifySignature(
                azihsm_key.handle(),
                None,
                &digest,
                &signature,
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_ok());
        }
    }
}

#[test]
fn test_ecdsa_p521_sign_invalid_digest_sizes() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_P521_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let valid_digest_sizes = [22, 35, 50, 100]; // Invalid digest sizes

        for &digest_size in &valid_digest_sizes {
            let mut digest = vec![0u8; digest_size];
            rand_bytes(&mut digest).unwrap();
            let mut signature_size = 0u32;
            let result = NCryptSignHash(
                azihsm_key.handle(),
                None,
                &digest,
                None,
                ptr::addr_of_mut!(signature_size),
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_err(), "result {:?}", result);
        }
    }
}

#[test]
fn test_ecdsa_sign_buffer_lt_required() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_P521_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut digest = [0u8; 32];
        rand_bytes(&mut digest).unwrap();

        let mut signature_size = 0u32;
        let result = NCryptSignHash(
            azihsm_key.handle(),
            None,
            &digest,
            None,
            ptr::addr_of_mut!(signature_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        assert_eq!(signature_size, 132);

        // Subtract 1 from the required buffer size
        let mut signature = vec![0u8; (signature_size - 1) as usize];
        let result = NCryptSignHash(
            azihsm_key.handle(),
            None,
            &digest,
            Some(&mut signature),
            ptr::addr_of_mut!(signature_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BUFFER_TOO_SMALL));
    }
}

#[test]
fn test_ecdsa_sign_buffer_gt_required() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_P521_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut digest = [0u8; 32];
        rand_bytes(&mut digest).unwrap();

        let mut signature_size = 0u32;
        let result = NCryptSignHash(
            azihsm_key.handle(),
            None,
            &digest,
            None,
            ptr::addr_of_mut!(signature_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        assert_eq!(signature_size, 132);

        // Add 1 from the required buffer size
        let mut signature = vec![0u8; (signature_size + 1) as usize];
        let result = NCryptSignHash(
            azihsm_key.handle(),
            None,
            &digest,
            Some(&mut signature),
            ptr::addr_of_mut!(signature_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        assert_eq!(signature_size, 132);

        let result = NCryptVerifySignature(
            azihsm_key.handle(),
            None,
            &digest,
            &signature[..signature_size as usize],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
    }
}

#[test]
fn test_ecdsa_sign_invalid_flag() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let curve_type = std::slice::from_raw_parts(
            BCRYPT_ECC_CURVE_NISTP256.as_ptr().cast::<u8>(),
            BCRYPT_ECC_CURVE_NISTP256.to_string().unwrap().len() * size_of::<u16>(),
        );
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_ECC_CURVE_NAME_PROPERTY,
            curve_type,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut digest = [0u8; 32];
        rand_bytes(&mut digest).unwrap();
        let mut signature_size = 0u32;
        let result = NCryptSignHash(
            azihsm_key.handle(),
            None,
            &digest,
            None,
            ptr::addr_of_mut!(signature_size),
            NCRYPT_PAD_PKCS1_FLAG, // Invalid flag
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BAD_FLAGS));
    }
}

#[test]
fn test_ecdsa_verify_invalid_flag() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let curve_type = std::slice::from_raw_parts(
            BCRYPT_ECC_CURVE_NISTP256.as_ptr().cast::<u8>(),
            BCRYPT_ECC_CURVE_NISTP256.to_string().unwrap().len() * size_of::<u16>(),
        );
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_ECC_CURVE_NAME_PROPERTY,
            curve_type,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut digest = [0u8; 32];
        rand_bytes(&mut digest).unwrap();
        let mut signature_size = 0u32;
        let result = NCryptSignHash(
            azihsm_key.handle(),
            None,
            &digest,
            None,
            ptr::addr_of_mut!(signature_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        assert_eq!(signature_size, 64);

        let mut signature = vec![0u8; signature_size as usize];
        let result = NCryptSignHash(
            azihsm_key.handle(),
            None,
            &digest,
            Some(&mut signature),
            ptr::addr_of_mut!(signature_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptVerifySignature(
            azihsm_key.handle(),
            None,
            &digest,
            &signature,
            NCRYPT_PAD_PKCS1_FLAG,
        ); // Invalid flag
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BAD_FLAGS));
    }
}

#[test]
fn test_ecdsa_invalid_curve_type() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let invalid_curve_type = std::slice::from_raw_parts(
            b"INVALID_CURVE".as_ptr().cast::<u8>(),
            b"INVALID_CURVE".len(),
        );
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_ECC_CURVE_NAME_PROPERTY,
            invalid_curve_type,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_err(), "result {:?}", result);
    }
}

#[test]
fn test_ecdsa_sign_empty_digest() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let curve_type = std::slice::from_raw_parts(
            BCRYPT_ECC_CURVE_NISTP256.as_ptr().cast::<u8>(),
            BCRYPT_ECC_CURVE_NISTP256.to_string().unwrap().len() * size_of::<u16>(),
        );
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_ECC_CURVE_NAME_PROPERTY,
            curve_type,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut signature_size = 0u32;
        let result = NCryptSignHash(
            azihsm_key.handle(),
            None,
            &[],
            None,
            ptr::addr_of_mut!(signature_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_err(), "result {:?}", result);
    }
}

#[test]
fn test_ecdsa_verify_modified_signature() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let curve_type = std::slice::from_raw_parts(
            BCRYPT_ECC_CURVE_NISTP256.as_ptr().cast::<u8>(),
            BCRYPT_ECC_CURVE_NISTP256.to_string().unwrap().len() * size_of::<u16>(),
        );
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_ECC_CURVE_NAME_PROPERTY,
            curve_type,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut digest = [0u8; 32];
        rand_bytes(&mut digest).unwrap();
        let mut signature_size = 0u32;
        let result = NCryptSignHash(
            azihsm_key.handle(),
            None,
            &digest,
            None,
            ptr::addr_of_mut!(signature_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let mut signature = vec![0u8; signature_size as usize];
        let result = NCryptSignHash(
            azihsm_key.handle(),
            None,
            &digest,
            Some(&mut signature),
            ptr::addr_of_mut!(signature_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Modify the signature
        signature[0] ^= 0xFF;

        let result = NCryptVerifySignature(
            azihsm_key.handle(),
            None,
            &digest,
            &signature,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_err(), "result {:?}", result);
    }
}

#[test]
fn test_ecdsa_key_deletion_and_reuse() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let curve_type = std::slice::from_raw_parts(
            BCRYPT_ECC_CURVE_NISTP256.as_ptr().cast::<u8>(),
            BCRYPT_ECC_CURVE_NISTP256.to_string().unwrap().len() * size_of::<u16>(),
        );
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_ECC_CURVE_NAME_PROPERTY,
            curve_type,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let temp_key = azihsm_key.release();
        let result = NCryptDeleteKey(temp_key, NCRYPT_SILENT_FLAG.0);
        assert!(result.is_ok());

        // Attempt to use the deleted key
        let mut digest = [0u8; 32];
        rand_bytes(&mut digest).unwrap();
        let mut signature_size = 0u32;
        let result = NCryptSignHash(
            temp_key,
            None,
            &digest,
            None,
            ptr::addr_of_mut!(signature_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_err(), "result {:?}", result);
    }
}
