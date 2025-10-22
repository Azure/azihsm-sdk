// Copyright (C) Microsoft Corporation. All rights reserved.
mod common;

#[cfg(not(feature = "disable-fp"))]
use std::mem::size_of;
#[cfg(not(feature = "disable-fp"))]
use std::ptr;

#[cfg(not(feature = "disable-fp"))]
use crypto::rand::rand_bytes;
#[cfg(not(feature = "disable-fp"))]
use winapi::shared::winerror::E_INVALIDARG;
#[cfg(not(feature = "disable-fp"))]
use winapi::shared::winerror::NTE_BAD_FLAGS;
#[cfg(not(feature = "disable-fp"))]
use winapi::shared::winerror::NTE_BUFFER_TOO_SMALL;
#[cfg(not(feature = "disable-fp"))]
use winapi::shared::winerror::NTE_INVALID_HANDLE;
#[cfg(not(feature = "disable-fp"))]
use winapi::shared::winerror::NTE_INVALID_PARAMETER;
#[cfg(not(feature = "disable-fp"))]
use windows::core::HRESULT;
use windows::Win32::Security::Cryptography::*;

use crate::common::*;

#[test]
#[cfg(feature = "disable-fp")]
fn test_aes_xts_not_supported() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_XTS_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_err());
    }
}

/// Test AES-XTS encryption and decryption
///
/// This test allocates a 1MB buffer, encrypts it using AES-XTS, then decrypts it.
/// It verifies that the decrypted buffer matches the original buffer.
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_xts_encrypt_decrypt_1mb_buffer() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_XTS_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 512u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut tweak = [0u8; 16];
        rand_bytes(&mut tweak).expect("Failed to generate random bytes");

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: tweak.as_mut_ptr(),
            cbIV: tweak.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = vec![0; 1024 * 1024];
        let plaintext_len = plaintext.len() as u32;
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // First call - Get the ciphertext length.
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, plaintext_len);

        // Second call - Encrypt the plaintext.
        let mut ciphertext = vec![0u8; ciphertext_len as usize];
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        // First call - Get the decrypted data length.
        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, plaintext_len);

        // Second call - Decrypt the ciphertext.
        let mut decrypted = vec![0u8; decrypted_len as usize];
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        // Compare the plaintext and decrypted data.
        assert_eq!(plaintext, decrypted);
    }
}

/// Test AES-XTS encryption and decryption
///
/// This test allocates an arbitrary size 512 bytes, encrypts it using AES-XTS, then decrypts it.
/// It verifies that the decrypted buffer matches the original buffer.
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_xts_encrypt_decrypt_arbitrary_buffer_500_bytes() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_XTS_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 512u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut tweak = [0u8; 16];
        rand_bytes(&mut tweak).expect("Failed to generate random bytes");

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: tweak.as_mut_ptr(),
            cbIV: tweak.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = vec![0; 512];
        let plaintext_len = plaintext.len() as u32;
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // First call - Get the ciphertext length.
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, plaintext_len);

        // Second call - Encrypt the plaintext.
        let mut ciphertext = vec![0u8; ciphertext_len as usize];
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        // First call - Get the decrypted data length.
        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, plaintext_len);

        // Second call - Decrypt the ciphertext.
        let mut decrypted = vec![0u8; decrypted_len as usize];
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        // Compare the plaintext and decrypted data.
        assert_eq!(plaintext, decrypted);
    }
}

/// Test AES-XTS encryption with an unsupported key length
///
/// This test attempts to set an unsupported key length (256 bits) for AES-XTS encryption.
/// It verifies that the key finalization fails with the appropriate error code (E_INVALIDARG).
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_xts_unsupported_key_length() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_XTS_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 256u32; // Unsupported key length
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(E_INVALIDARG));
    }
}

/// Test finalizing AES-XTS key without setting key length
///
/// This test attempts to finalize an AES-XTS key without setting the key length.
/// It verifies that the finalization operation fails.
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_xts_finalize_key_without_setting_length() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_XTS_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(E_INVALIDARG));
    }
}

/// Test AES-XTS encryption and decryption with an invalid tweak size
///
/// This test attempts to encrypt a buffer using AES-XTS with an invalid tweak size (20 bytes instead of 16).
/// It verifies that the encryption operation fails with the appropriate error code (NTE_INVALID_PARAMETER).
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_xts_encrypt_decrypt_with_invalid_tweak_size() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_XTS_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 512u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut tweak = [0u8; 20]; // Invalid tweak size; must be 16 bytes.
        rand_bytes(&mut tweak).expect("Failed to generate random bytes");

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: tweak.as_mut_ptr(),
            cbIV: tweak.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = vec![0; 1024 * 1024];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}

/// Test AES-XTS encryption and decryption with corrupted ciphertext
///
/// This test encrypts a buffer using AES-XTS, then corrupts the ciphertext by modifying its content.
/// It verifies that the decrypted data does not match the original plaintext.
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_xts_encrypt_decrypt_with_corrupt_ciphertext() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_XTS_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 512u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut tweak = [0u8; 16];
        rand_bytes(&mut tweak).expect("Failed to generate random bytes");

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: tweak.as_mut_ptr(),
            cbIV: tweak.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = vec![0; 512];
        let plaintext_len = plaintext.len() as u32;
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // First call - Get the ciphertext length.
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, plaintext_len);

        // Second call - Encrypt the plaintext.
        let mut ciphertext = vec![0u8; ciphertext_len as usize];
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        // Corrupt the ciphertext.
        ciphertext[0] = ciphertext[0].wrapping_add(1);
        ciphertext[1] = ciphertext[1].wrapping_add(1);

        // First call - Get the decrypted data length.
        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, plaintext_len);

        // Second call - Decrypt the ciphertext.
        let mut decrypted = vec![0u8; decrypted_len as usize];
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        // Compare the plaintext and decrypted data.
        // The decrypted data should not match the original plaintext.
        assert_ne!(plaintext, decrypted);
    }
}

/// Test AES-XTS encryption and decryption with a deleted key
///
/// This test encrypts a buffer using AES-XTS, then deletes the key.
/// It verifies that attempting to decrypt the ciphertext with the deleted key fails, ensuring proper error handling.
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_xts_encrypt_decrypt_with_deleted_key() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_XTS_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 512u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut tweak = [0u8; 16];
        rand_bytes(&mut tweak).expect("Failed to generate random bytes");

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: tweak.as_mut_ptr(),
            cbIV: tweak.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = vec![0; 128];
        let plaintext_len = plaintext.len() as u32;
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // First call - Get the ciphertext length.
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, plaintext_len);

        // Second call - Encrypt the plaintext.
        let mut ciphertext = vec![0u8; ciphertext_len as usize];
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        // Delete the key.
        let released_key = azihsm_key.release();
        let result = NCryptDeleteKey(released_key, NCRYPT_SILENT_FLAG.0);
        assert!(result.is_ok());

        // Decrypt the ciphertext with the deleted key.
        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            released_key,
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_HANDLE));
    }
}

/// Test AES-XTS encryption and decryption with a corrupted tweak
///
/// This test encrypts a buffer using AES-XTS, then corrupts the tweak value.
/// It verifies that the decrypted data does not match the original plaintext.
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_xts_encrypt_decrypt_with_corrupted_tweak() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_XTS_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 512u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut tweak = [0u8; 16];
        rand_bytes(&mut tweak).expect("Failed to generate random bytes");

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: tweak.as_mut_ptr(),
            cbIV: tweak.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = vec![0; 256];
        let plaintext_len = plaintext.len() as u32;
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // First call - Get the ciphertext length.
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, plaintext_len);

        // Second call - Encrypt the plaintext.
        let mut ciphertext = vec![0u8; ciphertext_len as usize];
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        // Corrupt the tweak
        tweak[0] = tweak[0].wrapping_add(1);
        tweak[1] = tweak[1].wrapping_add(1);

        // First call - Get the decrypted data length.
        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, plaintext_len);

        // Second call - Decrypt the ciphertext.
        let mut decrypted = vec![0u8; decrypted_len as usize];
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        // Compare the plaintext and decrypted data.
        // The decrypted data should not match the original plaintext because the tweak is corrupted.
        assert_ne!(plaintext, decrypted);
    }
}

/// Test AES-XTS encryption with null padding information
///
/// This test attempts to encrypt a buffer using AES-XTS without providing the required padding information.
/// It verifies that the encryption operation fails with the appropriate error code (NTE_INVALID_PARAMETER).
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_xts_encrypt_decrypt_with_null_padding_info() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_XTS_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 512u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut plaintext = vec![0; 256];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // First call - Get the ciphertext length.
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            None,
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}

/// Test AES-XTS encryption with invalid flags
///
/// This test attempts to encrypt a buffer using AES-XTS with an invalid flag (NCRYPT_PAD_OAEP_FLAG).
/// It verifies that the encryption operation fails with the appropriate error code (NTE_BAD_FLAGS).
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_xts_encrypt_decrypt_with_bad_flags() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_XTS_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 512u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut tweak = [0u8; 16];
        rand_bytes(&mut tweak).expect("Failed to generate random bytes");

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: tweak.as_mut_ptr(),
            cbIV: tweak.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = vec![0; 384];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BAD_FLAGS));
    }
}

#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_xts_encrypt_query_required_input_buffer_size_lt_required() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_XTS_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 512u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut tweak = [0u8; 16];
        rand_bytes(&mut tweak).expect("Failed to generate random bytes");

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: tweak.as_mut_ptr(),
            cbIV: tweak.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // First call - Get the ciphertext length.
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, 128);

        // Subtract 1 from the required input buffer size.
        let mut ciphertext = vec![0u8; ciphertext_len as usize - 1];
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BUFFER_TOO_SMALL));
    }
}

#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_xts_encrypt_query_required_output_buffer_size_lt_required() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_XTS_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 512u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut tweak = [0u8; 16];
        rand_bytes(&mut tweak).expect("Failed to generate random bytes");
        let ciphertext = [0u8; 128];

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: tweak.as_mut_ptr(),
            cbIV: tweak.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        // First call - Get the decrypted data length.
        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, 128);

        // Subtract 1 from the required output buffer size.
        let mut decrypted = vec![0u8; decrypted_len as usize - 1];
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BUFFER_TOO_SMALL));
    }
}

#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_xts_encrypt_query_required_input_buffer_size_gt_required() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_XTS_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 512u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut tweak = [0u8; 16];
        rand_bytes(&mut tweak).expect("Failed to generate random bytes");

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: tweak.as_mut_ptr(),
            cbIV: tweak.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // First call - Get the ciphertext length.
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, 128);

        // Add 1 from the required input buffer size.
        let mut ciphertext = vec![0u8; ciphertext_len as usize + 1];
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
    }
}

#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_xts_encrypt_query_required_output_buffer_size_gt_required() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_XTS_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 512u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut tweak = [0u8; 16];
        rand_bytes(&mut tweak).expect("Failed to generate random bytes");

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: tweak.as_mut_ptr(),
            cbIV: tweak.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // First call - Get the ciphertext length.
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, 128);

        // Second call - Encrypt the plaintext.
        let mut ciphertext = [0u8; 128];
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        // First call - Get the decrypted data length.
        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, 128);

        // Add 1 from the required output buffer size.
        let mut decrypted = vec![0u8; decrypted_len as usize + 1];
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        // Compare the plaintext and decrypted data.
        assert_eq!(plaintext, decrypted[..decrypted_len as usize]);
    }
}
