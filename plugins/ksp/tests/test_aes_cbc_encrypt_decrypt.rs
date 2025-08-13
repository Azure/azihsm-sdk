// Copyright (C) Microsoft Corporation. All rights reserved.
mod common;

use std::mem::size_of;
use std::ptr;

use openssl::rand::rand_bytes;
use widestring::*;
use winapi::shared::winerror::E_INVALIDARG;
use winapi::shared::winerror::NTE_BAD_FLAGS;
use winapi::shared::winerror::NTE_BUFFER_TOO_SMALL;
use winapi::shared::winerror::NTE_INVALID_PARAMETER;
use windows::core::HRESULT;
use windows::Win32::Security::Cryptography::*;
use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;

use crate::common::*;

#[test]
fn test_aes_cbc_encrypt_decrypt() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 128u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

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
            azihsm_key.handle(),
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
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext, decrypted);

        // Get the key length property size
        let mut key_length_property_size = 0u32;
        let result = NCryptGetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            None,
            ptr::addr_of_mut!(key_length_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());
        assert_eq!(key_length_property_size, size_of::<u32>() as u32);

        // Get the key length property value
        let mut key_length_bytes = vec![0u8; key_length_property_size as usize];
        let result = NCryptGetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            Some(&mut key_length_bytes),
            ptr::addr_of_mut!(key_length_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());
        let key_length = u32::from_le_bytes(key_length_bytes.try_into().unwrap());
        assert_eq!(key_length, 128);

        // Get the chaining mode property size
        let mut chaining_mode_property_size = 0u32;
        let result = NCryptGetProperty(
            azihsm_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            None,
            ptr::addr_of_mut!(chaining_mode_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());

        // Get the chaining mode property value
        let mut chaining_mode_bytes = vec![0u8; chaining_mode_property_size as usize];
        let result = NCryptGetProperty(
            azihsm_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            Some(&mut chaining_mode_bytes),
            ptr::addr_of_mut!(chaining_mode_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());
        let chaining_mode = byte_slice_to_pcwstr(&chaining_mode_bytes).unwrap();
        assert_eq!(
            WideCString::from_ptr_str(chaining_mode.as_ptr()),
            WideCString::from_ptr_str(BCRYPT_CHAIN_MODE_CBC.as_ptr())
        );
    }
}

// Test Encrypt/Decrypt with no flag set
#[test]
fn test_aes_cbc_encrypt_decrypt_no_flag() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 128u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

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

        // Try Encrypt with no flag
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(0), // No NCRYPT_PAD_CIPHER_FLAG
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));

        // Encrypt with proper flag, so we can try decrypt later
        let result = NCryptEncrypt(
            azihsm_key.handle(),
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

        // Try Decrypt with no flag
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(0), // No NCRYPT_PAD_CIPHER_FLAG
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));

        // Try Decrypt with proper flag
        let result = NCryptDecrypt(
            azihsm_key.handle(),
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

// Test AES Encrypt/Decrypt with flag for RSA Encrypt/Decrypt
#[test]
fn test_aes_cbc_encrypt_decrypt_rsa_flag() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 128u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

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

        // Try Encrypt with RSA flag
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BAD_FLAGS));

        // Encrypt with proper flag, so we can try decrypt later
        let result = NCryptEncrypt(
            azihsm_key.handle(),
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

        // Try Decrypt with RSA flag
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BAD_FLAGS));

        // Try Decrypt with proper flag
        let result = NCryptDecrypt(
            azihsm_key.handle(),
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

#[test]
fn test_aes_cbc_encrypt_query_required_input_buffer_size() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 128u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(NCRYPT_SILENT_FLAG.0));
        assert!(result.is_ok());

        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).unwrap();

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: iv.as_mut_ptr(),
            cbIV: iv.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_SILENT_FLAG.0 | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext.len(), ciphertext_len as usize);
    }
}

#[test]
fn test_aes_cbc_encrypt_query_required_output_buffer_size() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 128u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

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
        let ciphertext = [0u8; 128];
        rand_bytes(&mut plaintext).unwrap();

        let mut decrypted_len = 0u32;
        padding_info.pbIV = iv_orig.as_mut_ptr();

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext.len(), decrypted_len as usize);
    }
}

#[test]
fn test_aes_cbc_encrypt_query_required_input_buffer_size_lt_required() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 128u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(NCRYPT_SILENT_FLAG.0));
        assert!(result.is_ok());

        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).unwrap();

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: iv.as_mut_ptr(),
            cbIV: iv.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_SILENT_FLAG.0 | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext.len(), ciphertext_len as usize);

        // Subtract 1 from the required input buffer size.
        let mut ciphertext = vec![0u8; ciphertext_len as usize - 1];
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_SILENT_FLAG.0 | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BUFFER_TOO_SMALL));
    }
}

#[test]
fn test_aes_cbc_encrypt_query_required_input_buffer_size_gt_required() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 128u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(NCRYPT_SILENT_FLAG.0));
        assert!(result.is_ok());

        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).unwrap();

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: iv.as_mut_ptr(),
            cbIV: iv.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_SILENT_FLAG.0 | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext.len(), ciphertext_len as usize);

        // Add 1 to the required input buffer size.
        let mut ciphertext = vec![0u8; ciphertext_len as usize + 1];
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_SILENT_FLAG.0 | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, plaintext.len() as u32);
    }
}

#[test]
fn test_aes_cbc_encrypt_query_required_output_buffer_size_lt_required() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 128u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

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
        let ciphertext = [0u8; 128];
        rand_bytes(&mut plaintext).unwrap();

        let mut decrypted_len = 0u32;
        padding_info.pbIV = iv_orig.as_mut_ptr();

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext.len(), decrypted_len as usize);

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
fn test_aes_cbc_encrypt_query_required_output_buffer_size_gt_required() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 128u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

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
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        let mut decrypted_len = 0u32;
        padding_info.pbIV = iv_orig.as_mut_ptr();

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext.len(), decrypted_len as usize);

        // Add 1 to the required output buffer size.
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
        assert_eq!(plaintext, decrypted[..decrypted_len as usize]);
    }
}

#[test]
fn test_aes_cbc_multi_block_encrypt_decrypt() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 128u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

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

        let chunk_size = 128;
        let mut plaintext = [0u8; 256];
        let mut ciphertext1 = [0u8; 128];
        let mut ciphertext2 = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext[..chunk_size]),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext1),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, 128);

        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext[chunk_size..]),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext2),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        let mut decrypted1 = [0u8; 128];
        let mut decrypted2 = [0u8; 128];
        let mut decrypted_len = 0u32;
        padding_info.pbIV = iv_orig.as_mut_ptr();

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext1),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted1),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, 128);
        assert_eq!(plaintext[..chunk_size], decrypted1);

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext2),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted2),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext[chunk_size..], decrypted2);
    }
}

// Test key size that is invalid
#[test]
fn test_aes_cbc_invalid_key_length() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        // Try invalid key length
        let key_length = 100u32;
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

#[test]
fn test_aes128_cbc_encrypt_decrypt_various_sizes() {
    test_aes_cbc_encrypt_decrypt_various_sizes(128);
}

#[test]
fn test_aes192_cbc_encrypt_decrypt_various_sizes() {
    test_aes_cbc_encrypt_decrypt_various_sizes(192);
}

#[test]
fn test_aes256_cbc_encrypt_decrypt_various_sizes() {
    test_aes_cbc_encrypt_decrypt_various_sizes(256);
}

#[derive(Debug)]
enum IvType {
    Size(usize),
    Null,
    NoPaddingInfo,
}

fn test_aes_cbc_encrypt_decrypt_various_sizes(key_size: u32) {
    println!("Testing with key size: {} bits", key_size);
    let flags_pad_cipher =
        NCRYPT_FLAGS(NCRYPT_SILENT_FLAG.0 | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0);
    let flags_no_pad_cipher = NCRYPT_FLAGS(NCRYPT_SILENT_FLAG.0);

    // Positive tests
    // Data = 16 bytes
    test_encrypt_decrypt(
        key_size,
        16,
        IvType::Size(16),
        flags_pad_cipher,
        true,
        false,
    );
    // Data > multiple of 16 bytes
    test_encrypt_decrypt(
        key_size,
        128,
        IvType::Size(16),
        flags_pad_cipher,
        true,
        false,
    );
    // Data > multiple of 16 bytes
    test_encrypt_decrypt(
        key_size,
        32,
        IvType::Size(16),
        flags_pad_cipher,
        true,
        false,
    );
    // Data = 1024 bytes
    test_encrypt_decrypt(
        key_size,
        1024,
        IvType::Size(16),
        flags_pad_cipher,
        true,
        false,
    );

    // Negative tests
    // Data < 16 bytes
    test_encrypt_decrypt(
        key_size,
        10,
        IvType::Size(16),
        flags_pad_cipher,
        false,
        false,
    );
    // Data != multiple of 16 bytes
    test_encrypt_decrypt(
        key_size,
        17,
        IvType::Size(16),
        flags_pad_cipher,
        false,
        false,
    );
    // Data > 1024 bytes
    test_encrypt_decrypt(
        key_size,
        2048,
        IvType::Size(16),
        flags_pad_cipher,
        false,
        false,
    );
    // IV != 16 bytes
    test_encrypt_decrypt(
        key_size,
        16,
        IvType::Size(15),
        flags_pad_cipher,
        false,
        false,
    );
    // PaddingInfo.pbIV == null
    test_encrypt_decrypt(key_size, 16, IvType::Null, flags_pad_cipher, false, true);
    // Padding flag set but no padding info struct provided
    test_encrypt_decrypt(
        key_size,
        128,
        IvType::NoPaddingInfo,
        flags_pad_cipher,
        false,
        true,
    );
    // Padding info struct provided but padding flag unset
    test_encrypt_decrypt(
        key_size,
        128,
        IvType::Size(16),
        flags_no_pad_cipher,
        false,
        true,
    );
    // No padding info and no padding flag
    test_encrypt_decrypt(
        key_size,
        128,
        IvType::NoPaddingInfo,
        flags_no_pad_cipher,
        false,
        true,
    );
}

fn assert_with_cleanup(what_we_expect: bool) {
    assert!(what_we_expect);
}

/**
 * Test runner for AES encryption/decryption with various input data sizes and IV types.
 * @param key_size The size of the key in bits.
 * @param data_size The size of the data to be encrypted in bytes.
 * @param iv_type The type of IV to be used.
 * @param flags The flags to be used for encryption.
 * @param should_succeed Whether the operation should succeed.
 * @param early_fail Whether the operation should fail early during param validation at KSP layer (true) or later from AZIHSM client API (false).
*/
fn test_encrypt_decrypt(
    key_size: u32,
    data_size: usize,
    iv_type: IvType,
    flags: NCRYPT_FLAGS,
    should_succeed: bool,
    early_fail: bool,
) {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();
    println!(
        "data_size: {}, iv_type: {:?} flags: {:?} should_succeed: {}",
        data_size, iv_type, flags, should_succeed
    );
    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set encryption mode to CBC
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set key length
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_size.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Get the key length property size
        let mut key_length_property_size = 0u32;
        let result = NCryptGetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            None,
            ptr::addr_of_mut!(key_length_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());
        assert_eq!(key_length_property_size, size_of::<u32>() as u32);

        // Get the key length property value
        let mut key_length_bytes = vec![0u8; key_length_property_size as usize];
        let result = NCryptGetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            Some(&mut key_length_bytes),
            ptr::addr_of_mut!(key_length_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());
        let key_length = u32::from_le_bytes(key_length_bytes.try_into().unwrap());
        assert_eq!(key_length, key_size);

        // Get the chaining mode property size
        let mut chaining_mode_property_size = 0u32;
        let result = NCryptGetProperty(
            azihsm_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            None,
            ptr::addr_of_mut!(chaining_mode_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());

        // Get the chaining mode property value
        let mut chaining_mode_bytes = vec![0u8; chaining_mode_property_size as usize];
        let result = NCryptGetProperty(
            azihsm_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            Some(&mut chaining_mode_bytes),
            ptr::addr_of_mut!(chaining_mode_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());
        let chaining_mode = byte_slice_to_pcwstr(&chaining_mode_bytes).unwrap();
        assert_eq!(
            WideCString::from_ptr_str(chaining_mode.as_ptr()),
            WideCString::from_ptr_str(BCRYPT_CHAIN_MODE_CBC.as_ptr())
        );

        // Prepare data and IV
        let mut plaintext = vec![0u8; data_size];
        let iv_size = match iv_type {
            IvType::Size(size) => size,
            _ => 0,
        };
        rand_bytes(&mut plaintext).unwrap();
        let mut iv = vec![0u8; iv_size];
        rand_bytes(&mut iv).unwrap();
        let mut iv_orig = iv.clone();

        let (iv_ptr, iv_len) = match iv_type {
            IvType::Size(_) => (iv.as_mut_ptr(), iv.len() as u32),
            _ => (std::ptr::null_mut(), 0),
        };
        let mut padding_info = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: iv_ptr,
            cbIV: iv_len,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };
        let p_padding_info = if matches!(iv_type, IvType::NoPaddingInfo) {
            None
        } else {
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void)
        };

        println!("p_padding_info: {:?}", p_padding_info);
        println!("padding_info: {:?}", padding_info);

        // Get ciphertext length by passing null ciphertext
        let mut ciphertext_len = 0u32;
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            p_padding_info,
            None,
            ptr::addr_of_mut!(ciphertext_len),
            flags,
        );

        // padding errors fail early
        if !should_succeed && early_fail {
            assert_with_cleanup(result.is_err());
            return;
        }

        assert!(result.is_ok());
        println!("ciphertext_len: {}", ciphertext_len);
        assert_eq!(ciphertext_len as usize, plaintext.len());
        let mut ciphertext = vec![0u8; ciphertext_len as usize];

        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            p_padding_info,
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            flags,
        );

        // check errors related to input data size
        if should_succeed {
            assert_with_cleanup(result.is_ok());
            // Decrypt
            let mut decrypted = vec![0u8; data_size];
            let mut decrypted_len = 0u32;
            padding_info.pbIV = iv_orig.as_mut_ptr();

            let result = NCryptDecrypt(
                azihsm_key.handle(),
                Some(&ciphertext),
                p_padding_info,
                Some(&mut decrypted),
                ptr::addr_of_mut!(decrypted_len),
                flags,
            );
            match result {
                Ok(_) => {
                    assert_with_cleanup(plaintext == decrypted[..plaintext.len()]);
                }
                Err(_) => {
                    println!("error: {:?}", result);
                    assert_with_cleanup(false);
                }
            }
        } else {
            println!("error: {:?}", result);
            assert_with_cleanup(result.is_err());
        }

        // Clean up
        println!(
            "data_size: {}, iv_type: {:?} should_succeed: {} passed",
            data_size, iv_type, should_succeed
        );
    }
}
