// Copyright (C) Microsoft Corporation. All rights reserved.
mod common;

#[cfg(not(feature = "disable-fp"))]
use std::mem::size_of;
#[cfg(not(feature = "disable-fp"))]
use std::ptr;

#[cfg(not(feature = "disable-fp"))]
use widestring::*;
#[cfg(not(feature = "disable-fp"))]
use winapi::shared::winerror::ERROR_INVALID_DATA;
#[cfg(not(feature = "disable-fp"))]
use winapi::shared::winerror::E_INVALIDARG;
#[cfg(not(feature = "disable-fp"))]
use winapi::shared::winerror::NTE_BUFFER_TOO_SMALL;
#[cfg(not(feature = "disable-fp"))]
use winapi::shared::winerror::NTE_INVALID_HANDLE;
#[cfg(not(feature = "disable-fp"))]
use winapi::shared::winerror::NTE_INVALID_PARAMETER;
#[cfg(not(feature = "disable-fp"))]
use windows::core::HRESULT;
use windows::Win32::Security::Cryptography::*;
#[cfg(not(feature = "disable-fp"))]
use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;

#[cfg(not(feature = "disable-fp"))]
use crypto::rand::rand_bytes;

use crate::common::*;

// Create an AES 256 key for AES GCM
#[cfg(not(feature = "disable-fp"))]
fn helper_create_aes_256_key(azihsm_provider: &mut ProviderHandle, azihsm_key: &mut KeyHandle) {
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
            BCRYPT_CHAIN_MODE_GCM.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_GCM.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 256u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
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
        assert_eq!(key_length, 256);

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
            WideCString::from_ptr_str(BCRYPT_CHAIN_MODE_GCM.as_ptr())
        );
    }
}

#[test]
#[cfg(feature = "disable-fp")]
fn test_aes_gcm_not_supported() {
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

        // Set Encryption Mode to GCM.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_GCM.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_GCM.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_err());
    }
}

#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_decrypt() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = vec![0u8; 256_usize];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // Get Ciphertext length
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, 256);
        let mut ciphertext = vec![0u8; ciphertext_len as usize];

        // Get Ciphertext
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());

        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, 256);
        let mut decrypted = vec![0u8; decrypted_len as usize];

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext, decrypted);
    }
}

#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_decrypt_data_eq_1024_bytes() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = vec![0u8; 1024_usize];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // Get Ciphertext length
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, 1024);
        let mut ciphertext = vec![0u8; ciphertext_len as usize];

        // Get Ciphertext
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());

        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, 1024);
        let mut decrypted = vec![0u8; decrypted_len as usize];

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext, decrypted);
    }
}

// Test encrypt/decrypt data that is greater than 1024 bytes
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_decrypt_data_gt_1024_bytes() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = vec![0u8; 2048_usize];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // Get Ciphertext length
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, 2048);
        let mut ciphertext = vec![0u8; ciphertext_len as usize];

        // Get Ciphertext
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());

        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, 2048);
        let mut decrypted = vec![0u8; decrypted_len as usize];

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext, decrypted);
    }
}

#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_query_required_input_buffer_size() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = [0u8; 256];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext.len(), ciphertext_len as usize);
    }
}

#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_query_required_output_buffer_size() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = [0u8; 256];
        let ciphertext = [0u8; 256];
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let mut decrypted_len = 0u32;

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext.len(), decrypted_len as usize);
    }
}

// Buffer size less than required
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_query_required_input_buffer_size_lt_required() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = [0u8; 256];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext.len(), ciphertext_len as usize);

        // Subtract 1 from the required input buffer size
        let mut ciphertext = vec![0u8; ciphertext_len as usize - 1];
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BUFFER_TOO_SMALL));
    }
}

#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_query_required_output_buffer_size_lt_required() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = [0u8; 256];
        let ciphertext = [0u8; 256];
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let mut decrypted_len = 0u32;

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext.len(), decrypted_len as usize);

        // Subtract 1 from the required output buffer size
        let mut decrypted = vec![0u8; decrypted_len as usize - 1];
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BUFFER_TOO_SMALL));
    }
}

// Buffer size greater than required
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_query_required_input_buffer_size_gt_required() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = [0u8; 256];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext.len(), ciphertext_len as usize);

        // Add 1 from the required input buffer size
        let mut ciphertext = vec![0u8; ciphertext_len as usize + 1];
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext.len(), ciphertext_len as usize);
    }
}

#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_query_required_output_buffer_size_gt_required() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = vec![0u8; 256_usize];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, 256);
        let mut ciphertext = vec![0u8; ciphertext_len as usize];

        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());

        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, 256);

        // Add 1 from the required output buffer size
        let mut decrypted = vec![0u8; decrypted_len as usize + 1];

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext, decrypted[..decrypted_len as usize]);
    }
}

#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_multi_block_encrypt_decrypt() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = vec![0u8; 512_usize];
        let chunk_size = 256;

        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext[..chunk_size]),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, 256);
        let mut ciphertext1 = vec![0u8; ciphertext_len as usize];
        let mut ciphertext2 = vec![0u8; ciphertext_len as usize];

        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext[..chunk_size]),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext1),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());

        // Cache Tag from the padding_info field for future use
        let padding_info_ptr_1 =
            padding_info.pbOtherInfo as *mut BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;
        let tag_ptr_1 = (*padding_info_ptr_1).pbTag;
        let tag_length_1 = (*padding_info_ptr_1).cbTag;
        let mut tag_1 = std::slice::from_raw_parts_mut(tag_ptr_1, tag_length_1 as usize).to_vec();

        // Call NCryptEncrypt on second half of plain text
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext[chunk_size..]),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext2),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());

        // Cache Tag from the padding_info field for future use
        let padding_info_ptr_2 =
            padding_info.pbOtherInfo as *mut BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;
        let tag_ptr_2 = (*padding_info_ptr_2).pbTag;
        let tag_length_2 = (*padding_info_ptr_2).cbTag;
        let mut tag_2 = std::slice::from_raw_parts_mut(tag_ptr_2, tag_length_2 as usize).to_vec();

        let mut decrypted_len = 0u32;
        let padding_info_decrypt_1 =
            padding_info.pbOtherInfo as *mut BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;
        (*padding_info_decrypt_1).pbTag = tag_1.as_mut_ptr();

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext1),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, 256);
        let mut decrypted1 = vec![0u8; decrypted_len as usize];

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext1),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted1),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext[..chunk_size], decrypted1);

        let mut decrypted2 = vec![0u8; decrypted_len as usize];
        let padding_info_decrypt_2 =
            padding_info.pbOtherInfo as *mut BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;
        (*padding_info_decrypt_2).pbTag = tag_2.as_mut_ptr();

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext2),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted2),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext[chunk_size..], decrypted2);
    }
}

// Set AES Key property to [`BCRYPT_CHAIN_MODE_CBC`] but use it for GCM
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_decrypt_invalid_key_property() {
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

        // Set wrong Encryption Mode.
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
        let key_length = 256u32;
        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = vec![0u8; 256_usize];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // Get Ciphertext length
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}

// Use Key type that is not 256bit
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_decrypt_key_size_not_256() {
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
            BCRYPT_CHAIN_MODE_GCM.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_GCM.to_string().unwrap().len() * size_of::<u16>(),
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
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(E_INVALIDARG));
    }
}

// When creating key, don't set key size
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_decrypt_key_size_not_set() {
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
            BCRYPT_CHAIN_MODE_GCM.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_GCM.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            azihsm_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Skip setting Key Length.

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(E_INVALIDARG));
    }
}

// When encrypt or decrypt, data is array with zero size
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_decrypt_data_zero_size() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let plaintext: Vec<u8> = Vec::new();
        let mut ciphertext_len = 0u32;

        // Get Ciphertext length, should fail
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));

        // Decrypt zero size array, should pass
        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, 0);
    }
}

// When encrypt, IV is null
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_iv_is_null() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (_, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                // Pass NULL to IV
                pbNonce: std::ptr::null_mut(),
                cbNonce: 0,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = vec![0u8; 256_usize];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // Get Ciphertext length
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}

// When decrypt, IV is null
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_decrypt_iv_is_null() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = vec![0u8; 256_usize];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // Get Ciphertext length
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, 256);
        let mut ciphertext = vec![0u8; ciphertext_len as usize];

        // Get Ciphertext
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());

        // Set up padding info with IV = null
        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                // Pass NULL to IV
                pbNonce: std::ptr::null_mut(),
                cbNonce: 0,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        // Get Decrypted message length
        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}

// Encrypt, when decrypt, IV is tampered
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_decrypt_tampered_iv() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = vec![0u8; 256_usize];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // Get Ciphertext length
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, 256);
        let mut ciphertext = vec![0u8; ciphertext_len as usize];

        // Get Ciphertext
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());

        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, 256);
        let mut decrypted = vec![0u8; decrypted_len as usize];

        // Modify IV
        iv[0] = iv[0].wrapping_add(1);
        iv[1] = iv[1].wrapping_add(1);

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(
            result.unwrap_err().code(),
            HRESULT::from_win32(ERROR_INVALID_DATA)
        );
    }
}

// When encrypt, AAD is null
// When decrypt, provide random AAD
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_decrypt_aad_provided() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                // AAD = null
                pbAuthData: std::ptr::null_mut(),
                cbAuthData: 0,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = vec![0u8; 256_usize];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // Get Ciphertext length
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, 256);
        let mut ciphertext = vec![0u8; ciphertext_len as usize];

        // Get Ciphertext
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());

        // Set up random AAD for decrypt
        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, 256);
        let mut decrypted = vec![0u8; decrypted_len as usize];

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_err(), "result {:?}", result);

        assert_eq!(
            result.unwrap_err().code(),
            HRESULT::from_win32(ERROR_INVALID_DATA)
        );
    }
}

// When encrypt, AAD is val1
// When decrypt, AAD is val2 (tampered AAD)
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_decrypt_add_tampered() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = vec![0u8; 256_usize];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // Get Ciphertext length
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, 256);
        let mut ciphertext = vec![0u8; ciphertext_len as usize];

        // Get Ciphertext
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());

        // Modify AAD for decrypt
        aad[0] = aad[0].wrapping_add(1);
        aad[1] = aad[1].wrapping_add(1);

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, 256);
        let mut decrypted = vec![0u8; decrypted_len as usize];

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_err(), "result {:?}", result);

        assert_eq!(
            result.unwrap_err().code(),
            HRESULT::from_win32(ERROR_INVALID_DATA)
        );
    }
}

// Encrypt buffer, then corrupt the ciphertext
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_decrypt_tampered_ciphertext() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = vec![0u8; 256_usize];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // Get Ciphertext length
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, 256);
        let mut ciphertext = vec![0u8; ciphertext_len as usize];

        // Get Ciphertext
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());

        // Modify content of ciphertext
        ciphertext[0] = ciphertext[0].wrapping_add(1);
        ciphertext[1] = ciphertext[1].wrapping_add(1);

        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, 256);
        let mut decrypted = vec![0u8; decrypted_len as usize];

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_err(), "result {:?}", result);
        // Cannot find the macro for this error code
        assert_eq!(
            result.unwrap_err().code(),
            HRESULT::from_win32(ERROR_INVALID_DATA)
        );
    }
}

// Encrypt, then decrypt with tag = NULL
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_decrypt_tag_is_null() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let mut iv = [0u8; AES_GCM_IV_SIZE];
        rand_bytes(&mut iv).expect("Failed to generate random bytes");

        let mut aad = [0u8; AES_GCM_AAD_SIZE];
        rand_bytes(&mut aad).expect("Failed to generate random bytes");

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                // Tag = null
                pbTag: std::ptr::null_mut(),
                cbTag: 0,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = vec![0u8; 256_usize];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // Get Ciphertext length
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, 256);
        let mut ciphertext = vec![0u8; ciphertext_len as usize];

        // Get Ciphertext
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());

        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, 256);
        let mut decrypted = vec![0u8; decrypted_len as usize];

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_err(), "result {:?}", result);

        assert_eq!(
            result.unwrap_err().code(),
            HRESULT::from_win32(ERROR_INVALID_DATA)
        );
    }
}

// Encrypt, then decrypt with tag tampered
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_decrypt_tampered_tag() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = vec![0u8; 256_usize];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // Get Ciphertext length
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, 256);
        let mut ciphertext = vec![0u8; ciphertext_len as usize];

        // Get Ciphertext
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());

        // Modify tag
        tag[0] = tag[0].wrapping_add(1);
        tag[1] = tag[1].wrapping_add(1);

        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, 256);
        let mut decrypted = vec![0u8; decrypted_len as usize];

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_err(), "result {:?}", result);
        // Cannot find the macro for this error code
        assert_eq!(
            result.unwrap_err().code(),
            HRESULT::from_win32(ERROR_INVALID_DATA)
        );
    }
}

// Encrypt buffer, then delete the key
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_decrypt_with_deleted_key() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = vec![0u8; 256_usize];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // Get Ciphertext length
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, 256);
        let mut ciphertext = vec![0u8; ciphertext_len as usize];

        // Get Ciphertext
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());

        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, 256);
        let mut decrypted = vec![0u8; decrypted_len as usize];

        // Delete the key
        let released_key = azihsm_key.release();
        let result = NCryptDeleteKey(released_key, NCRYPT_SILENT_FLAG.0);
        assert!(result.is_ok());

        let result = NCryptDecrypt(
            released_key,
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_HANDLE));
    }
}

// Encrypt with len(data) = 16 bytes
// Should pass
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_decrypt_data_16_bytes() {
    // length, in bytes
    const PLAINTEXT_LEN: usize = 16;

    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = vec![0u8; PLAINTEXT_LEN];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // Get Ciphertext length
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, PLAINTEXT_LEN as u32);
        let mut ciphertext = vec![0u8; ciphertext_len as usize];

        // Get Ciphertext
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());

        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, PLAINTEXT_LEN as u32);
        let mut decrypted = vec![0u8; decrypted_len as usize];

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext, decrypted);
    }
}

// Encrypt with len(data) > multiple of 16 bytes
// Should pass
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_decrypt_data_gt_16_bytes() {
    // length, in bytes
    const PLAINTEXT_LEN: usize = 32;

    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(azihsm_key.handle());

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = vec![0u8; PLAINTEXT_LEN];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // Get Ciphertext length
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, PLAINTEXT_LEN as u32);
        let mut ciphertext = vec![0u8; ciphertext_len as usize];

        // Get Ciphertext
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());

        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, PLAINTEXT_LEN as u32);
        let mut decrypted = vec![0u8; decrypted_len as usize];

        let result = NCryptDecrypt(
            azihsm_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext, decrypted);
    }
}

// Encrypt with len(IV) != AES_GCM_IV_SIZE
// Should fail
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_encrypt_decrypt_iv_ne_12() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        helper_create_aes_256_key(&mut azihsm_provider, &mut azihsm_key);

        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).expect("Failed to generate random bytes");

        let mut aad = [0u8; 16];
        rand_bytes(&mut aad).expect("Failed to generate random bytes");

        let mut tag_length_property_size = 0u32;
        let result = NCryptGetProperty(
            azihsm_key.handle(),
            BCRYPT_AUTH_TAG_LENGTH,
            None,
            ptr::addr_of_mut!(tag_length_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );
        assert!(result.is_ok());
        assert_eq!(tag_length_property_size, size_of::<u32>() as u32);
        let mut tag_length_bytes = vec![0u8; tag_length_property_size as usize];

        let result = NCryptGetProperty(
            azihsm_key.handle(),
            BCRYPT_AUTH_TAG_LENGTH,
            Some(&mut tag_length_bytes),
            ptr::addr_of_mut!(tag_length_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );
        assert!(result.is_ok());
        let tag_length = u32::from_le_bytes(tag_length_bytes.try_into().unwrap());
        assert_eq!(tag_length, 16);

        // Create the tag buffer
        let mut tag = vec![0u8; tag_length as usize];

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = vec![0u8; 256_usize];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        // Get Ciphertext length
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, 256);
        let mut ciphertext = vec![0u8; ciphertext_len as usize];

        // Get Ciphertext
        let result = NCryptEncrypt(
            azihsm_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_err(), "result {:?}", result);
        // Cannot find the macro for this error code
        assert_eq!(
            result.unwrap_err().code(),
            HRESULT::from_win32(ERROR_INVALID_DATA)
        );
    }
}
