// Copyright (C) Microsoft Corporation. All rights reserved.
mod common;
use std::mem::size_of;
use std::ptr;

use winapi::shared::winerror::NTE_BAD_TYPE;
use windows::core::HRESULT;
use windows::Win32::Security::Cryptography::*;

use crate::common::*;

#[test]
fn test_ecdsa_export_pubkey() {
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
            BCRYPT_ECC_CURVE_NISTP521.as_ptr().cast::<u8>(),
            BCRYPT_ECC_CURVE_NISTP521.to_string().unwrap().len() * size_of::<u16>(),
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

        let mut exportbuffer_size = 0u32;
        let result = NCryptExportKey(
            azihsm_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            None,
            ptr::addr_of_mut!(exportbuffer_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        assert!(
            exportbuffer_size > 0,
            "Expected non-zero export buffer size, but found {}",
            exportbuffer_size
        );

        let mut export_buffer = vec![0u8; exportbuffer_size as usize];
        let result = NCryptExportKey(
            azihsm_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut export_buffer),
            ptr::addr_of_mut!(exportbuffer_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        assert!(!export_buffer.is_empty(), "Export buffer is empty!");
    }
}

#[test]
fn test_ecdh_export_pubkey() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDH_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let curve_type = std::slice::from_raw_parts(
            BCRYPT_ECC_CURVE_NISTP521.as_ptr().cast::<u8>(),
            BCRYPT_ECC_CURVE_NISTP521.to_string().unwrap().len() * size_of::<u16>(),
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

        let mut exportbuffer_size = 0u32;
        let result = NCryptExportKey(
            azihsm_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            None,
            ptr::addr_of_mut!(exportbuffer_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        assert!(
            exportbuffer_size > 0,
            "Expected non-zero export buffer size, but found {}",
            exportbuffer_size
        );

        let mut export_buffer = vec![0u8; exportbuffer_size as usize];
        let result = NCryptExportKey(
            azihsm_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut export_buffer),
            ptr::addr_of_mut!(exportbuffer_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        assert!(!export_buffer.is_empty(), "Export buffer is empty!");
    }
}

#[test]
fn test_aes_export() {
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

        let mut exportbuffer_size = 0u32;
        let result = NCryptExportKey(
            azihsm_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            None,
            ptr::addr_of_mut!(exportbuffer_size),
            NCRYPT_FLAGS(0),
        );
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BAD_TYPE));
    }
}

#[test]
fn test_rsa_builtin_key_export() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

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
        let mut exportbuffer_size = 0u32;
        let result = NCryptExportKey(
            import_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            None,
            ptr::addr_of_mut!(exportbuffer_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        assert!(
            exportbuffer_size > 0,
            "Expected non-zero export buffer size, but found {}",
            exportbuffer_size
        );

        let mut export_buffer = vec![0u8; exportbuffer_size as usize];
        let result = NCryptExportKey(
            import_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut export_buffer),
            ptr::addr_of_mut!(exportbuffer_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        assert!(!export_buffer.is_empty(), "Export buffer is empty!");
    }
}
