// Copyright (C) Microsoft Corporation. All rights reserved.
mod common;

use common::*;
use windows::Win32::Security::Cryptography::*;

// Free a Key Handle using NCryptFreeObject
#[test]
fn test_free_object_key_handle() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = NCRYPT_KEY_HANDLE::default();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            &mut azihsm_key,
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
            azihsm_key,
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 128u32;
        let result = NCryptSetProperty(
            azihsm_key,
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key, NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let result = NCryptFreeObject(azihsm_key);
        assert!(result.is_ok(), "{:?}", result);
    }
}

// Free a Key Handle using NCryptDeleteKey
#[test]
fn test_delete_key_key_handle() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = NCRYPT_KEY_HANDLE::default();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            &mut azihsm_key,
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
            azihsm_key,
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 128u32;
        let result = NCryptSetProperty(
            azihsm_key,
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key, NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let result = NCryptDeleteKey(azihsm_key, 0);
        assert!(result.is_ok(), "{:?}", result);
    }
}

// Free a not-finalized Key Handle using NCryptFreeObject
#[test]
fn test_free_object_not_finalized_key_handle() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = NCRYPT_KEY_HANDLE::default();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            &mut azihsm_key,
            BCRYPT_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFreeObject(azihsm_key);
        assert!(result.is_ok(), "{:?}", result);
    }
}

// Free a not-finalized Key Handle using NCryptDeleteKey
#[test]
fn test_delete_key_not_finalized_key_handle() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = NCRYPT_KEY_HANDLE::default();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            &mut azihsm_key,
            BCRYPT_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptDeleteKey(azihsm_key, 0);
        assert!(result.is_ok(), "{:?}", result);
    }
}
