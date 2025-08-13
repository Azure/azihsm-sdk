// Copyright (C) Microsoft Corporation. All rights reserved.
mod common;

use std::mem::size_of;

use winapi::shared::winerror::NTE_NOT_SUPPORTED;
use windows::core::HRESULT;
use windows::core::*;
use windows::Win32::Security::Cryptography::*;

use crate::common::*;

#[test]
fn test_create_persisted_key_fail_non_null_keyname() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_AES_ALGORITHM,
            w!("test_key"), // Key name is not supported.
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(HRESULT(NTE_NOT_SUPPORTED), result.err().unwrap().code());
    }
}

#[test]
fn test_create_finalize_delete_key() {
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
    }
}
