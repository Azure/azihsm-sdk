// Copyright (C) Microsoft Corporation. All rights reserved.
mod common;

use winapi::shared::winerror::NTE_INVALID_PARAMETER;
use winapi::shared::winerror::NTE_NOT_FOUND;
use windows::core::*;
use windows::Win32::Security::Cryptography::*;

use crate::common::*;

#[test]
fn test_open_key_azihsm_builtin_unwrap_key() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptOpenKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            AZIHSM_BUILTIN_UNWRAP_KEY,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );

        assert!(result.is_ok());
    }
}

#[test]
fn test_open_key_with_invalid_key_name() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();
    let unwrap_key: PCWSTR = w!("UNWRAP_KEY");

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptOpenKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            unwrap_key,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );

        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_NOT_FOUND));
    }
}

#[test]
fn test_open_key_with_null_key_name() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptOpenKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );

        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}
