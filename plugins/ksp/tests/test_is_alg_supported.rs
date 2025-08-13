// Copyright (C) Microsoft Corporation. All rights reserved.
mod common;

use winapi::shared::winerror::NTE_BAD_FLAGS;
use winapi::shared::winerror::NTE_INVALID_PARAMETER;
use winapi::shared::winerror::NTE_NOT_SUPPORTED;
use winapi::shared::winerror::S_OK;
use windows::core::HRESULT;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::*;

use crate::common::*;

unsafe fn helper_check_algorithms(
    handle_provider: NCRYPT_PROV_HANDLE,
    algorithm: PCWSTR,
) -> HRESULT {
    let result = NCryptIsAlgSupported(handle_provider, algorithm, 0);

    match result {
        Ok(_) => HRESULT(S_OK),
        Err(e) => e.code(),
    }
}

#[test]
fn test_check_all_supported_alg() {
    let mut handle_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(handle_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok(),);

        let supported_alg = vec![
            BCRYPT_AES_ALGORITHM,
            #[cfg(not(feature = "disable-fp"))]
            BCRYPT_XTS_AES_ALGORITHM,
            BCRYPT_RSA_ALGORITHM,
            BCRYPT_ECDH_ALGORITHM,
            BCRYPT_ECDH_P256_ALGORITHM,
            BCRYPT_ECDH_P384_ALGORITHM,
            BCRYPT_ECDH_P521_ALGORITHM,
            BCRYPT_ECDSA_ALGORITHM,
            BCRYPT_ECDSA_P256_ALGORITHM,
            BCRYPT_ECDSA_P384_ALGORITHM,
            BCRYPT_ECDSA_P521_ALGORITHM,
            BCRYPT_SP800108_CTR_HMAC_ALGORITHM,
            BCRYPT_HKDF_ALGORITHM,
        ];

        for each in supported_alg {
            let result = helper_check_algorithms(handle_provider.handle(), each);
            assert_eq!(result, HRESULT(S_OK));
        }
    }
}

#[test]
fn test_check_unsupported_alg() {
    let mut handle_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(handle_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok(),);

        let result = helper_check_algorithms(handle_provider.handle(), BCRYPT_3DES_112_ALGORITHM);
        assert_eq!(result, HRESULT(NTE_NOT_SUPPORTED));
    }
}

#[test]
fn test_is_alg_supported_invalid_input() {
    let mut handle_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(handle_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok(),);

        let result = NCryptIsAlgSupported(handle_provider.handle(), PCWSTR::null(), 0);
        assert!(result.is_err());

        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}

#[test]
fn test_is_alg_supported_invalid_flag() {
    let mut handle_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(handle_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok(),);

        let result =
            NCryptIsAlgSupported(handle_provider.handle(), BCRYPT_ECDSA_P384_ALGORITHM, 999);
        assert!(result.is_err());

        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BAD_FLAGS));
    }
}

#[test]
#[cfg(feature = "disable-fp")]
fn test_xts_not_supported() {
    let mut handle_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(handle_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok(),);

        let result = NCryptIsAlgSupported(handle_provider.handle(), BCRYPT_XTS_AES_ALGORITHM, 0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_NOT_SUPPORTED));
    }
}
