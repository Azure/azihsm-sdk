// Copyright (C) Microsoft Corporation. All rights reserved.
mod common;

use winapi::shared::winerror::NTE_BAD_FLAGS;
use winapi::shared::winerror::NTE_INVALID_PARAMETER;
use windows::core::HRESULT;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::*;

use crate::common::*;

struct Algorithms {
    ptr: *mut NCryptAlgorithmName,
    pub algorithms: Vec<NCryptAlgorithmName>,
}

impl Drop for Algorithms {
    fn drop(&mut self) {
        let result = unsafe { NCryptFreeBuffer(self.ptr as *mut std::ffi::c_void) };
        assert!(result.is_ok(), "Failed to free buffer: {:?}", result);
    }
}

unsafe fn helper_enum_algorithms(
    handle_provider: NCRYPT_PROV_HANDLE,
    algclass: NCRYPT_OPERATION,
) -> Algorithms {
    let mut count = 0;
    let mut list_raw = std::ptr::null_mut();

    let result = NCryptEnumAlgorithms(
        handle_provider,
        algclass,
        std::ptr::addr_of_mut!(count),
        std::ptr::addr_of_mut!(list_raw),
        0,
    );
    assert!(result.is_ok(), "Failed NCryptEnumAlgorithms {:?}", result);

    // Make a copy of pointer
    let mut algorithms = Vec::with_capacity(count as usize);
    std::ptr::copy_nonoverlapping(list_raw, algorithms.as_mut_ptr(), count as usize);
    algorithms.set_len(count as usize);

    Algorithms {
        ptr: list_raw,
        algorithms,
    }
}

unsafe fn helper_compare_algorithms(expected: &[PCWSTR], actual: &[NCryptAlgorithmName]) {
    for i in 0..expected.len() {
        assert_eq!(
            expected[i].as_wide(),
            actual[i].pszName.as_wide(),
            "{} th mismatch, left {}, right {}",
            i,
            expected[i].to_string().unwrap(),
            actual[i].pszName.to_string().unwrap()
        );
    }
}

#[test]
fn test_enum_all_algorithms() {
    let mut handle_provider = ProviderHandle::new();
    #[cfg(feature = "disable-fp")]
    const EXPECTED_COUNT: usize = 10;
    #[cfg(not(feature = "disable-fp"))]
    const EXPECTED_COUNT: usize = 11;

    unsafe {
        let result = NCryptOpenStorageProvider(handle_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok(),);

        let algorithms = helper_enum_algorithms(handle_provider.handle(), NCRYPT_OPERATION(0));
        assert_eq!(
            algorithms.algorithms.len(),
            EXPECTED_COUNT,
            "There should be {} results",
            EXPECTED_COUNT
        );

        let expected_alg = vec![
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
        ];

        helper_compare_algorithms(&expected_alg, &algorithms.algorithms);
    }
}

#[test]
fn test_enum_each_algorithms() {
    let mut handle_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(handle_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok(),);

        // Enum NCRYPT_CIPHER_OPERATION
        {
            #[cfg(feature = "disable-fp")]
            const EXPECTED_COUNT: usize = 1;
            #[cfg(not(feature = "disable-fp"))]
            const EXPECTED_COUNT: usize = 2;

            let algorithms =
                helper_enum_algorithms(handle_provider.handle(), NCRYPT_CIPHER_OPERATION);
            assert_eq!(algorithms.algorithms.len(), EXPECTED_COUNT);

            let expected_alg = vec![
                BCRYPT_AES_ALGORITHM,
                #[cfg(not(feature = "disable-fp"))]
                BCRYPT_XTS_AES_ALGORITHM,
            ];

            helper_compare_algorithms(&expected_alg, &algorithms.algorithms);
        }

        // Enum NCRYPT_HASH_OPERATION
        {
            const EXPECTED_COUNT: usize = 0;
            let algorithms =
                helper_enum_algorithms(handle_provider.handle(), NCRYPT_HASH_OPERATION);
            assert_eq!(algorithms.algorithms.len(), EXPECTED_COUNT);

            let expected_alg = vec![];

            helper_compare_algorithms(&expected_alg, &algorithms.algorithms);
        }

        // Enum NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION
        {
            const EXPECTED_COUNT: usize = 1;
            let algorithms = helper_enum_algorithms(
                handle_provider.handle(),
                NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION,
            );
            assert_eq!(algorithms.algorithms.len(), EXPECTED_COUNT);

            let expected_alg = vec![BCRYPT_RSA_ALGORITHM];

            helper_compare_algorithms(&expected_alg, &algorithms.algorithms);
        }

        // Enum NCRYPT_SECRET_AGREEMENT_OPERATION
        {
            const EXPECTED_COUNT: usize = 4;
            let algorithms =
                helper_enum_algorithms(handle_provider.handle(), NCRYPT_SECRET_AGREEMENT_OPERATION);
            assert_eq!(algorithms.algorithms.len(), EXPECTED_COUNT);

            let expected_alg = vec![
                BCRYPT_ECDH_ALGORITHM,
                BCRYPT_ECDH_P256_ALGORITHM,
                BCRYPT_ECDH_P384_ALGORITHM,
                BCRYPT_ECDH_P521_ALGORITHM,
            ];

            helper_compare_algorithms(&expected_alg, &algorithms.algorithms);
        }

        // Enum NCRYPT_SIGNATURE_OPERATION
        {
            const EXPECTED_COUNT: usize = 5;
            let algorithms =
                helper_enum_algorithms(handle_provider.handle(), NCRYPT_SIGNATURE_OPERATION);
            assert_eq!(algorithms.algorithms.len(), EXPECTED_COUNT);

            let expected_alg = vec![
                BCRYPT_RSA_ALGORITHM,
                BCRYPT_ECDSA_ALGORITHM,
                BCRYPT_ECDSA_P256_ALGORITHM,
                BCRYPT_ECDSA_P384_ALGORITHM,
                BCRYPT_ECDSA_P521_ALGORITHM,
            ];

            helper_compare_algorithms(&expected_alg, &algorithms.algorithms);
        }
    }
}

#[test]
fn test_enum_subset_of_algorithms() {
    let mut handle_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(handle_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok(),);

        // NCRYPT_CIPHER_OPERATION + NCRYPT_HASH_OPERATION
        {
            #[cfg(feature = "disable-fp")]
            const EXPECTED_COUNT: usize = 1;
            #[cfg(not(feature = "disable-fp"))]
            const EXPECTED_COUNT: usize = 2;

            let algorithms = helper_enum_algorithms(
                handle_provider.handle(),
                NCRYPT_CIPHER_OPERATION | NCRYPT_HASH_OPERATION,
            );
            assert_eq!(algorithms.algorithms.len(), EXPECTED_COUNT);

            let expected_alg = vec![
                BCRYPT_AES_ALGORITHM,
                #[cfg(not(feature = "disable-fp"))]
                BCRYPT_XTS_AES_ALGORITHM,
            ];

            helper_compare_algorithms(&expected_alg, &algorithms.algorithms);
        }

        // NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION + NCRYPT_SIGNATURE_OPERATION
        {
            const EXPECTED_COUNT: usize = 5;
            let algorithms = helper_enum_algorithms(
                handle_provider.handle(),
                NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION | NCRYPT_SIGNATURE_OPERATION,
            );
            assert_eq!(algorithms.algorithms.len(), EXPECTED_COUNT);

            let expected_alg = vec![
                BCRYPT_RSA_ALGORITHM,
                BCRYPT_ECDSA_ALGORITHM,
                BCRYPT_ECDSA_P256_ALGORITHM,
                BCRYPT_ECDSA_P384_ALGORITHM,
                BCRYPT_ECDSA_P521_ALGORITHM,
            ];

            helper_compare_algorithms(&expected_alg, &algorithms.algorithms);
        }

        // ALL
        {
            #[cfg(feature = "disable-fp")]
            const EXPECTED_COUNT: usize = 10;
            #[cfg(not(feature = "disable-fp"))]
            const EXPECTED_COUNT: usize = 11;

            let algorithms = helper_enum_algorithms(
                handle_provider.handle(),
                NCRYPT_CIPHER_OPERATION
                    | NCRYPT_HASH_OPERATION
                    | NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION
                    | NCRYPT_SECRET_AGREEMENT_OPERATION
                    | NCRYPT_SIGNATURE_OPERATION,
            );
            assert_eq!(algorithms.algorithms.len(), EXPECTED_COUNT);

            let expected_alg = vec![
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
            ];

            helper_compare_algorithms(&expected_alg, &algorithms.algorithms);
        }
    }
}

#[test]
fn test_invalid_inputs() {
    let mut handle_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(handle_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok(),);

        let mut count = 0;
        let mut list = std::ptr::null_mut();

        // Invalid operation
        {
            let result = NCryptEnumAlgorithms(
                handle_provider.handle(),
                NCRYPT_OPERATION(9999),
                std::ptr::addr_of_mut!(count),
                std::ptr::addr_of_mut!(list),
                0,
            );
            assert!(result.is_err());

            assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
        }

        // List is null
        {
            let result = NCryptEnumAlgorithms(
                handle_provider.handle(),
                NCRYPT_OPERATION(0),
                std::ptr::addr_of_mut!(count),
                std::ptr::null_mut(),
                0,
            );
            assert!(result.is_err());

            assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
        }

        // Count is null
        {
            let result = NCryptEnumAlgorithms(
                handle_provider.handle(),
                NCRYPT_OPERATION(0),
                std::ptr::null_mut(),
                std::ptr::addr_of_mut!(list),
                0,
            );
            assert!(result.is_err());

            assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
        }
    }
}

#[test]
fn test_enum_algorithms_invalid_flags() {
    let mut handle_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(handle_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok(),);

        let mut count = 0;
        let mut list = std::ptr::null_mut();

        let result = NCryptEnumAlgorithms(
            handle_provider.handle(),
            NCRYPT_OPERATION(0),
            std::ptr::addr_of_mut!(count),
            std::ptr::addr_of_mut!(list),
            999,
        );
        assert!(result.is_err());

        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BAD_FLAGS));
    }
}

#[test]
fn test_free_buffer_null_ptr() {
    unsafe {
        let result = NCryptFreeBuffer(std::ptr::null_mut());
        assert!(result.is_ok());
    }
}
