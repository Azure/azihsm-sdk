// Copyright (C) Microsoft Corporation. All rights reserved.
mod common;

use std::ptr;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread;

use mcr_api::HsmDevice;
use winapi::shared::winerror::ERROR_LOCK_FAILED;
use winapi::shared::winerror::E_UNEXPECTED;
use winapi::shared::winerror::NTE_BUFFER_TOO_SMALL;
use winapi::shared::winerror::NTE_INVALID_HANDLE;
use windows::core::*;
use windows::Win32::Security::Cryptography::*;
use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;

use crate::common::*;

#[test]
fn test_open_multiple_providers() {
    let mut azihsm_provider_1 = ProviderHandle::new();
    let mut azihsm_provider_2 = ProviderHandle::new();
    let mut azihsm_provider_3 = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider_1.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptOpenStorageProvider(azihsm_provider_2.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let temp_provider = azihsm_provider_1.release();
        let result = NCryptFreeObject(temp_provider);
        assert!(result.is_ok());

        let result = NCryptOpenStorageProvider(azihsm_provider_3.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());
    }
}

// Test the NCryptEnumStorageProviders
#[test]
fn test_enumerate_provider() {
    let mut provider_count: u32 = 0;
    let mut provider_list: *mut NCryptProviderName = ptr::null_mut();

    unsafe {
        let result = NCryptEnumStorageProviders(&mut provider_count, &mut provider_list, 0);
        assert!(result.is_ok());

        assert!(provider_count > 0);

        // Check if the existing providers contain KSP
        let ksp_name = AZIHSM_KSP_NAME.to_string().unwrap();
        let mut has_azihsm = false;
        for i in 0..provider_count {
            let provider = *provider_list.add(i as usize);

            let provider_name = provider.pszName.to_string().unwrap();

            if provider_name == ksp_name {
                has_azihsm = true;
            }
        }

        // Free provider list
        let result = NCryptFreeBuffer(provider_list as *mut _);
        assert!(result.is_ok());

        assert!(has_azihsm, "AZIHSM Key Storage Provider is not found!");
    }
}

#[test]
fn test_stress_open_provider() {
    const PROVIDER_COUNT: usize = 4;
    unsafe {
        for i in 0..PROVIDER_COUNT {
            let mut azihsm_provider = ProviderHandle::new();

            let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
            assert!(result.is_ok(), "Failed to open at {}", i);
        }
    }
}

#[test]
fn test_repeated_open_close_provider_multithreaded() {
    let devices = HsmDevice::get_devices();
    if devices.is_empty() {
        println!("No devices found");
        return;
    }

    let session_count = 7;
    const NUM_PER_THREAD_ITERATIONS: usize = 10;
    const NUM_ITERATIONS: usize = 10;
    let barrier = Arc::new(Barrier::new(session_count));

    for _ in 0..NUM_ITERATIONS {
        let mut handles = vec![];
        for _ in 0..session_count {
            let barrier = Arc::clone(&barrier);
            let handle = thread::spawn(move || {
                // Wait for all threads to be ready
                barrier.wait();

                for _ in 0..NUM_PER_THREAD_ITERATIONS {
                    let mut azihsm_provider: NCRYPT_PROV_HANDLE = NCRYPT_PROV_HANDLE(0);

                    unsafe {
                        let result =
                            NCryptOpenStorageProvider(&mut azihsm_provider, AZIHSM_KSP_NAME, 0);
                        if result.is_err() {
                            assert_eq!(
                                result.unwrap_err().code(),
                                HRESULT::from_win32(ERROR_LOCK_FAILED)
                            );
                        } else {
                            let result = NCryptFreeObject(azihsm_provider);
                            assert!(result.is_ok());
                        }
                    }
                }
            });
            handles.push(handle);
        }
        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }
}

#[test]
fn test_free_null_provider_handle() {
    unsafe {
        let result = NCryptFreeObject(NCRYPT_PROV_HANDLE(0));
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_HANDLE));
    }
}

#[test]
fn test_get_provider_resource_property() {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let max_key_count = {
            let mut buffer_size = 0u32;

            let result = NCryptGetProperty(
                azihsm_provider.handle(),
                AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY,
                None,
                std::ptr::addr_of_mut!(buffer_size),
                OBJECT_SECURITY_INFORMATION(0),
            );

            assert!(result.is_ok());
            assert!(buffer_size > 0);

            let mut buffer = vec![0u8; buffer_size as usize];
            let result = NCryptGetProperty(
                azihsm_provider.handle(),
                AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY,
                Some(&mut buffer),
                std::ptr::addr_of_mut!(buffer_size),
                OBJECT_SECURITY_INFORMATION(0),
            );

            assert!(result.is_ok());
            let size_u32 = std::mem::size_of::<u32>();
            assert_eq!(buffer_size, size_u32 as u32);

            u32::from_le_bytes(buffer[..size_u32].try_into().unwrap())
        };

        let max_storage_size = {
            let mut buffer_size = 0u32;

            let result = NCryptGetProperty(
                azihsm_provider.handle(),
                AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY,
                None,
                std::ptr::addr_of_mut!(buffer_size),
                OBJECT_SECURITY_INFORMATION(0),
            );

            assert!(result.is_ok());
            assert!(buffer_size > 0);

            let mut buffer = vec![0u8; buffer_size as usize];
            let result = NCryptGetProperty(
                azihsm_provider.handle(),
                AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY,
                Some(&mut buffer),
                std::ptr::addr_of_mut!(buffer_size),
                OBJECT_SECURITY_INFORMATION(0),
            );

            assert!(result.is_ok());
            let size_u32 = std::mem::size_of::<u32>();
            assert_eq!(buffer_size, size_u32 as u32);

            u32::from_le_bytes(buffer[..size_u32].try_into().unwrap())
        };

        // We can't check for exact value because that changes with number of table assigned, the ratio should be the same
        assert_eq!(256 / 16, max_key_count / max_storage_size);
    }
}

#[test]
fn test_get_provider_resource_property_invalid_buffer() {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        {
            let mut buffer_size = 0u32;

            let result = NCryptGetProperty(
                azihsm_provider.handle(),
                AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY,
                None,
                std::ptr::addr_of_mut!(buffer_size),
                OBJECT_SECURITY_INFORMATION(0),
            );

            assert!(result.is_ok());
            assert!(buffer_size > 0);

            // Make a buffer smaller than required
            let mut buffer = vec![0u8; (buffer_size - 1) as usize];
            let result = NCryptGetProperty(
                azihsm_provider.handle(),
                AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY,
                Some(&mut buffer),
                std::ptr::addr_of_mut!(buffer_size),
                OBJECT_SECURITY_INFORMATION(0),
            );

            assert!(result.is_err());
            assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BUFFER_TOO_SMALL));
        };

        {
            let mut buffer_size = 0u32;

            let result = NCryptGetProperty(
                azihsm_provider.handle(),
                AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY,
                None,
                std::ptr::addr_of_mut!(buffer_size),
                OBJECT_SECURITY_INFORMATION(0),
            );

            assert!(result.is_ok());
            assert!(buffer_size > 0);

            let mut buffer = vec![0u8; (buffer_size - 1) as usize];
            let result = NCryptGetProperty(
                azihsm_provider.handle(),
                AZIHSM_DEVICE_MAX_STORAGE_SIZE_PROPERTY,
                Some(&mut buffer),
                std::ptr::addr_of_mut!(buffer_size),
                OBJECT_SECURITY_INFORMATION(0),
            );

            assert!(result.is_err());
            assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BUFFER_TOO_SMALL));
        };
    }
}

// Generate keys till we reach the limit of AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY
#[test]
fn test_generate_key_till_limit() {
    const NUM_BUILTIN_KEYS: u32 = 4;

    unsafe fn create_key(
        azihsm_provider: &mut Handle<NCRYPT_PROV_HANDLE>,
        expect_to_fail: bool,
    ) -> Option<Handle<NCRYPT_KEY_HANDLE>> {
        let mut azihsm_key = KeyHandle::new();

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
        if expect_to_fail {
            assert!(result.is_err());
            assert_eq!(result.unwrap_err().code(), HRESULT(E_UNEXPECTED));
            None
        } else {
            assert!(result.is_ok());
            Some(azihsm_key)
        }
    }

    let mut azihsm_provider = ProviderHandle::new();
    let mut keys = vec![];

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let max_key_count = {
            let mut buffer_size = 0u32;

            let result = NCryptGetProperty(
                azihsm_provider.handle(),
                AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY,
                None,
                std::ptr::addr_of_mut!(buffer_size),
                OBJECT_SECURITY_INFORMATION(0),
            );

            assert!(result.is_ok());
            assert!(buffer_size > 0);

            let mut buffer = vec![0u8; buffer_size as usize];
            let result = NCryptGetProperty(
                azihsm_provider.handle(),
                AZIHSM_DEVICE_MAX_KEY_COUNT_PROPERTY,
                Some(&mut buffer),
                std::ptr::addr_of_mut!(buffer_size),
                OBJECT_SECURITY_INFORMATION(0),
            );

            assert!(result.is_ok());
            let size_u32 = std::mem::size_of::<u32>();
            assert_eq!(buffer_size, size_u32 as u32);

            u32::from_le_bytes(buffer[..size_u32].try_into().unwrap())
        };

        // Create this many keys
        // Minus builtin keys
        for _ in 0..(max_key_count - NUM_BUILTIN_KEYS) {
            let key = create_key(&mut azihsm_provider, false).unwrap();
            keys.push(key);
        }

        // Next key creation should fail
        let result = create_key(&mut azihsm_provider, true);
        assert!(result.is_none(), "Key creation should fail");
    }
}
