// Copyright (C) Microsoft Corporation. All rights reserved.
mod common;

use std::mem::size_of;
use std::ptr;

use crypto::rand::rand_bytes;
use winapi::shared::winerror::NTE_BAD_TYPE;
use winapi::shared::winerror::NTE_INVALID_HANDLE;
use winapi::shared::winerror::NTE_INVALID_PARAMETER;
use windows::core::HRESULT;
use windows::Win32::Security::Cryptography::*;

use crate::common::*;

// Positive tests for NCryptCreateClaim
// 1. Create a claim for a built-in unwrapping key.
// 2. Create a claim for an ECDSA keys.
//      a. ECDSA P256
//      b. ECDSA P384
//      c. ECDSA P521
// 3. Create a claim for an RSA keys.
//      a. RSA 2K
//      b. RSA 3K
//      c. RSA 4K
// 4. Create a claim for an ECDH keys.
//      a. ECDH P256
//      b. ECDH P384
//      c. ECDH P521
#[test]
fn test_create_claim_builtin_unwrapping_key() {
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

        let mut report_data = [0u8; REPORT_DATA_SIZE as usize];
        rand_bytes(&mut report_data).expect("Failed to generate random bytes");

        let param_buffers = [BCryptBuffer {
            cbBuffer: report_data.len() as u32,
            BufferType: NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE,
            pvBuffer: report_data.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        let mut claim_size = 0u32;
        let result = NCryptCreateClaim(
            azihsm_key.handle(),
            None,
            0,
            Some(&params),
            None,
            ptr::addr_of_mut!(claim_size),
            0,
        );

        assert!(result.is_ok());
        assert!(claim_size > 0);

        let mut claim = vec![0u8; claim_size as usize];
        let result = NCryptCreateClaim(
            azihsm_key.handle(),
            None,
            0,
            Some(&params),
            Some(&mut claim),
            ptr::addr_of_mut!(claim_size),
            0,
        );
        assert!(result.is_ok());

        verify_attestation_claim(&claim[..claim_size as usize]);
    }
}

#[test]
fn test_create_claim_ecdsa_p256() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_P256_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut report_data = [0u8; REPORT_DATA_SIZE as usize];
        rand_bytes(&mut report_data).expect("Failed to generate random bytes");

        let param_buffers = [BCryptBuffer {
            cbBuffer: report_data.len() as u32,
            BufferType: NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE,
            pvBuffer: report_data.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        let mut claim_size = 0u32;
        let result = NCryptCreateClaim(
            azihsm_key.handle(),
            None,
            0,
            Some(&params),
            None,
            ptr::addr_of_mut!(claim_size),
            0,
        );

        assert!(result.is_ok());
        assert!(claim_size > 0);

        let mut claim = vec![0u8; claim_size as usize];
        let result = NCryptCreateClaim(
            azihsm_key.handle(),
            None,
            0,
            Some(&params),
            Some(&mut claim),
            ptr::addr_of_mut!(claim_size),
            0,
        );
        assert!(result.is_ok());
        verify_attestation_claim(&claim[..claim_size as usize]);
    }
}

#[test]
fn test_create_claim_ecdsa_p384() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_P384_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut report_data = [0u8; REPORT_DATA_SIZE as usize];
        rand_bytes(&mut report_data).expect("Failed to generate random bytes");

        let param_buffers = [BCryptBuffer {
            cbBuffer: report_data.len() as u32,
            BufferType: NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE,
            pvBuffer: report_data.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        let mut claim_size = 0u32;
        let result = NCryptCreateClaim(
            azihsm_key.handle(),
            None,
            0,
            Some(&params),
            None,
            ptr::addr_of_mut!(claim_size),
            0,
        );

        assert!(result.is_ok());
        assert!(claim_size > 0);

        let mut claim = vec![0u8; claim_size as usize];
        let result = NCryptCreateClaim(
            azihsm_key.handle(),
            None,
            0,
            Some(&params),
            Some(&mut claim),
            ptr::addr_of_mut!(claim_size),
            0,
        );
        assert!(result.is_ok());
        verify_attestation_claim(&claim[..claim_size as usize]);
    }
}

#[test]
fn test_create_claim_ecdsa_p521() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_P521_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut report_data = [0u8; REPORT_DATA_SIZE as usize];
        rand_bytes(&mut report_data).expect("Failed to generate random bytes");

        let param_buffers = [BCryptBuffer {
            cbBuffer: report_data.len() as u32,
            BufferType: NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE,
            pvBuffer: report_data.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        let mut claim_size = 0u32;
        let result = NCryptCreateClaim(
            azihsm_key.handle(),
            None,
            0,
            Some(&params),
            None,
            ptr::addr_of_mut!(claim_size),
            0,
        );

        assert!(result.is_ok());
        assert!(claim_size > 0);

        let mut claim = vec![0u8; claim_size as usize];
        let result = NCryptCreateClaim(
            azihsm_key.handle(),
            None,
            0,
            Some(&params),
            Some(&mut claim),
            ptr::addr_of_mut!(claim_size),
            0,
        );
        assert!(result.is_ok());
        verify_attestation_claim(&claim[..claim_size as usize]);
    }
}

#[test]
fn test_create_claim_ecdh_p521() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDH_P521_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut report_data = [0u8; REPORT_DATA_SIZE as usize];
        rand_bytes(&mut report_data).expect("Failed to generate random bytes");

        let param_buffers = [BCryptBuffer {
            cbBuffer: report_data.len() as u32,
            BufferType: NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE,
            pvBuffer: report_data.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        let mut claim_size = 0u32;
        let result = NCryptCreateClaim(
            azihsm_key.handle(),
            None,
            0,
            Some(&params),
            None,
            ptr::addr_of_mut!(claim_size),
            0,
        );

        assert!(result.is_ok());
        assert!(claim_size > 0);

        let mut claim = vec![0u8; claim_size as usize];
        let result = NCryptCreateClaim(
            azihsm_key.handle(),
            None,
            0,
            Some(&params),
            Some(&mut claim),
            ptr::addr_of_mut!(claim_size),
            0,
        );
        assert!(result.is_ok());
        verify_attestation_claim(&claim[..claim_size as usize]);
    }
}

// Negative tests for NCryptCreateClaim
// 1. Create a claim for an AES key => This should fail as AES keys are not supported for claims.
// 2. Create a claim with report size greater than expected.
// 3. Create a claim with report size less than expected.
// 4. Create a claim for built-in unwrapping key with null params.
// 5. Create a claim with incorrect buffer descriptor.
// 6. Create a claim with an invalid key handle.
// 7. Create a claim with an invalid provider handle.
// 8. Create a claim with an invalid flag.
// 9. Create a claim with a non-null authority key.
#[test]
fn test_create_claim_aes_should_fail() {
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

        let mut report_data = [0u8; REPORT_DATA_SIZE as usize];
        rand_bytes(&mut report_data).expect("Failed to generate random bytes");

        let param_buffers = [BCryptBuffer {
            cbBuffer: report_data.len() as u32,
            BufferType: NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE,
            pvBuffer: report_data.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        let mut claim_size = 0u32;
        let result = NCryptCreateClaim(
            azihsm_key.handle(),
            None,
            0,
            Some(&params),
            None,
            ptr::addr_of_mut!(claim_size),
            0,
        );

        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BAD_TYPE));
    }
}

#[test]
fn test_create_claim_report_size_greater_than_expected() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDH_P256_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut report_data = [0u8; (REPORT_DATA_SIZE as usize) + 50];
        rand_bytes(&mut report_data).expect("Failed to generate random bytes");

        let param_buffers = [BCryptBuffer {
            cbBuffer: report_data.len() as u32,
            BufferType: NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE,
            pvBuffer: report_data.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        let mut claim_size = 0u32;
        let result = NCryptCreateClaim(
            azihsm_key.handle(),
            None,
            0,
            Some(&params),
            None,
            ptr::addr_of_mut!(claim_size),
            0,
        );

        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}

#[test]
fn test_create_claim_report_size_less_than_expected() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDH_P256_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut report_data = [0u8; (REPORT_DATA_SIZE as usize) - 50];
        rand_bytes(&mut report_data).expect("Failed to generate random bytes");

        let param_buffers = [BCryptBuffer {
            cbBuffer: report_data.len() as u32,
            BufferType: NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE,
            pvBuffer: report_data.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        let mut claim_size = 0u32;
        let result = NCryptCreateClaim(
            azihsm_key.handle(),
            None,
            0,
            Some(&params),
            None,
            ptr::addr_of_mut!(claim_size),
            0,
        );

        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}

#[test]
fn test_create_claim_builtin_unwrapping_key_null_params() {
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

        let mut report_data = [0u8; REPORT_DATA_SIZE as usize];
        rand_bytes(&mut report_data).expect("Failed to generate random bytes");

        let mut claim_size = 0u32;
        let result = NCryptCreateClaim(
            azihsm_key.handle(),
            None,
            0,
            None,
            None,
            ptr::addr_of_mut!(claim_size),
            0,
        );

        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}

#[test]
fn test_create_claim_incorrect_buffer_descriptor() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_P521_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut report_data = [0u8; REPORT_DATA_SIZE as usize];
        rand_bytes(&mut report_data).expect("Failed to generate random bytes");

        // Instead of NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE, we use NCRYPTBUFFER_PKCS_ALG_ID
        let param_buffers = [BCryptBuffer {
            cbBuffer: (BCRYPT_ECDSA_P256_ALGORITHM.to_string().unwrap().len()
                * std::mem::size_of::<u16>()) as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_ECDSA_P256_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        let mut claim_size = 0u32;
        let result = NCryptCreateClaim(
            azihsm_key.handle(),
            None,
            0,
            Some(&params),
            None,
            ptr::addr_of_mut!(claim_size),
            0,
        );

        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}

#[test]
fn test_create_claim_invalid_key_handle() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_P521_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Delete the key before calling NCryptCreateClaim
        let released_key = azihsm_key.release();
        let result = NCryptDeleteKey(released_key, 0);
        assert!(result.is_ok());

        let mut report_data = [0u8; REPORT_DATA_SIZE as usize];
        rand_bytes(&mut report_data).expect("Failed to generate random bytes");

        let param_buffers = [BCryptBuffer {
            cbBuffer: report_data.len() as u32,
            BufferType: NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE,
            pvBuffer: report_data.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        let mut claim_size = 0u32;
        let result = NCryptCreateClaim(
            released_key,
            None,
            0,
            Some(&params),
            None,
            ptr::addr_of_mut!(claim_size),
            0,
        );

        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_HANDLE));
    }
}

#[test]
fn test_create_claim_with_invalid_provider_handle() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDH_P256_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut report_data = [0u8; REPORT_DATA_SIZE as usize];
        rand_bytes(&mut report_data).expect("Failed to generate random bytes");

        let param_buffers = [BCryptBuffer {
            cbBuffer: report_data.len() as u32,
            BufferType: NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE,
            pvBuffer: report_data.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        let mut claim_size = 0u32;
        let result = NCryptCreateClaim(
            NCRYPT_KEY_HANDLE(0),
            None,
            0,
            Some(&params),
            None,
            ptr::addr_of_mut!(claim_size),
            0,
        );

        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_HANDLE));
    }
}

#[test]
fn test_create_claim_with_invalid_flag() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_P384_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut report_data = [0u8; REPORT_DATA_SIZE as usize];
        rand_bytes(&mut report_data).expect("Failed to generate random bytes");

        let param_buffers = [BCryptBuffer {
            cbBuffer: report_data.len() as u32,
            BufferType: NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE,
            pvBuffer: report_data.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        let mut claim_size = 0u32;
        let result = NCryptCreateClaim(
            azihsm_key.handle(),
            None,
            0,
            Some(&params),
            None,
            ptr::addr_of_mut!(claim_size),
            1, // Invalid flag. Must be set to 0.
        );

        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}

#[test]
fn test_create_claim_non_null_authority_key() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut azihsm_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            azihsm_key.as_mut(),
            BCRYPT_ECDSA_P256_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut report_data = [0u8; REPORT_DATA_SIZE as usize];
        rand_bytes(&mut report_data).expect("Failed to generate random bytes");

        let param_buffers = [BCryptBuffer {
            cbBuffer: report_data.len() as u32,
            BufferType: NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE,
            pvBuffer: report_data.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        let mut claim_size = 0u32;
        let result = NCryptCreateClaim(
            azihsm_key.handle(),
            azihsm_key.handle(), // Authority key must be null.
            0,
            Some(&params),
            None,
            ptr::addr_of_mut!(claim_size),
            0,
        );

        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}
