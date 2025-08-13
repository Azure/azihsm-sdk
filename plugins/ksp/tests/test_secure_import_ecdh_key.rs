// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use std::mem::size_of;
use std::ptr;

use winapi::shared::winerror::NTE_NOT_SUPPORTED;
use windows::core::HRESULT;
use windows::Win32::Security::Cryptography::*;
use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;

use crate::common::*;

#[test]
fn test_ecdh_p256_key_unwrap_with_ckm_rsa_aes_key_wrap() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut alice_key = KeyHandle::new();
    let mut bob_key = KeyHandle::new();
    let mut secret_handle = SecretHandle::new();
    let mut alice_imported_bob_public_key = KeyHandle::new();

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
        let mut pub_key = vec![0u8; 600];
        let mut pub_key_size = pub_key.len() as u32;
        let result = NCryptExportKey(
            import_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut pub_key),
            ptr::addr_of_mut!(pub_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        pub_key.truncate(pub_key_size as usize);

        // Generate a ECC256 private key
        // Wrap it with the import public key using CKM_RSA_AES_KEY_WRAP key encryption algorithm
        let private_key = generate_ecc_der(KeyType::Ecc256).0;
        let encrypted_blob = wrap_data(
            pub_key,
            &private_key,
            KeyEncryptionAlgorithm::CKM_RSA_AES_KEY_WRAP,
        );
        let key_blob = create_pkcs11_rsa_aes_wrap_blob(
            &encrypted_blob,
            KeyEncryptionAlgorithm::CKM_RSA_AES_KEY_WRAP,
        );

        // Prepare paramlist for unwrapping
        let param_buffers = [BCryptBuffer {
            cbBuffer: (BCRYPT_ECDH_P256_ALGORITHM.to_string().unwrap().len()
                * std::mem::size_of::<u16>()) as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_ECDH_P256_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        // Import the wrapped key for Alice
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            import_key.handle(),
            BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
            Some(&params),
            alice_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(alice_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Get the key length property size
        let mut key_length_property_size = 0u32;
        let result = NCryptGetProperty(
            alice_key.handle(),
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
            alice_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            Some(&mut key_length_bytes),
            ptr::addr_of_mut!(key_length_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());
        let key_length = u32::from_le_bytes(key_length_bytes.try_into().unwrap());
        assert_eq!(key_length, 256);

        // Generate key for Bob
        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            bob_key.as_mut(),
            BCRYPT_ECDH_P256_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(bob_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Export Bob's public key
        let mut bob_public_key_handle = vec![0u8; 600];
        let mut bob_public_key_size = bob_public_key_handle.len() as u32;
        let result = NCryptExportKey(
            bob_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut bob_public_key_handle),
            ptr::addr_of_mut!(bob_public_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        bob_public_key_handle.truncate(bob_public_key_size as usize);

        // Key Exchange and Public Key Import for Alice
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            NCRYPT_KEY_HANDLE(0),
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            alice_imported_bob_public_key.as_mut(),
            &bob_public_key_handle,
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the imported key
        let result = NCryptFinalizeKey(alice_imported_bob_public_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Generate secret agreement
        let result = NCryptSecretAgreement(
            alice_key.handle(),
            alice_imported_bob_public_key.handle(),
            secret_handle.as_mut(),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
    }
}

#[test]
fn test_ecdh_p256_key_unwrap_with_rsa_aes_key_wrap_256() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut alice_key = KeyHandle::new();
    let mut bob_key = KeyHandle::new();
    let mut secret_handle = SecretHandle::new();
    let mut alice_imported_bob_public_key = KeyHandle::new();

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
        let mut pub_key = vec![0u8; 600];
        let mut pub_key_size = pub_key.len() as u32;
        let result = NCryptExportKey(
            import_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut pub_key),
            ptr::addr_of_mut!(pub_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        pub_key.truncate(pub_key_size as usize);

        // Generate a ECC256 private key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_256 key encryption algorithm
        let private_key = generate_ecc_der(KeyType::Ecc256).0;
        let encrypted_blob = wrap_data(
            pub_key,
            &private_key,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        );
        let key_blob = create_pkcs11_rsa_aes_wrap_blob(
            &encrypted_blob,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        );

        // Prepare paramlist for unwrapping
        let param_buffers = [BCryptBuffer {
            cbBuffer: (BCRYPT_ECDH_ALGORITHM.to_string().unwrap().len()
                * std::mem::size_of::<u16>()) as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_ECDH_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        // Import the wrapped key
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            import_key.handle(),
            BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
            Some(&params),
            alice_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(alice_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Generate key for Bob
        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            bob_key.as_mut(),
            BCRYPT_ECDH_P256_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(bob_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Export Bob's public key
        let mut bob_public_key_handle = vec![0u8; 600];
        let mut bob_public_key_size = bob_public_key_handle.len() as u32;
        let result = NCryptExportKey(
            bob_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut bob_public_key_handle),
            ptr::addr_of_mut!(bob_public_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        bob_public_key_handle.truncate(bob_public_key_size as usize);

        // Key Exchange and Public Key Import for Alice
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            NCRYPT_KEY_HANDLE(0),
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            alice_imported_bob_public_key.as_mut(),
            &bob_public_key_handle,
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the imported key
        let result = NCryptFinalizeKey(alice_imported_bob_public_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Generate secret agreement
        let result = NCryptSecretAgreement(
            alice_key.handle(),
            alice_imported_bob_public_key.handle(),
            secret_handle.as_mut(),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
    }
}

#[test]
fn test_ecdh_p256_key_unwrap_with_rsa_aes_key_wrap_384() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut alice_key = KeyHandle::new();
    let mut bob_key = KeyHandle::new();
    let mut secret_handle = SecretHandle::new();
    let mut alice_imported_bob_public_key = KeyHandle::new();

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
        let mut pub_key = vec![0u8; 600];
        let mut pub_key_size = pub_key.len() as u32;
        let result = NCryptExportKey(
            import_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut pub_key),
            ptr::addr_of_mut!(pub_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        pub_key.truncate(pub_key_size as usize);

        // Generate a ECC256 private key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_384 key encryption algorithm
        let private_key = generate_ecc_der(KeyType::Ecc256).0;
        let encrypted_blob = wrap_data(
            pub_key,
            &private_key,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        );
        let key_blob = create_pkcs11_rsa_aes_wrap_blob(
            &encrypted_blob,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        );

        // Prepare paramlist for unwrapping
        let param_buffers = [BCryptBuffer {
            cbBuffer: (BCRYPT_ECDH_P256_ALGORITHM.to_string().unwrap().len()
                * std::mem::size_of::<u16>()) as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_ECDH_P256_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        // Import the wrapped key
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            import_key.handle(),
            BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
            Some(&params),
            alice_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(alice_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Generate key for Bob
        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            bob_key.as_mut(),
            BCRYPT_ECDH_P256_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(bob_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Export Bob's public key
        let mut bob_public_key_handle = vec![0u8; 600];
        let mut bob_public_key_size = bob_public_key_handle.len() as u32;
        let result = NCryptExportKey(
            bob_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut bob_public_key_handle),
            ptr::addr_of_mut!(bob_public_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        bob_public_key_handle.truncate(bob_public_key_size as usize);

        // Key Exchange and Public Key Import for Alice
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            NCRYPT_KEY_HANDLE(0),
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            alice_imported_bob_public_key.as_mut(),
            &bob_public_key_handle,
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the imported key
        let result = NCryptFinalizeKey(alice_imported_bob_public_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Generate secret agreement
        let result = NCryptSecretAgreement(
            alice_key.handle(),
            alice_imported_bob_public_key.handle(),
            secret_handle.as_mut(),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
    }
}

#[test]
fn test_ecdh_p384_key_unwrap_with_ckm_rsa_aes_key_wrap() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut alice_key = KeyHandle::new();
    let mut bob_key = KeyHandle::new();
    let mut secret_handle = SecretHandle::new();
    let mut alice_imported_bob_public_key = KeyHandle::new();

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
        let mut pub_key = vec![0u8; 600];
        let mut pub_key_size = pub_key.len() as u32;
        let result = NCryptExportKey(
            import_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut pub_key),
            ptr::addr_of_mut!(pub_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        pub_key.truncate(pub_key_size as usize);

        // Generate a ECC384 private key
        // Wrap it with the import public key using CKM_RSA_AES_KEY_WRAP key encryption algorithm
        let private_key = generate_ecc_der(KeyType::Ecc384).0;
        let encrypted_blob = wrap_data(
            pub_key,
            &private_key,
            KeyEncryptionAlgorithm::CKM_RSA_AES_KEY_WRAP,
        );
        let key_blob = create_pkcs11_rsa_aes_wrap_blob(
            &encrypted_blob,
            KeyEncryptionAlgorithm::CKM_RSA_AES_KEY_WRAP,
        );

        // Prepare paramlist for unwrapping
        let param_buffers = [BCryptBuffer {
            cbBuffer: (BCRYPT_ECDH_P384_ALGORITHM.to_string().unwrap().len()
                * std::mem::size_of::<u16>()) as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_ECDH_P384_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        // Import the wrapped key
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            import_key.handle(),
            BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
            Some(&params),
            alice_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(alice_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Get the key length property size
        let mut key_length_property_size = 0u32;
        let result = NCryptGetProperty(
            alice_key.handle(),
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
            alice_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            Some(&mut key_length_bytes),
            ptr::addr_of_mut!(key_length_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());
        let key_length = u32::from_le_bytes(key_length_bytes.try_into().unwrap());
        assert_eq!(key_length, 384);

        // Generate key for Bob
        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            bob_key.as_mut(),
            BCRYPT_ECDH_P384_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(bob_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Export Bob's public key
        let mut bob_public_key_handle = vec![0u8; 600];
        let mut bob_public_key_size = bob_public_key_handle.len() as u32;
        let result = NCryptExportKey(
            bob_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut bob_public_key_handle),
            ptr::addr_of_mut!(bob_public_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        bob_public_key_handle.truncate(bob_public_key_size as usize);

        // Key Exchange and Public Key Import for Alice
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            NCRYPT_KEY_HANDLE(0),
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            alice_imported_bob_public_key.as_mut(),
            &bob_public_key_handle,
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the imported key
        let result = NCryptFinalizeKey(alice_imported_bob_public_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Generate secret agreement
        let result = NCryptSecretAgreement(
            alice_key.handle(),
            alice_imported_bob_public_key.handle(),
            secret_handle.as_mut(),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
    }
}

#[test]
fn test_ecdh_p384_key_unwrap_with_rsa_aes_key_wrap_256() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut alice_key = KeyHandle::new();
    let mut bob_key = KeyHandle::new();
    let mut secret_handle = SecretHandle::new();
    let mut alice_imported_bob_public_key = KeyHandle::new();

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
        let mut pub_key = vec![0u8; 600];
        let mut pub_key_size = pub_key.len() as u32;
        let result = NCryptExportKey(
            import_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut pub_key),
            ptr::addr_of_mut!(pub_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        pub_key.truncate(pub_key_size as usize);

        // Generate a ECC384 private key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_256 key encryption algorithm
        let private_key = generate_ecc_der(KeyType::Ecc384).0;
        let encrypted_blob = wrap_data(
            pub_key,
            &private_key,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        );
        let key_blob = create_pkcs11_rsa_aes_wrap_blob(
            &encrypted_blob,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        );

        // Prepare paramlist for unwrapping
        let param_buffers = [BCryptBuffer {
            cbBuffer: (BCRYPT_ECDH_ALGORITHM.to_string().unwrap().len()
                * std::mem::size_of::<u16>()) as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_ECDH_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        // Import the wrapped key
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            import_key.handle(),
            BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
            Some(&params),
            alice_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(alice_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Generate key for Bob
        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            bob_key.as_mut(),
            BCRYPT_ECDH_P384_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(bob_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Export Bob's public key
        let mut bob_public_key_handle = vec![0u8; 600];
        let mut bob_public_key_size = bob_public_key_handle.len() as u32;
        let result = NCryptExportKey(
            bob_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut bob_public_key_handle),
            ptr::addr_of_mut!(bob_public_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        bob_public_key_handle.truncate(bob_public_key_size as usize);

        // Key Exchange and Public Key Import for Alice
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            NCRYPT_KEY_HANDLE(0),
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            alice_imported_bob_public_key.as_mut(),
            &bob_public_key_handle,
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the imported key
        let result = NCryptFinalizeKey(alice_imported_bob_public_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Generate secret agreement
        let result = NCryptSecretAgreement(
            alice_key.handle(),
            alice_imported_bob_public_key.handle(),
            secret_handle.as_mut(),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
    }
}

#[test]
fn test_ecdh_p384_key_unwrap_with_rsa_aes_key_wrap_384() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut alice_key = KeyHandle::new();
    let mut bob_key = KeyHandle::new();
    let mut secret_handle = SecretHandle::new();
    let mut alice_imported_bob_public_key = KeyHandle::new();

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
        let mut pub_key = vec![0u8; 600];
        let mut pub_key_size = pub_key.len() as u32;
        let result = NCryptExportKey(
            import_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut pub_key),
            ptr::addr_of_mut!(pub_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        pub_key.truncate(pub_key_size as usize);

        // Generate a ECC384 private key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_384 key encryption algorithm
        let private_key = generate_ecc_der(KeyType::Ecc384).0;
        let encrypted_blob = wrap_data(
            pub_key,
            &private_key,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        );
        let key_blob = create_pkcs11_rsa_aes_wrap_blob(
            &encrypted_blob,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        );

        // Prepare paramlist for unwrapping
        let param_buffers = [BCryptBuffer {
            cbBuffer: (BCRYPT_ECDH_P384_ALGORITHM.to_string().unwrap().len()
                * std::mem::size_of::<u16>()) as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_ECDH_P384_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        // Import the wrapped key
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            import_key.handle(),
            BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
            Some(&params),
            alice_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(alice_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Generate key for Bob
        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            bob_key.as_mut(),
            BCRYPT_ECDH_P384_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(bob_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Export Bob's public key
        let mut bob_public_key_handle = vec![0u8; 600];
        let mut bob_public_key_size = bob_public_key_handle.len() as u32;
        let result = NCryptExportKey(
            bob_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut bob_public_key_handle),
            ptr::addr_of_mut!(bob_public_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        bob_public_key_handle.truncate(bob_public_key_size as usize);

        // Key Exchange and Public Key Import for Alice
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            NCRYPT_KEY_HANDLE(0),
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            alice_imported_bob_public_key.as_mut(),
            &bob_public_key_handle,
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the imported key
        let result = NCryptFinalizeKey(alice_imported_bob_public_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Generate secret agreement
        let result = NCryptSecretAgreement(
            alice_key.handle(),
            alice_imported_bob_public_key.handle(),
            secret_handle.as_mut(),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
    }
}

#[test]
fn test_ecdh_p521_key_unwrap_with_ckm_rsa_aes_key_wrap() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut alice_key = KeyHandle::new();
    let mut bob_key = KeyHandle::new();
    let mut secret_handle = SecretHandle::new();
    let mut alice_imported_bob_public_key = KeyHandle::new();

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
        let mut pub_key = vec![0u8; 600];
        let mut pub_key_size = pub_key.len() as u32;
        let result = NCryptExportKey(
            import_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut pub_key),
            ptr::addr_of_mut!(pub_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        pub_key.truncate(pub_key_size as usize);

        // Generate a ECC521 private key
        // Wrap it with the exported public key using CKM_RSA_AES_KEY_WRAP key encryption algorithm
        let private_key = generate_ecc_der(KeyType::Ecc521).0;
        let encrypted_blob = wrap_data(
            pub_key,
            &private_key,
            KeyEncryptionAlgorithm::CKM_RSA_AES_KEY_WRAP,
        );
        let key_blob = create_pkcs11_rsa_aes_wrap_blob(
            &encrypted_blob,
            KeyEncryptionAlgorithm::CKM_RSA_AES_KEY_WRAP,
        );

        // Prepare paramlist for unwrapping
        let param_buffers = [BCryptBuffer {
            cbBuffer: (BCRYPT_ECDH_ALGORITHM.to_string().unwrap().len()
                * std::mem::size_of::<u16>()) as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_ECDH_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        // Import the wrapped key
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            import_key.handle(),
            BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
            Some(&params),
            alice_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(alice_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Generate key for Bob
        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            bob_key.as_mut(),
            BCRYPT_ECDH_P521_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(bob_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Get the key length property size
        let mut key_length_property_size = 0u32;
        let result = NCryptGetProperty(
            alice_key.handle(),
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
            alice_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            Some(&mut key_length_bytes),
            ptr::addr_of_mut!(key_length_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());
        let key_length = u32::from_le_bytes(key_length_bytes.try_into().unwrap());
        assert_eq!(key_length, 521);

        // Export Bob's public key
        let mut bob_public_key_handle = vec![0u8; 600];
        let mut bob_public_key_size = bob_public_key_handle.len() as u32;
        let result = NCryptExportKey(
            bob_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut bob_public_key_handle),
            ptr::addr_of_mut!(bob_public_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        bob_public_key_handle.truncate(bob_public_key_size as usize);

        // Key Exchange and Public Key Import for Alice
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            NCRYPT_KEY_HANDLE(0),
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            alice_imported_bob_public_key.as_mut(),
            &bob_public_key_handle,
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the imported key
        let result = NCryptFinalizeKey(alice_imported_bob_public_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Generate secret agreement
        let result = NCryptSecretAgreement(
            alice_key.handle(),
            alice_imported_bob_public_key.handle(),
            secret_handle.as_mut(),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
    }
}

#[test]
fn test_ecdh_p521_key_unwrap_with_rsa_aes_key_wrap_256() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut alice_key = KeyHandle::new();
    let mut bob_key = KeyHandle::new();
    let mut secret_handle = SecretHandle::new();
    let mut alice_imported_bob_public_key = KeyHandle::new();

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
        let mut pub_key = vec![0u8; 600];
        let mut pub_key_size = pub_key.len() as u32;
        let result = NCryptExportKey(
            import_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut pub_key),
            ptr::addr_of_mut!(pub_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        pub_key.truncate(pub_key_size as usize);

        // Generate a ECC521 private key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_256 key encryption algorithm
        let private_key = generate_ecc_der(KeyType::Ecc521).0;
        let encrypted_blob = wrap_data(
            pub_key,
            &private_key,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        );
        let key_blob = create_pkcs11_rsa_aes_wrap_blob(
            &encrypted_blob,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        );

        // Prepare paramlist for unwrapping
        let param_buffers = [BCryptBuffer {
            cbBuffer: (BCRYPT_ECDH_P521_ALGORITHM.to_string().unwrap().len()
                * std::mem::size_of::<u16>()) as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_ECDH_P521_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        // Import the wrapped key
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            import_key.handle(),
            BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
            Some(&params),
            alice_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(alice_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Generate key for Bob
        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            bob_key.as_mut(),
            BCRYPT_ECDH_P521_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(bob_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Export Bob's public key
        let mut bob_public_key_handle = vec![0u8; 600];
        let mut bob_public_key_size = bob_public_key_handle.len() as u32;
        let result = NCryptExportKey(
            bob_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut bob_public_key_handle),
            ptr::addr_of_mut!(bob_public_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        bob_public_key_handle.truncate(bob_public_key_size as usize);

        // Key Exchange and Public Key Import for Alice
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            NCRYPT_KEY_HANDLE(0),
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            alice_imported_bob_public_key.as_mut(),
            &bob_public_key_handle,
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the imported key
        let result = NCryptFinalizeKey(alice_imported_bob_public_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Generate secret agreement
        let result = NCryptSecretAgreement(
            alice_key.handle(),
            alice_imported_bob_public_key.handle(),
            secret_handle.as_mut(),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
    }
}

#[test]
fn test_ecdh_p521_key_unwrap_with_rsa_aes_key_wrap_384() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut alice_key = KeyHandle::new();
    let mut bob_key = KeyHandle::new();
    let mut secret_handle = SecretHandle::new();
    let mut alice_imported_bob_public_key = KeyHandle::new();

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
        let mut pub_key = vec![0u8; 600];
        let mut pub_key_size = pub_key.len() as u32;
        let result = NCryptExportKey(
            import_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut pub_key),
            ptr::addr_of_mut!(pub_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        pub_key.truncate(pub_key_size as usize);

        // Generate a ECC521 private key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_384 key encryption algorithm
        let private_key = generate_ecc_der(KeyType::Ecc521).0;
        let encrypted_blob = wrap_data(
            pub_key,
            &private_key,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        );
        let key_blob = create_pkcs11_rsa_aes_wrap_blob(
            &encrypted_blob,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        );

        // Prepare paramlist for unwrapping
        let param_buffers = [BCryptBuffer {
            cbBuffer: (BCRYPT_ECDH_P521_ALGORITHM.to_string().unwrap().len()
                * std::mem::size_of::<u16>()) as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_ECDH_P521_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        // Import the wrapped key
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            import_key.handle(),
            BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
            Some(&params),
            alice_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(alice_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Generate key for Bob
        let result = NCryptCreatePersistedKey(
            azihsm_provider.handle(),
            bob_key.as_mut(),
            BCRYPT_ECDH_P521_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(bob_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Export Bob's public key
        let mut bob_public_key_handle = vec![0u8; 600];
        let mut bob_public_key_size = bob_public_key_handle.len() as u32;
        let result = NCryptExportKey(
            bob_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut bob_public_key_handle),
            ptr::addr_of_mut!(bob_public_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        bob_public_key_handle.truncate(bob_public_key_size as usize);

        // Key Exchange and Public Key Import for Alice
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            NCRYPT_KEY_HANDLE(0),
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            alice_imported_bob_public_key.as_mut(),
            &bob_public_key_handle,
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the imported key
        let result = NCryptFinalizeKey(alice_imported_bob_public_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Generate secret agreement
        let result = NCryptSecretAgreement(
            alice_key.handle(),
            alice_imported_bob_public_key.handle(),
            secret_handle.as_mut(),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
    }
}

#[test]
fn test_ecdh_p521_key_unwrap_algo_id_mismatch() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut alice_key = KeyHandle::new();

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
        let mut pub_key = vec![0u8; 600];
        let mut pub_key_size = pub_key.len() as u32;
        let result = NCryptExportKey(
            import_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut pub_key),
            ptr::addr_of_mut!(pub_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        pub_key.truncate(pub_key_size as usize);

        // Generate a ECC521 private key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_384 key encryption algorithm
        let private_key = generate_ecc_der(KeyType::Ecc521).0;
        let encrypted_blob = wrap_data(
            pub_key,
            &private_key,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        );
        let key_blob = create_pkcs11_rsa_aes_wrap_blob(
            &encrypted_blob,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_384,
        );

        // Supply wrong algo id in params list
        let param_buffers = [BCryptBuffer {
            cbBuffer: (BCRYPT_ECDH_P384_ALGORITHM.to_string().unwrap().len()
                * std::mem::size_of::<u16>()) as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_ECDH_P384_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        // Import the wrapped key
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            import_key.handle(),
            BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
            Some(&params),
            alice_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(alice_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_err(), "result {:?}", result);
    }
}

// This test ensures that the custom `RsaCrtEnabled` property is not supported
// for imported ECDH keys. (This custom key property is only intended for use
// when importing an RSA key into AZIHSM.)
#[test]
fn test_ecdh_p256_key_unwrap_with_unsupported_rsa_crt_property() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut alice_key = KeyHandle::new();

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
        let mut pub_key = vec![0u8; 600];
        let mut pub_key_size = pub_key.len() as u32;
        let result = NCryptExportKey(
            import_key.handle(),
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut pub_key),
            ptr::addr_of_mut!(pub_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        pub_key.truncate(pub_key_size as usize);

        // Generate a ECC256 private key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_256 key encryption algorithm
        let private_key = generate_ecc_der(KeyType::Ecc256).0;
        let encrypted_blob = wrap_data(
            pub_key,
            &private_key,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        );
        let key_blob = create_pkcs11_rsa_aes_wrap_blob(
            &encrypted_blob,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        );

        // Prepare paramlist for unwrapping
        let param_buffers = [BCryptBuffer {
            cbBuffer: (BCRYPT_ECDH_ALGORITHM.to_string().unwrap().len()
                * std::mem::size_of::<u16>()) as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_ECDH_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
        }];

        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        // Import the wrapped key
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            import_key.handle(),
            BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
            Some(&params),
            alice_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Next, attempt to set the `RsaCrtEnabled` property. We expect this to
        // fail, because we're importing an ECDH key, not an RSA key.
        let rsa_crt_enabled_value: u32 = 1;
        let result = NCryptSetProperty(
            alice_key.handle(),
            AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED,
            &rsa_crt_enabled_value.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_NOT_SUPPORTED));

        // We'll also attempt to retrieve the `RsaCrtEnabled` property. This
        // should also fail with the same error.
        let mut rsa_crt_enabled_value_size = 0u32;
        let result = NCryptGetProperty(
            alice_key.handle(),
            AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED,
            None,
            ptr::addr_of_mut!(rsa_crt_enabled_value_size),
            OBJECT_SECURITY_INFORMATION(0),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_NOT_SUPPORTED));
    }
}
