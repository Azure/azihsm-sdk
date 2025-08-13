// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use std::mem::size_of;
use std::ptr;

use openssl::rand::rand_bytes;
use widestring::*;
use winapi::shared::winerror::NTE_NOT_SUPPORTED;
use windows::core::HRESULT;
use windows::Win32::Security::Cryptography::*;
use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;

use crate::common::*;

#[test]
fn test_aes_cbc_128_key_unwrap_encryption_mode_not_set() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut target_key = KeyHandle::new();

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

        // Generate an AES 128 key
        // Wrap it with the import public key using CKM_RSA_AES_KEY_WRAP key encryption algorithm
        let private_key = generate_aes(KeyType::Aes128);
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
            cbBuffer: (BCRYPT_AES_ALGORITHM.to_string().unwrap().len() * std::mem::size_of::<u16>())
                as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_AES_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
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
            target_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(target_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_err(), "result {:?}", result);
    }
}

#[test]
fn test_aes_cbc_128_key_unwrap_with_ckm_rsa_aes_key_wrap() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut target_key = KeyHandle::new();

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

        // Generate an AES 128 key
        // Wrap it with the import public key using CKM_RSA_AES_KEY_WRAP key encryption algorithm
        let private_key = generate_aes(KeyType::Aes128);
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
            cbBuffer: (BCRYPT_AES_ALGORITHM.to_string().unwrap().len() * std::mem::size_of::<u16>())
                as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_AES_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
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
            target_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(target_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Get the key length property size
        let mut key_length_property_size = 0u32;
        let result = NCryptGetProperty(
            target_key.handle(),
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
            target_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            Some(&mut key_length_bytes),
            ptr::addr_of_mut!(key_length_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());
        let key_length = u32::from_le_bytes(key_length_bytes.try_into().unwrap());
        assert_eq!(key_length, 128);

        // Get the chaining mode property size
        let mut chaining_mode_property_size = 0u32;
        let result = NCryptGetProperty(
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            None,
            ptr::addr_of_mut!(chaining_mode_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());

        // Get the chaining mode property value
        let mut chaining_mode_bytes = vec![0u8; chaining_mode_property_size as usize];
        let result = NCryptGetProperty(
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            Some(&mut chaining_mode_bytes),
            ptr::addr_of_mut!(chaining_mode_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());
        let chaining_mode = byte_slice_to_pcwstr(&chaining_mode_bytes).unwrap();
        assert_eq!(
            WideCString::from_ptr_str(chaining_mode.as_ptr()),
            WideCString::from_ptr_str(BCRYPT_CHAIN_MODE_CBC.as_ptr())
        );

        // Encrypt and decrypt data using the target key
        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).unwrap();
        let mut iv_orig = iv;

        let mut padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: iv.as_mut_ptr(),
            cbIV: iv.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        let mut decrypted = [0u8; 128];
        let mut decrypted_len = 0u32;
        padding_info.pbIV = iv_orig.as_mut_ptr();

        let result = NCryptDecrypt(
            target_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        assert_eq!(plaintext, decrypted);
    }
}

#[test]
fn test_aes_cbc_128_key_unwrap_with_rsa_aes_key_wrap_256() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut target_key = KeyHandle::new();

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

        // Generate an AES 128 key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_256 key encryption algorithm
        let private_key = generate_aes(KeyType::Aes128);
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
            cbBuffer: (BCRYPT_AES_ALGORITHM.to_string().unwrap().len() * std::mem::size_of::<u16>())
                as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_AES_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
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
            target_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(target_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Encrypt and decrypt data using the target key
        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).unwrap();
        let mut iv_orig = iv;

        let mut padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: iv.as_mut_ptr(),
            cbIV: iv.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        let mut decrypted = [0u8; 128];
        let mut decrypted_len = 0u32;
        padding_info.pbIV = iv_orig.as_mut_ptr();

        let result = NCryptDecrypt(
            target_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        assert_eq!(plaintext, decrypted);
    }
}

#[test]
fn test_aes_cbc_128_key_unwrap_with_rsa_aes_key_wrap_384() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut target_key = KeyHandle::new();

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

        // Generate an AES 128 key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_384 key encryption algorithm
        let private_key = generate_aes(KeyType::Aes128);
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
            cbBuffer: (BCRYPT_AES_ALGORITHM.to_string().unwrap().len() * std::mem::size_of::<u16>())
                as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_AES_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
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
            target_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(target_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Encrypt and decrypt data using the target key
        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).unwrap();
        let mut iv_orig = iv;

        let mut padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: iv.as_mut_ptr(),
            cbIV: iv.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        let mut decrypted = [0u8; 128];
        let mut decrypted_len = 0u32;
        padding_info.pbIV = iv_orig.as_mut_ptr();

        let result = NCryptDecrypt(
            target_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        assert_eq!(plaintext, decrypted);
    }
}

#[test]
fn test_aes_cbc_192_key_unwrap_with_ckm_rsa_aes_key_wrap() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut target_key = KeyHandle::new();

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

        // Generate an AES 192 key
        // Wrap it with the import public key using CKM_RSA_AES_KEY_WRAP key encryption algorithm
        let private_key = generate_aes(KeyType::Aes192);
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
            cbBuffer: (BCRYPT_AES_ALGORITHM.to_string().unwrap().len() * std::mem::size_of::<u16>())
                as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_AES_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
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
            target_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(target_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Get the key length property size
        let mut key_length_property_size = 0u32;
        let result = NCryptGetProperty(
            target_key.handle(),
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
            target_key.handle(),
            NCRYPT_LENGTH_PROPERTY,
            Some(&mut key_length_bytes),
            ptr::addr_of_mut!(key_length_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());
        let key_length = u32::from_le_bytes(key_length_bytes.try_into().unwrap());
        assert_eq!(key_length, 192);

        // Get the chaining mode property size
        let mut chaining_mode_property_size = 0u32;
        let result = NCryptGetProperty(
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            None,
            ptr::addr_of_mut!(chaining_mode_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());

        // Get the chaining mode property value
        let mut chaining_mode_bytes = vec![0u8; chaining_mode_property_size as usize];
        let result = NCryptGetProperty(
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            Some(&mut chaining_mode_bytes),
            ptr::addr_of_mut!(chaining_mode_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());
        let chaining_mode = byte_slice_to_pcwstr(&chaining_mode_bytes).unwrap();
        assert_eq!(
            WideCString::from_ptr_str(chaining_mode.as_ptr()),
            WideCString::from_ptr_str(BCRYPT_CHAIN_MODE_CBC.as_ptr())
        );

        // Encrypt and decrypt data using the target key
        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).unwrap();
        let mut iv_orig = iv;

        let mut padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: iv.as_mut_ptr(),
            cbIV: iv.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        let mut decrypted = [0u8; 128];
        let mut decrypted_len = 0u32;
        padding_info.pbIV = iv_orig.as_mut_ptr();

        let result = NCryptDecrypt(
            target_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        assert_eq!(plaintext, decrypted);
    }
}

#[test]
fn test_aes_cbc_192_key_unwrap_with_rsa_aes_key_wrap_256() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut target_key = KeyHandle::new();

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

        // Generate an AES 192 key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_256 key encryption algorithm
        let private_key = generate_aes(KeyType::Aes192);
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
            cbBuffer: (BCRYPT_AES_ALGORITHM.to_string().unwrap().len() * std::mem::size_of::<u16>())
                as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_AES_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
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
            target_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(target_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Encrypt and decrypt data using the target key
        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).unwrap();
        let mut iv_orig = iv;

        let mut padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: iv.as_mut_ptr(),
            cbIV: iv.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        let mut decrypted = [0u8; 128];
        let mut decrypted_len = 0u32;
        padding_info.pbIV = iv_orig.as_mut_ptr();

        let result = NCryptDecrypt(
            target_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        assert_eq!(plaintext, decrypted);
    }
}

#[test]
fn test_aes_cbc_192_key_unwrap_with_rsa_aes_key_wrap_384() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut target_key = KeyHandle::new();

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

        // Generate an AES 192 key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_384 key encryption algorithm
        let private_key = generate_aes(KeyType::Aes192);
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
            cbBuffer: (BCRYPT_AES_ALGORITHM.to_string().unwrap().len() * std::mem::size_of::<u16>())
                as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_AES_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
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
            target_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(target_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Encrypt and decrypt data using the target key
        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).unwrap();
        let mut iv_orig = iv;

        let mut padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: iv.as_mut_ptr(),
            cbIV: iv.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        let mut decrypted = [0u8; 128];
        let mut decrypted_len = 0u32;
        padding_info.pbIV = iv_orig.as_mut_ptr();

        let result = NCryptDecrypt(
            target_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        assert_eq!(plaintext, decrypted);
    }
}

#[test]
fn test_aes_cbc_256_key_unwrap_with_ckm_rsa_aes_key_wrap() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut target_key = KeyHandle::new();

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

        // Generate an AES 256 key
        // Wrap it with the import public key using CKM_RSA_AES_KEY_WRAP key encryption algorithm
        let private_key = generate_aes(KeyType::Aes256);
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
            cbBuffer: (BCRYPT_AES_ALGORITHM.to_string().unwrap().len() * std::mem::size_of::<u16>())
                as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_AES_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
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
            target_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(target_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Get the key length property size
        let mut key_length_property_size = 0u32;
        let result = NCryptGetProperty(
            target_key.handle(),
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
            target_key.handle(),
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
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            None,
            ptr::addr_of_mut!(chaining_mode_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());

        // Get the chaining mode property value
        let mut chaining_mode_bytes = vec![0u8; chaining_mode_property_size as usize];
        let result = NCryptGetProperty(
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            Some(&mut chaining_mode_bytes),
            ptr::addr_of_mut!(chaining_mode_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());
        let chaining_mode = byte_slice_to_pcwstr(&chaining_mode_bytes).unwrap();
        assert_eq!(
            WideCString::from_ptr_str(chaining_mode.as_ptr()),
            WideCString::from_ptr_str(BCRYPT_CHAIN_MODE_CBC.as_ptr())
        );

        // Encrypt and decrypt data using the target key
        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).unwrap();
        let mut iv_orig = iv;

        let mut padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: iv.as_mut_ptr(),
            cbIV: iv.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        let mut decrypted = [0u8; 128];
        let mut decrypted_len = 0u32;
        padding_info.pbIV = iv_orig.as_mut_ptr();

        let result = NCryptDecrypt(
            target_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        assert_eq!(plaintext, decrypted);
    }
}

#[test]
fn test_aes_cbc_256_key_unwrap_with_rsa_aes_key_wrap_256() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut target_key = KeyHandle::new();

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

        // Generate an AES 256 key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_256 key encryption algorithm
        let private_key = generate_aes(KeyType::Aes256);
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
            cbBuffer: (BCRYPT_AES_ALGORITHM.to_string().unwrap().len() * std::mem::size_of::<u16>())
                as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_AES_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
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
            target_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(target_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Encrypt and decrypt data using the target key
        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).unwrap();
        let mut iv_orig = iv;

        let mut padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: iv.as_mut_ptr(),
            cbIV: iv.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        let mut decrypted = [0u8; 128];
        let mut decrypted_len = 0u32;
        padding_info.pbIV = iv_orig.as_mut_ptr();

        let result = NCryptDecrypt(
            target_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        assert_eq!(plaintext, decrypted);
    }
}

#[test]
fn test_aes_cbc_256_key_unwrap_with_rsa_aes_key_wrap_384() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut target_key = KeyHandle::new();

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

        // Generate an AES 256 key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_384 key encryption algorithm
        let private_key = generate_aes(KeyType::Aes256);
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
            cbBuffer: (BCRYPT_AES_ALGORITHM.to_string().unwrap().len() * std::mem::size_of::<u16>())
                as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_AES_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
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
            target_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(target_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Encrypt and decrypt data using the target key
        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).unwrap();
        let mut iv_orig = iv;

        let mut padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: iv.as_mut_ptr(),
            cbIV: iv.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        let mut decrypted = [0u8; 128];
        let mut decrypted_len = 0u32;
        padding_info.pbIV = iv_orig.as_mut_ptr();

        let result = NCryptDecrypt(
            target_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        assert_eq!(plaintext, decrypted);
    }
}

#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_256_key_unwrap_with_ckm_rsa_aes_key_wrap() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut target_key = KeyHandle::new();

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

        // Generate an AES 256 key
        // Wrap it with the import public key using CKM_RSA_AES_KEY_WRAP key encryption algorithm
        let private_key = generate_aes(KeyType::Aes256);
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
            cbBuffer: (BCRYPT_AES_ALGORITHM.to_string().unwrap().len() * std::mem::size_of::<u16>())
                as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_AES_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
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
            target_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_GCM.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_GCM.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(target_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Get the key length property size
        let mut key_length_property_size = 0u32;
        let result = NCryptGetProperty(
            target_key.handle(),
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
            target_key.handle(),
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
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            None,
            ptr::addr_of_mut!(chaining_mode_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );

        assert!(result.is_ok());

        // Get the chaining mode property value
        let mut chaining_mode_bytes = vec![0u8; chaining_mode_property_size as usize];
        let result = NCryptGetProperty(
            target_key.handle(),
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
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_256_key_unwrap_with_rsa_aes_key_wrap_256() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut target_key = KeyHandle::new();

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

        // Generate an AES 256 key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_256 key encryption algorithm
        let private_key = generate_aes(KeyType::Aes256);
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
            cbBuffer: (BCRYPT_AES_ALGORITHM.to_string().unwrap().len() * std::mem::size_of::<u16>())
                as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_AES_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
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
            target_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_GCM.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_GCM.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(target_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());
    }
}

#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_aes_gcm_256_key_unwrap_with_rsa_aes_key_wrap_384() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut target_key = KeyHandle::new();

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

        // Generate an AES 256 key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_384 key encryption algorithm
        let private_key = generate_aes(KeyType::Aes256);
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
            cbBuffer: (BCRYPT_AES_ALGORITHM.to_string().unwrap().len() * std::mem::size_of::<u16>())
                as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_AES_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
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
            target_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_GCM.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_GCM.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Finalize the target key
        let result = NCryptFinalizeKey(target_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Encrypt and decrypt data using the target key
        let mut iv = [0u8; AES_GCM_IV_SIZE];
        rand_bytes(&mut iv).unwrap();

        let mut aad = [0u8; AES_GCM_AAD_SIZE];
        rand_bytes(&mut aad).unwrap();

        let mut tag_length_property_size = 0u32;
        let result = NCryptGetProperty(
            target_key.handle(),
            BCRYPT_AUTH_TAG_LENGTH,
            None,
            ptr::addr_of_mut!(tag_length_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );
        assert!(result.is_ok());
        assert_eq!(tag_length_property_size, size_of::<u32>() as u32);
        let mut tag_length_bytes = vec![0u8; tag_length_property_size as usize];

        let result = NCryptGetProperty(
            target_key.handle(),
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
        rand_bytes(&mut plaintext).unwrap();

        let result = NCryptEncrypt(
            target_key.handle(),
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
            target_key.handle(),
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
            target_key.handle(),
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
            target_key.handle(),
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
#[cfg(feature = "disable-fp")]
fn test_aes_gcm_key_import_not_supported() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut target_key = KeyHandle::new();

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

        // Generate an AES 256 key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_384 key encryption algorithm
        let private_key = generate_aes(KeyType::Aes256);
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
            cbBuffer: (BCRYPT_AES_ALGORITHM.to_string().unwrap().len() * std::mem::size_of::<u16>())
                as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_AES_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
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
            target_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Confirm we can't set encryption mode to GCM
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_GCM.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_GCM.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_err(), "result: {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_NOT_SUPPORTED));
    }
}

// This test ensures that the custom `RsaCrtEnabled` property is not supported
// for imported AES keys.  (This custom key property is only intended for use
// when importing an RSA key into AZIHSM.)
#[test]
fn test_aes_cbc_256_key_unwrap_with_unsupported_rsa_crt_property() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut target_key = KeyHandle::new();

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

        // Generate an AES 256 key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_256 key encryption algorithm
        let private_key = generate_aes(KeyType::Aes256);
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
            cbBuffer: (BCRYPT_AES_ALGORITHM.to_string().unwrap().len() * std::mem::size_of::<u16>())
                as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_AES_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
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
            target_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            target_key.handle(),
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Next, attempt to set the `RsaCrtEnabled` property. We expect this to
        // fail, because we're importing an AES key, not an RSA key.
        let rsa_crt_enabled_value: u32 = 1;
        let result = NCryptSetProperty(
            target_key.handle(),
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
            target_key.handle(),
            AZIHSM_KEY_PROPERTY_RSA_CRT_ENABLED,
            None,
            ptr::addr_of_mut!(rsa_crt_enabled_value_size),
            OBJECT_SECURITY_INFORMATION(0),
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_NOT_SUPPORTED));
    }
}

// This test ensures that the KSP does *not* support AES-XTS key import. It
// checks to ensure that an appropriate error code (`NTE_NOT_SUPPORTED`) is
// returned when attempting to import an AES-XTS key.
#[test]
fn test_aes_xts_key_import_not_supported() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut target_key = KeyHandle::new();

    unsafe {
        // Open a handle to the AzIHSM KSP
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

        // Next, generate *two* AES-256 keys. AES-XTS-512 (which is supported
        // by AzIHSM) works by using two individual AES-256 keys.
        //
        // We'll combine these two keys' bytes together when we wrap it up with
        // the AzIHSM built-in unwrapping key.
        let private_key_1 = generate_aes(KeyType::Aes256);
        let private_key_2 = generate_aes(KeyType::Aes256);
        let mut private_key_combined = private_key_1.clone();
        private_key_combined.extend(private_key_2.as_slice());

        // Next, wrap the combined private keys into a blob, which we'll use to
        // import into NCrypt.
        let encrypted_blob = wrap_data(
            pub_key,
            &private_key_combined,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        );
        let key_blob = create_pkcs11_rsa_aes_wrap_blob(
            &encrypted_blob,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        );

        // Prepare the NCrypt buffers and parameter list, which we'll pass into
        // `NCryptImportKey()`. Specify `BCRYPT_XTS_AES_ALGORITHM` to indicate
        // that we'd like to import an AES-XTS key.
        let param_buffers = [BCryptBuffer {
            cbBuffer: (BCRYPT_XTS_AES_ALGORITHM.to_string().unwrap().len()
                * std::mem::size_of::<u16>()) as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_XTS_AES_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
        }];
        let params = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: param_buffers.len() as u32,
            pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        // Invoke `NCryptImportKey()` to import the two wrapped AES-256 keys.
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            import_key.handle(),
            BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
            Some(&params),
            target_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );

        // The key import should fail here; the KSP should return that secure
        // key import does not support AES-XTS
        assert!(result.is_err(), "result: {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_NOT_SUPPORTED));
    }
}
