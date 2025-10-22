// Copyright (C) Microsoft Corporation. All rights reserved.
// This test file is specifically for testing the behavior of NCRYPT_DO_NOT_FINALIZE_FLAG for NCryptImportKey
mod common;

use std::ptr;

use crypto::rand::rand_bytes;
use widestring::WideCString;
use windows::core::*;
use windows::Win32::Security::Cryptography::*;
use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;

use crate::common::*;

#[test]
fn test_import_without_flag_then_finalize() {
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
        let private_key = generate_aes_bytes(KeyType::Aes128);
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
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(target_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_err());
    }
}

// Try to import AES CBC 128 key without NCRYPT_DO_NOT_FINALIZE_FLAG
// This should pass because it matches the default value if not provided by user
#[test]
fn test_import_aes_128_key_without_flag() {
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
        let private_key = generate_aes_bytes(KeyType::Aes128);
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
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Verify by Encrypt and decrypt data using the target key
        {
            let mut iv = [0u8; 16];
            rand_bytes(&mut iv).expect("Failed to generate random bytes");
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
            rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

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

        // Verify Key Length and Encryption Mode
        {
            const EXPECTED_KEY_LENGTH: u32 = 128;
            const EXPECTED_ENCRYPTION_MODE: PCWSTR = BCRYPT_CHAIN_MODE_CBC;

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
            assert_eq!(key_length, EXPECTED_KEY_LENGTH);

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
                WideCString::from_ptr_str(EXPECTED_ENCRYPTION_MODE.as_ptr())
            );
        }
    }
}

// Try to import AES CBC 256 key without NCRYPT_DO_NOT_FINALIZE_FLAG
// This would pass because key length is set by device, even though the key size defaults to 128
#[test]
fn test_import_aes_256_key_without_flag() {
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
        let private_key = generate_aes_bytes(KeyType::Aes256);
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
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Encrypt and decrypt data using the target key
        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).expect("Failed to generate random bytes");
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
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

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

        // Verify Key Length and Encryption Mode
        {
            const EXPECTED_KEY_LENGTH: u32 = 256;
            const EXPECTED_ENCRYPTION_MODE: PCWSTR = BCRYPT_CHAIN_MODE_CBC;

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
            assert_eq!(key_length, EXPECTED_KEY_LENGTH);

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
                WideCString::from_ptr_str(EXPECTED_ENCRYPTION_MODE.as_ptr())
            );
        }
    }
}

// Try to import AES GCM key without NCRYPT_DO_NOT_FINALIZE_FLAG
// This should fail because encryption mode doesn't match the default value
#[test]
#[cfg(not(feature = "disable-fp"))]
fn test_import_aes_gcm_256_key_without_flag() {
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
        let private_key = generate_aes_bytes(KeyType::Aes256);
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
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Try to use the key for AES GCM Encryption
        // Should fail
        {
            let (mut iv, mut aad, mut tag) = test_helper_create_iv_aad_tag(target_key.handle());

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
            rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

            // Get Ciphertext length
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
            assert!(result.is_err());
        }
    }
}

// Unwrap and import a RSA 2K key without NCRYPT_DO_NOT_FINALIZE_FLAG
// Should pass because default size matches actual size
#[test]
fn test_import_rsa_2k_key_without_flag() {
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

        // Generate a KeyType::Rsa2k RSA private key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_256 key encryption algorithm
        let private_key = generate_rsa_der(KeyType::Rsa2k).0;
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
            cbBuffer: (BCRYPT_RSA_ALGORITHM.to_string().unwrap().len() * std::mem::size_of::<u16>())
                as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_RSA_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
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
            NCRYPT_FLAGS(0), // Without NCRYPT_DO_NOT_FINALIZE_FLAG
        );
        assert!(result.is_ok());

        // Verify Key Length and Usage
        {
            // 2K RSA Key
            const EXPECTED_KEY_LENGTH: u32 = 2048;
            const EXPECTED_KEY_USAGE: u32 = NCRYPT_ALLOW_SIGNING_FLAG;

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
            assert_eq!(key_length, EXPECTED_KEY_LENGTH);

            // Get the key usage property size
            let mut usage_property_size = 0u32;
            let result = NCryptGetProperty(
                target_key.handle(),
                NCRYPT_KEY_USAGE_PROPERTY,
                None,
                ptr::addr_of_mut!(usage_property_size),
                OBJECT_SECURITY_INFORMATION(0),
            );
            assert!(result.is_ok());
            assert_eq!(usage_property_size, size_of::<u32>() as u32);

            // Get the key usage property value
            let mut usage_bytes = vec![0u8; usage_property_size as usize];
            let result = NCryptGetProperty(
                target_key.handle(),
                NCRYPT_KEY_USAGE_PROPERTY,
                Some(&mut usage_bytes),
                ptr::addr_of_mut!(usage_property_size),
                OBJECT_SECURITY_INFORMATION(0),
            );
            assert!(result.is_ok());
            let key_usage = u32::from_le_bytes(usage_bytes.try_into().unwrap());
            assert_eq!(key_usage, EXPECTED_KEY_USAGE);
        }

        // Use the key to sign/verify
        test_helper_rsa_sign_verify(
            &target_key,
            &KeyType::Rsa2k,
            Some(NCryptPaddingType::Pkcs1),
            Some(NCryptPaddingType::Pkcs1),
            NCryptShaAlgorithm::Sha256,
            false,
            false,
        );
    }
}

// Unwrap and import a RSA 4K key without NCRYPT_DO_NOT_FINALIZE_FLAG
// Should pass because key size is determined by the device
#[test]
fn test_import_rsa_4k_key_without_flag() {
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

        // Generate a KeyType::Rsa4k RSA private key
        // Wrap it with the import public key using RSA_AES_KEY_WRAP_256 key encryption algorithm
        let private_key = generate_rsa_der(KeyType::Rsa4k).0;
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
            cbBuffer: (BCRYPT_RSA_ALGORITHM.to_string().unwrap().len() * std::mem::size_of::<u16>())
                as u32,
            BufferType: NCRYPTBUFFER_PKCS_ALG_ID,
            pvBuffer: BCRYPT_RSA_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
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
            NCRYPT_FLAGS(0), // Without NCRYPT_DO_NOT_FINALIZE_FLAG
        );
        assert!(result.is_ok());

        // Verify Key Length and Usage
        {
            // 4K RSA Key
            const EXPECTED_KEY_LENGTH: u32 = 4096;
            const EXPECTED_KEY_USAGE: u32 = NCRYPT_ALLOW_SIGNING_FLAG;

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
            assert_eq!(key_length, EXPECTED_KEY_LENGTH);

            // Get the key usage property size
            let mut usage_property_size = 0u32;
            let result = NCryptGetProperty(
                target_key.handle(),
                NCRYPT_KEY_USAGE_PROPERTY,
                None,
                ptr::addr_of_mut!(usage_property_size),
                OBJECT_SECURITY_INFORMATION(0),
            );
            assert!(result.is_ok());
            assert_eq!(usage_property_size, size_of::<u32>() as u32);

            // Get the key usage property value
            let mut usage_bytes = vec![0u8; usage_property_size as usize];
            let result = NCryptGetProperty(
                target_key.handle(),
                NCRYPT_KEY_USAGE_PROPERTY,
                Some(&mut usage_bytes),
                ptr::addr_of_mut!(usage_property_size),
                OBJECT_SECURITY_INFORMATION(0),
            );
            assert!(result.is_ok());
            let key_usage = u32::from_le_bytes(usage_bytes.try_into().unwrap());
            assert_eq!(key_usage, EXPECTED_KEY_USAGE);
        }

        // Use the key to sign/verify
        test_helper_rsa_sign_verify(
            &target_key,
            &KeyType::Rsa4k,
            Some(NCryptPaddingType::Pkcs1),
            Some(NCryptPaddingType::Pkcs1),
            NCryptShaAlgorithm::Sha512,
            false,
            false,
        );
    }
}

// Unwrap and import a ECDH P256 key without NCRYPT_DO_NOT_FINALIZE_FLAG
// Should pass because Curve type is determined by device
#[test]
fn test_import_ecdh_256_key_without_flag() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut alice_key = KeyHandle::new();
    let mut bob_key = KeyHandle::new();
    let mut secret_handle = SecretHandle::new();
    let mut alice_imported_bob_public_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        // Alice Wrap and import ECDH Key
        {
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
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_ok());
        }

        // Alice import Bob ECC Public Key
        {
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
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_ok());
        };

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

// Unwrap and import a ECDH P521 key without NCRYPT_DO_NOT_FINALIZE_FLAG
// Should pass because Curve type is determined by device
#[test]
fn test_import_ecdh_521_key_without_flag() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut alice_key = KeyHandle::new();
    let mut bob_key = KeyHandle::new();
    let mut secret_handle = SecretHandle::new();
    let mut alice_imported_bob_public_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        // Alice Wrap and import ECDH P521 Key
        {
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
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_ok());
        }

        // Alice import Bob ECC Public Key
        {
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
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_ok());
        };

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

// Unwrap and import a ECDSA P256 key without NCRYPT_DO_NOT_FINALIZE_FLAG
#[test]
fn test_import_ecdsa_256_key_without_flag() {
    let mut azihsm_provider = ProviderHandle::new();
    let mut import_key = KeyHandle::new();
    let mut target_key = KeyHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        // Open handle to the built-in import key
        let pub_key = {
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

            pub_key
        };

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

        // Import the wrapped key
        let result = NCryptImportKey(
            azihsm_provider.handle(),
            import_key.handle(),
            BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
            Some(&params),
            target_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Sign and verify a hash with the target key
        let mut digest = [0u8; 32];
        rand_bytes(&mut digest).expect("Failed to generate random bytes");
        let mut signature_size = 0u32;
        let result = NCryptSignHash(
            target_key.handle(),
            None,
            &digest,
            None,
            ptr::addr_of_mut!(signature_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        assert_eq!(signature_size, 64);

        let mut signature = vec![0u8; signature_size as usize];
        let result = NCryptSignHash(
            target_key.handle(),
            None,
            &digest,
            Some(&mut signature),
            ptr::addr_of_mut!(signature_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptVerifySignature(
            target_key.handle(),
            None,
            &digest,
            &signature,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
    }
}
