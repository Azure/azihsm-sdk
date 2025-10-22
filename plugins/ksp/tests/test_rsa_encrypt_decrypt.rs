// Copyright (C) Microsoft Corporation. All rights reserved.
mod common;
use std::ptr;

use crypto::rand::rand_bytes;
use winapi::shared::winerror::ERROR_INVALID_STATE;
use winapi::shared::winerror::E_UNEXPECTED;
use winapi::shared::winerror::NTE_BAD_DATA;
use winapi::shared::winerror::NTE_BAD_FLAGS;
use winapi::shared::winerror::NTE_BAD_KEY;
use winapi::shared::winerror::NTE_BUFFER_TOO_SMALL;
use winapi::shared::winerror::NTE_INVALID_HANDLE;
use winapi::shared::winerror::NTE_INVALID_PARAMETER;
use windows::core::Owned;
use windows::core::HRESULT;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::*;
use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;

use crate::common::*;

#[test]
fn test_rsa_import_key_donotfinalize_flag_not_set() {
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
            NCRYPT_FLAGS(0), // No NCRYPT_DO_NOT_FINALIZE_FLAG set
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
    }
}

// Use DO_NOT_FINALIZE_FLAG but don't call `NCryptFinalize`
fn test_helper_rsa_encrypt_without_finalize(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_alg: NCryptShaAlgorithm,
    enable_crt: Option<bool>,
) {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        // Generate and import an RSA private key, but don't finalize it
        let (_, target_key) =
            import_wrapped_key_not_finalized(azihsm_provider.handle(), key_type, key_enc_algo);

        // Set the target key usage to `EncryptDecrypt`
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let result = NCryptSetProperty(
            target_key.handle(),
            NCRYPT_KEY_USAGE_PROPERTY,
            &key_usage.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set the `RsaCrtEnabled` property to enable or disable CRT for this
        // key, if a value was given
        if let Some(enable_crt_val) = enable_crt {
            // We pass in `1` for the expected initial value, because RSA keys
            // are, by default, imported with CRT enabled. This means the
            // `RsaCrtEnabled` property should return `1`.
            set_key_rsa_crt_enabled_property_withcheck(&target_key, enable_crt_val as u32, 1);
        }

        // No Finalize call.

        // Next, attempt to encrypt via `NCryptEncrypt()`. This should fail with an
        // `NTE_INVALID_STATE` error, since the key was never finalized.
        let padding_info: BCRYPT_OAEP_PADDING_INFO = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: padding_alg.into(),
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        };
        let mut plaintext = [0u8; 100];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(
            result.unwrap_err().code(),
            HRESULT::from_win32(ERROR_INVALID_STATE)
        );
    }
}

#[test]
fn test_rsa_2k_encrypt_without_finalize() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_without_finalize(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch the RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_without_finalize_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_without_finalize(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_without_finalize_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_without_finalize(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_without_finalize() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_without_finalize(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch the RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_without_finalize_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_without_finalize(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_without_finalize_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_without_finalize(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_without_finalize() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_without_finalize(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch the RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_without_finalize_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_without_finalize(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_without_finalize_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_without_finalize(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

fn test_helper_rsa_finalize_without_key_usage(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    enable_crt: Option<bool>,
) {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        // Generate and import an RSA private key, but don't finalize it
        let (_, target_key) =
            import_wrapped_key_not_finalized(azihsm_provider.handle(), key_type, key_enc_algo);

        // No Key Usage set.

        // Set the `RsaCrtEnabled` property to enable or disable CRT for this
        // key, before we finalize it, if a value was given.
        if let Some(enable_crt_val) = enable_crt {
            // We pass in `1` for the expected initial value, because RSA keys
            // are, by default, imported with CRT enabled. This means the
            // `RsaCrtEnabled` property should return `1`.
            set_key_rsa_crt_enabled_property_withcheck(&target_key, enable_crt_val as u32, 1);
        }

        // Finalize the key; we should receive an error, because we never set
        // the key usage before finalizing the key.
        let result = NCryptFinalizeKey(target_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BAD_KEY));
    }
}

#[test]
fn test_rsa_finalize_without_key_usage() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_finalize_without_key_usage(
            KeyType::Rsa2k,
            *key_enc_alg,
            None, // don't touch the RSA-CRT property
        );
    }
}

#[test]
fn test_rsa_finalize_without_key_usage_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_finalize_without_key_usage(
            KeyType::Rsa2k,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
        );
    }
}

#[test]
fn test_rsa_finalize_without_key_usage_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_finalize_without_key_usage(
            KeyType::Rsa2k,
            *key_enc_alg,
            Some(false), // intentionally enable RSA-CRT
        );
    }
}

// Check if `NCryptEncrypt()` returns the correct number of bytes needed
fn test_helper_rsa_encrypt_decrypt_required_input_buffer_size(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_alg: NCryptShaAlgorithm,
    enable_crt: Option<bool>,
) {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let (_import_key, target_key) = import_wrapped_key(
            azihsm_provider.handle(),
            key_type,
            key_enc_algo,
            NCRYPT_ALLOW_DECRYPT_FLAG,
            enable_crt,
        );

        // Invoke `NCryptEncrypt()` a single time, to retrieve the number of
        // bytes required to store the ciphertext.

        let padding_info: BCRYPT_OAEP_PADDING_INFO = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: padding_alg.into(),
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        };
        let mut plaintext = [0u8; 100];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_ok());

        // Make sure the returned value matches what we expect, considering the
        // size of the key.
        let expected_ciphertext_len = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };
        assert_eq!(ciphertext_len, expected_ciphertext_len as u32);
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_required_input_buffer_size() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_required_input_buffer_size_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_required_input_buffer_size_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_required_input_buffer_size() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_required_input_buffer_size_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_required_input_buffer_size_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_required_input_buffer_size() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_required_input_buffer_size_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_required_input_buffer_size_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

fn test_helper_rsa_encrypt_decrypt_required_input_buffer_size_lt_required(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_alg: NCryptShaAlgorithm,
    enable_crt: Option<bool>,
) {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let (_import_key, target_key) = import_wrapped_key(
            azihsm_provider.handle(),
            key_type,
            key_enc_algo,
            NCRYPT_ALLOW_DECRYPT_FLAG,
            enable_crt,
        );

        // Invoke `NCryptEncrypt()` a single time, to retrieve the number of
        // bytes required to store the ciphertext.

        let padding_info: BCRYPT_OAEP_PADDING_INFO = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: padding_alg.into(),
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        };
        let mut plaintext = [0u8; 100];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_ok());

        // Make sure the returned value matches what we expect, considering the
        // size of the key.
        let expected_ciphertext_len = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };
        assert_eq!(ciphertext_len, expected_ciphertext_len as u32);

        // Subtract 1 from the required output buffer size, then attempt to
        // encrypt a buffer. This should failed with `NTE_BUFFER_TOO_SMALL`.
        let mut ciphertext = vec![0u8; expected_ciphertext_len - 1];
        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BUFFER_TOO_SMALL));
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_required_input_buffer_size_lt_required() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size_lt_required(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_required_input_buffer_size_lt_required_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size_lt_required(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_required_input_buffer_size_lt_required_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size_lt_required(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_required_input_buffer_size_lt_required() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size_lt_required(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_required_input_buffer_size_lt_required_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size_lt_required(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_required_input_buffer_size_lt_required_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size_lt_required(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_required_input_buffer_size_lt_required() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size_lt_required(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_required_input_buffer_size_lt_required_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size_lt_required(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_required_input_buffer_size_lt_required_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size_lt_required(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

fn test_helper_rsa_encrypt_decrypt_required_input_buffer_size_gt_required(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_alg: NCryptShaAlgorithm,
    enable_crt: Option<bool>,
) {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let (_import_key, target_key) = import_wrapped_key(
            azihsm_provider.handle(),
            key_type,
            key_enc_algo,
            NCRYPT_ALLOW_DECRYPT_FLAG,
            enable_crt,
        );

        // Invoke `NCryptEncrypt()` a single time, to retrieve the number of
        // bytes required to store the ciphertext.

        let padding_info: BCRYPT_OAEP_PADDING_INFO = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: padding_alg.into(),
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        };
        let mut plaintext = [0u8; 100];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_ok());

        // Make sure the returned value matches what we expect, considering the
        // size of the key.
        let expected_ciphertext_len = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };
        assert_eq!(ciphertext_len, expected_ciphertext_len as u32);

        // Add 1 to the required output buffer size.
        let mut ciphertext = vec![0u8; expected_ciphertext_len + 1];
        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, expected_ciphertext_len as u32);
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_required_input_buffer_size_gt_required() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size_gt_required(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_required_input_buffer_size_gt_required_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size_gt_required(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_required_input_buffer_size_gt_required_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size_gt_required(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_required_input_buffer_size_gt_required() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size_gt_required(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_required_input_buffer_size_gt_required_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size_gt_required(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_required_input_buffer_size_gt_required_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size_gt_required(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_required_input_buffer_size_gt_required() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size_gt_required(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_required_input_buffer_size_gt_required_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size_gt_required(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_required_input_buffer_size_gt_required_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_input_buffer_size_gt_required(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

// Check if `NCryptDecrypt()` returns the correct number of bytes needed
fn test_helper_rsa_encrypt_decrypt_required_output_buffer_size(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_alg: NCryptShaAlgorithm,
    enable_crt: Option<bool>,
) {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let (_import_key, target_key) = import_wrapped_key(
            azihsm_provider.handle(),
            key_type,
            key_enc_algo,
            NCRYPT_ALLOW_DECRYPT_FLAG,
            enable_crt,
        );

        // Invoke `NCryptDecrypt()` a single time, to retrieve the number of
        // bytes required to store the plaintext.

        let padding_info: BCRYPT_OAEP_PADDING_INFO = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: padding_alg.into(),
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        };
        let mut decrypted_len = 0u32;
        let ciphertext = [0u8; RSA_2K_DATA_SIZE_LIMIT];

        let result = NCryptDecrypt(
            target_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_ok());
        assert!(decrypted_len <= (ciphertext.len() as u32));
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_required_output_buffer_size() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_required_output_buffer_size_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_required_output_buffer_size_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_required_output_buffer_size() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_required_output_buffer_size_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_required_output_buffer_size_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_required_output_buffer_size() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_required_output_buffer_size_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_required_output_buffer_size_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

fn test_helper_rsa_encrypt_decrypt_required_output_buffer_size_lt_required(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_alg: NCryptShaAlgorithm,
    enable_crt: Option<bool>,
) {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let (_import_key, target_key) = import_wrapped_key(
            azihsm_provider.handle(),
            key_type,
            key_enc_algo,
            NCRYPT_ALLOW_DECRYPT_FLAG,
            enable_crt,
        );

        // Invoke `NCryptDecrypt()` a single time, to retrieve the number of
        // bytes required to store the plaintext.

        let padding_info: BCRYPT_OAEP_PADDING_INFO = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: padding_alg.into(),
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        };
        let mut decrypted_len = 0u32;
        let ciphertext = [0u8; RSA_2K_DATA_SIZE_LIMIT];

        let result = NCryptDecrypt(
            target_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_ok());
        assert!(decrypted_len <= (ciphertext.len() as u32));

        // Subtract 1 from the required output buffer size. This should fail
        // with a `NTE_BUFFER_TOO_SMALL` error.
        let mut decrypted = vec![0u8; decrypted_len as usize - 1];
        let result = NCryptDecrypt(
            target_key.handle(),
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BUFFER_TOO_SMALL));
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_required_output_buffer_size_lt_required() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size_lt_required(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_required_output_buffer_size_lt_required_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size_lt_required(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_required_output_buffer_size_lt_required_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size_lt_required(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_required_output_buffer_size_lt_required() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size_lt_required(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_required_output_buffer_size_lt_required_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size_lt_required(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_required_output_buffer_size_lt_required_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size_lt_required(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_required_output_buffer_size_lt_required() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size_lt_required(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_required_output_buffer_size_lt_required_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size_lt_required(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_required_output_buffer_size_lt_required_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size_lt_required(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

fn test_helper_rsa_encrypt_decrypt_required_output_buffer_size_gt_required(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_alg: NCryptShaAlgorithm,
    enable_crt: Option<bool>,
) {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let (_import_key, target_key) = import_wrapped_key(
            azihsm_provider.handle(),
            key_type,
            key_enc_algo,
            NCRYPT_ALLOW_DECRYPT_FLAG,
            enable_crt,
        );

        // Invoke `NCryptDecrypt()` a single time, to retrieve the number of
        // bytes required to store the plaintext.

        let padding_info: BCRYPT_OAEP_PADDING_INFO = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: padding_alg.into(),
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        };

        // Determine the size of the ciphertext buffer by examining the type of
        // key we're dealing with
        let expected_ciphertext_len = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };

        let mut plaintext = [0u8; 100];
        let mut ciphertext: Vec<u8> = vec![0u8; expected_ciphertext_len];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(ciphertext.as_mut_slice()),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext.len(), ciphertext_len as usize);

        // Get the required output buffer size.
        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            target_key.handle(),
            Some(ciphertext.as_slice()),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_ok());
        assert!(plaintext.len() <= decrypted_len as usize);

        // Add 1 to the required output buffer size.
        let mut decrypted = vec![0u8; decrypted_len as usize + 1];
        let result = NCryptDecrypt(
            target_key.handle(),
            Some(ciphertext.as_slice()),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_ok());
        assert_eq!(plaintext.len(), decrypted_len as usize);
        assert_eq!(plaintext, decrypted[0..decrypted_len as usize]);
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_required_output_buffer_size_gt_required() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size_gt_required(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_required_output_buffer_size_gt_required_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size_gt_required(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_required_output_buffer_size_gt_required_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size_gt_required(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_required_output_buffer_size_gt_required() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size_gt_required(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_required_output_buffer_size_gt_required_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size_gt_required(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_required_output_buffer_size_gt_required_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size_gt_required(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_required_output_buffer_size_gt_required() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size_gt_required(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_required_output_buffer_size_gt_required_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size_gt_required(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_required_output_buffer_size_gt_required_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_required_output_buffer_size_gt_required(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

fn test_helper_rsa_encrypt_algid_null(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    enable_crt: Option<bool>,
) {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let (_import_key, target_key) = import_wrapped_key(
            azihsm_provider.handle(),
            key_type,
            key_enc_algo,
            NCRYPT_ALLOW_DECRYPT_FLAG,
            enable_crt,
        );

        let padding_info: BCRYPT_OAEP_PADDING_INFO = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: PCWSTR::null(), // NULL AlgId
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        };

        // Determine the size of the ciphertext buffer by examining the type of
        // key we're dealing with
        let expected_ciphertext_len = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };

        let mut plaintext = [0u8; 100];
        let mut ciphertext: Vec<u8> = vec![0u8; expected_ciphertext_len];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(ciphertext.as_mut_slice()),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}

#[test]
fn test_rsa_2k_encrypt_algid_null() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_algid_null(
            KeyType::Rsa2k,
            *key_enc_alg,
            None, // don't touch RSA-CRT property
        );
    }
}

#[test]
fn test_rsa_2k_encrypt_algid_null_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_algid_null(
            KeyType::Rsa2k,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
        );
    }
}

#[test]
fn test_rsa_2k_encrypt_algid_null_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_algid_null(
            KeyType::Rsa2k,
            *key_enc_alg,
            Some(false), // intentionally enable RSA-CRT
        );
    }
}

#[test]
fn test_rsa_3k_encrypt_algid_null() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_algid_null(
            KeyType::Rsa3k,
            *key_enc_alg,
            None, // don't touch RSA-CRT property
        );
    }
}

#[test]
fn test_rsa_3k_encrypt_algid_null_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_algid_null(
            KeyType::Rsa3k,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
        );
    }
}

#[test]
fn test_rsa_3k_encrypt_algid_null_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_algid_null(
            KeyType::Rsa3k,
            *key_enc_alg,
            Some(false), // intentionally enable RSA-CRT
        );
    }
}

#[test]
fn test_rsa_4k_encrypt_algid_null() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_algid_null(
            KeyType::Rsa4k,
            *key_enc_alg,
            None, // don't touch RSA-CRT property
        );
    }
}

#[test]
fn test_rsa_4k_encrypt_algid_null_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_algid_null(
            KeyType::Rsa4k,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
        );
    }
}

#[test]
fn test_rsa_4k_encrypt_algid_null_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_algid_null(
            KeyType::Rsa4k,
            *key_enc_alg,
            Some(false), // intentionally enable RSA-CRT
        );
    }
}

fn test_helper_rsa_decrypt_algid_null(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_alg: NCryptShaAlgorithm,
    enable_crt: Option<bool>,
) {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let (_import_key, target_key) = import_wrapped_key(
            azihsm_provider.handle(),
            key_type,
            key_enc_algo,
            NCRYPT_ALLOW_DECRYPT_FLAG,
            enable_crt,
        );

        let mut padding_info: BCRYPT_OAEP_PADDING_INFO = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: padding_alg.into(),
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        };

        // Determine the size of the ciphertext buffer by examining the type of
        // key we're dealing with
        let expected_ciphertext_len = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };

        let mut plaintext = [0u8; 100];
        let mut ciphertext: Vec<u8> = vec![0u8; expected_ciphertext_len];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(ciphertext.as_mut_slice()),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext.len(), ciphertext_len as usize);

        let mut decrypted: Vec<u8> = vec![0u8; expected_ciphertext_len];
        let mut decrypted_len = 0u32;

        padding_info.pszAlgId = PCWSTR::null(); // <-- set alg ID to null
        let result = NCryptDecrypt(
            target_key.handle(),
            Some(ciphertext.as_slice()),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(decrypted.as_mut_slice()),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}

#[test]
fn test_rsa_2k_decrypt_algid_null() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_algid_null(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_2k_decrypt_algid_null_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_algid_null(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_2k_decrypt_algid_null_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_algid_null(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_decrypt_algid_null() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_algid_null(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_3k_decrypt_algid_null_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_algid_null(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_decrypt_algid_null_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_algid_null(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_decrypt_algid_null() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_algid_null(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_4k_decrypt_algid_null_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_algid_null(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_decrypt_algid_null_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_algid_null(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

// RSA Encrypt with SHA-1 is not supported
#[test]
fn test_rsa_2k_encrypt_sha1_rejected() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa2k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha1,
            None,
            true, // expect failure
            false,
        );
    }
}

// RSA Decrypt with SHA-1 should be supported
// Create RSA 2k Key, encrypt data using SHA-1 externally
// Import the RSA 2K key and decrypt the data with SHA-1
#[test]
fn test_rsa_2k_decrypt_sha1() {
    use symcrypt::hash::HashAlgorithm;
    use symcrypt::rsa::RsaKey;

    // RSA Encrypt with OAEP and SHA-1
    //
    // We can't re-use our crypto lib because it doesn't support SHA-1.
    // So instead, we use SymCrypt.
    fn _encrypt(key: &RsaKey, data: &[u8]) -> Vec<u8> {
        key.oaep_encrypt(data, HashAlgorithm::Sha1, b"")
            .expect("Failed to encrypt AES key with RSA public key")
    }

    unsafe fn _import_key(
        private_key: &[u8],
        prov_handle: NCRYPT_PROV_HANDLE,
        key_enc_algo: KeyEncryptionAlgorithm,
    ) -> KeyHandle {
        let mut import_key = Owned::default();
        let mut target_key = KeyHandle::new();

        // Open handle to the built-in import key
        let result = NCryptOpenKey(
            prov_handle,
            &mut *import_key,
            AZIHSM_BUILTIN_UNWRAP_KEY,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Export public key from the import key
        let mut pub_key = vec![0u8; 600];
        let mut pub_key_size = pub_key.len() as u32;
        let result = NCryptExportKey(
            *import_key,
            None,
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut pub_key),
            ptr::addr_of_mut!(pub_key_size),
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());
        pub_key.truncate(pub_key_size as usize);

        // Wrap it with the import public key using 'key_enc_algo' key encryption algorithm
        let encrypted_blob = wrap_data(pub_key, private_key, key_enc_algo);
        let key_blob = create_pkcs11_rsa_aes_wrap_blob(&encrypted_blob, key_enc_algo);

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
            prov_handle,
            *import_key,
            BCRYPT_PKCS11_RSA_AES_WRAP_KEY_BLOB,
            Some(&params),
            target_key.as_mut(),
            key_blob.as_slice(),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        target_key
    }

    let mut azihsm_provider = Owned::default();

    // Generate RSA Key
    let (der_rsa_key_private, der_rsa_key_pub) = generate_rsa_der(KeyType::Rsa2k);

    let plaintext = "Hello, world!".as_bytes().to_vec();

    // Encrypt plaintext using the public key
    let ciphertext = {
        let rsa_key = rsa_public_key_from_der(der_rsa_key_pub.as_slice());
        _encrypt(&rsa_key, &plaintext)
    };

    unsafe {
        // Import the RSA key
        let result = NCryptOpenStorageProvider(&mut *azihsm_provider, AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let imported_key = _import_key(
            &der_rsa_key_private,
            *azihsm_provider,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
        );

        let result = NCryptSetProperty(
            imported_key.handle(),
            NCRYPT_KEY_USAGE_PROPERTY,
            &NCRYPT_ALLOW_DECRYPT_FLAG.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(imported_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Decrypt ciphertext using the imported key
        let dec_result = test_helper_rsa_decrypt(
            &imported_key,
            &KeyType::Rsa2k,
            NCryptShaAlgorithm::Sha1,
            None,
            &ciphertext,
            false,
        );
        assert!(dec_result.is_ok(), "Decryption failed: {:?}", dec_result);

        let decrypted = dec_result.unwrap();
        assert_eq!(
            decrypted, plaintext,
            "Decrypted data does not match the original plaintext"
        );
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_sha256() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa2k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha256,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_sha256_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa2k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha256,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_sha256_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa2k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha256,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_sha384() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa2k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha384,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_sha384_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa2k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha384,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_sha384_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa2k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha384,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_sha512() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa2k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha512,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_sha512_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa2k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha512,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_sha512_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa2k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha512,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_sha256_with_oaep_label() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa2k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );

        // generate a random vector of bytes to use as the OAEP label
        let mut oaep_label: Vec<u8> = vec![0u8; 128];
        rand_bytes(oaep_label.as_mut_slice()).expect("Failed to generate random bytes");

        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha256,
            Some(oaep_label.as_mut_slice()),
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_sha256_with_oaep_label_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa2k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );

        // generate a random vector of bytes to use as the OAEP label
        let mut oaep_label: Vec<u8> = vec![0u8; 128];
        rand_bytes(oaep_label.as_mut_slice()).expect("Failed to generate random bytes");

        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha256,
            Some(oaep_label.as_mut_slice()),
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_sha256_with_oaep_label_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa2k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );

        // generate a random vector of bytes to use as the OAEP label
        let mut oaep_label: Vec<u8> = vec![0u8; 128];
        rand_bytes(oaep_label.as_mut_slice()).expect("Failed to generate random bytes");

        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha256,
            Some(oaep_label.as_mut_slice()),
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_sha256() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa3k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha256,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_sha256_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa3k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha256,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_sha256_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa3k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha256,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_sha384() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa3k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha384,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_sha384_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa3k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha384,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_sha384_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa3k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha384,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_sha512() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa3k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha512,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_sha512_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa3k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha512,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_sha512_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa3k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha512,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_sha256_with_oaep_label() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa3k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );

        // generate a random vector of bytes to use as the OAEP label
        let mut oaep_label: Vec<u8> = vec![0u8; 128];
        rand_bytes(oaep_label.as_mut_slice()).expect("Failed to generate random bytes");

        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha256,
            Some(oaep_label.as_mut_slice()),
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_sha256_with_oaep_label_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa3k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );

        // generate a random vector of bytes to use as the OAEP label
        let mut oaep_label: Vec<u8> = vec![0u8; 128];
        rand_bytes(oaep_label.as_mut_slice()).expect("Failed to generate random bytes");

        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha256,
            Some(oaep_label.as_mut_slice()),
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_sha256_with_oaep_label_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa3k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );

        // generate a random vector of bytes to use as the OAEP label
        let mut oaep_label: Vec<u8> = vec![0u8; 128];
        rand_bytes(oaep_label.as_mut_slice()).expect("Failed to generate random bytes");

        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha256,
            Some(oaep_label.as_mut_slice()),
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_sha256() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa4k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha256,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_sha256_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa4k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha256,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_sha256_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa4k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha256,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_sha384() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa4k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha384,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_sha384_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa4k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha384,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_sha384_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa4k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha384,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_sha512() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa4k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha512,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_sha512_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa4k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha512,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_sha512_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa4k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha512,
            None,
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_sha256_with_oaep_label() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa4k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );

        // generate a random vector of bytes to use as the OAEP label
        let mut oaep_label: Vec<u8> = vec![0u8; 128];
        rand_bytes(oaep_label.as_mut_slice()).expect("Failed to generate random bytes");

        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha256,
            Some(oaep_label.as_mut_slice()),
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_sha256_with_oaep_label_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa4k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );

        // generate a random vector of bytes to use as the OAEP label
        let mut oaep_label: Vec<u8> = vec![0u8; 128];
        rand_bytes(oaep_label.as_mut_slice()).expect("Failed to generate random bytes");

        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha256,
            Some(oaep_label.as_mut_slice()),
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_sha256_with_oaep_label_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_type = KeyType::Rsa4k;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );

        // generate a random vector of bytes to use as the OAEP label
        let mut oaep_label: Vec<u8> = vec![0u8; 128];
        rand_bytes(oaep_label.as_mut_slice()).expect("Failed to generate random bytes");

        test_helper_rsa_encrypt_decrypt(
            &key,
            &key_type,
            NCryptShaAlgorithm::Sha256,
            Some(oaep_label.as_mut_slice()),
            false,
            false,
        );
        test_helper_check_key_length(&key, &key_type);
        test_helper_check_key_usage(&key, key_usage);
    }
}

fn test_helper_rsa_encrypt_decrypt_with_tampered_oaep_label(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    enable_crt: Option<bool>,
) {
    // generate an RSA key and import it into Manticore
    let key_usage = NCRYPT_ALLOW_DECRYPT_FLAG;
    let key = test_helper_rsa_key_unwrap(&key_type, key_enc_algo, enable_crt, key_usage);

    test_helper_check_key_length(&key, &key_type);
    test_helper_check_key_usage(&key, key_usage);

    let padding_alg: NCryptShaAlgorithm = NCryptShaAlgorithm::Sha256;

    // generate a random plaintext buffer
    let mut plaintext: Vec<u8> = vec![0u8; 100];
    rand_bytes(plaintext.as_mut_slice()).expect("Failed to generate random bytes");

    // generate a random vector of bytes to use as the OAEP label. Make a second
    // copy to pass into the decrypt helper function later, to avoid ownership
    // issues
    let mut oaep_label: Vec<u8> = vec![0u8; 128];
    rand_bytes(oaep_label.as_mut_slice()).expect("Failed to generate random bytes");
    let mut oaep_label_dec: Vec<u8> = oaep_label.clone();

    // call the encryption helper function to encrypt the plaintext
    let enc_result = test_helper_rsa_encrypt(
        &key,
        &key_type,
        padding_alg,
        Some(oaep_label.as_mut_slice()),
        plaintext.as_slice(),
        false,
    );

    // verify that encryption succeeded
    if enc_result.is_err() {
        panic!("RSA encryption failed when it was not expected to fail");
    }
    let ciphertext = enc_result.unwrap();

    // next, tamper with the label bytes. We'll change a single byte in the
    // label, which means we should expect to receive a different decrypted
    // plaintext that does NOT match the original plaintext
    oaep_label_dec[0] = oaep_label_dec[0].wrapping_add(1);

    // next, call the decryption helper function to decrypt the ciphertext
    // (passing in the modified label). Because we've passed in a tampered
    // label, we expect this to fail with an error from the KSP
    let dec_result = test_helper_rsa_decrypt(
        &key,
        &key_type,
        padding_alg,
        Some(oaep_label_dec.as_mut_slice()),
        ciphertext.as_slice(),
        true,
    );

    // verify that decryption failed
    assert!(
        dec_result.is_err(),
        "Decryption succeeded when it was expected to fail."
    );
}

#[test]
fn test_rsa_2k_encrypt_decrypt_with_tampered_oaep_label() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_decrypt_with_tampered_oaep_label(
            KeyType::Rsa2k,
            *key_enc_alg,
            None, // don't touch RSA-CRT property
        );
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_with_tampered_oaep_label_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_decrypt_with_tampered_oaep_label(
            KeyType::Rsa2k,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
        );
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_with_tampered_oaep_label_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_decrypt_with_tampered_oaep_label(
            KeyType::Rsa2k,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
        );
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_with_tampered_oaep_label() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_decrypt_with_tampered_oaep_label(
            KeyType::Rsa3k,
            *key_enc_alg,
            None, // don't touch RSA-CRT property
        );
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_with_tampered_oaep_label_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_decrypt_with_tampered_oaep_label(
            KeyType::Rsa3k,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
        );
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_with_tampered_oaep_label_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_decrypt_with_tampered_oaep_label(
            KeyType::Rsa3k,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
        );
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_with_tampered_oaep_label() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_decrypt_with_tampered_oaep_label(
            KeyType::Rsa4k,
            *key_enc_alg,
            None, // don't touch RSA-CRT property
        );
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_with_tampered_oaep_label_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_decrypt_with_tampered_oaep_label(
            KeyType::Rsa4k,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
        );
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_with_tampered_oaep_label_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_decrypt_with_tampered_oaep_label(
            KeyType::Rsa4k,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
        );
    }
}

fn test_helper_rsa_encrypt_decrypt_with_paddinginfo_null(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    enable_crt: Option<bool>,
) {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let (_import_key, target_key) = import_wrapped_key(
            azihsm_provider.handle(),
            key_type,
            key_enc_algo,
            NCRYPT_ALLOW_DECRYPT_FLAG,
            enable_crt,
        );

        // Determine the size of the ciphertext buffer by examining the type of
        // key we're dealing with
        let expected_ciphertext_len = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };

        let mut plaintext = [0u8; 100];
        let mut ciphertext: Vec<u8> = vec![0u8; expected_ciphertext_len];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            None,
            Some(ciphertext.as_mut_slice()),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext.len(), ciphertext_len as usize);

        let mut decrypted: Vec<u8> = vec![0u8; expected_ciphertext_len];
        let mut decrypted_len = 0u32;

        let result = NCryptDecrypt(
            target_key.handle(),
            Some(ciphertext.as_slice()),
            None,
            Some(decrypted.as_mut_slice()),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_ok());
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_with_paddinginfo_null() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_decrypt_with_paddinginfo_null(
            KeyType::Rsa2k,
            *key_enc_alg,
            None, // don't touch RSA-CRT property
        );
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_with_paddinginfo_null_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_decrypt_with_paddinginfo_null(
            KeyType::Rsa2k,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
        );
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_with_paddinginfo_null_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_decrypt_with_paddinginfo_null(
            KeyType::Rsa2k,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
        );
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_with_paddinginfo_null() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_decrypt_with_paddinginfo_null(
            KeyType::Rsa3k,
            *key_enc_alg,
            None, // don't touch RSA-CRT property
        );
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_with_paddinginfo_null_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_decrypt_with_paddinginfo_null(
            KeyType::Rsa3k,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
        );
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_with_paddinginfo_null_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_decrypt_with_paddinginfo_null(
            KeyType::Rsa3k,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
        );
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_with_paddinginfo_null() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_decrypt_with_paddinginfo_null(
            KeyType::Rsa4k,
            *key_enc_alg,
            None, // don't touch RSA-CRT property
        );
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_with_paddinginfo_null_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_decrypt_with_paddinginfo_null(
            KeyType::Rsa4k,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
        );
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_with_paddinginfo_null_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        test_helper_rsa_encrypt_decrypt_with_paddinginfo_null(
            KeyType::Rsa4k,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
        );
    }
}

fn test_helper_rsa_encrypt_with_invalid_flag(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_alg: NCryptShaAlgorithm,
    enable_crt: Option<bool>,
) {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let (_import_key, target_key) = import_wrapped_key(
            azihsm_provider.handle(),
            key_type,
            key_enc_algo,
            NCRYPT_ALLOW_DECRYPT_FLAG,
            enable_crt,
        );

        let padding_info: BCRYPT_OAEP_PADDING_INFO = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: padding_alg.into(),
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        };

        // Determine the size of the ciphertext buffer by examining the type of
        // key we're dealing with
        let expected_ciphertext_len = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };

        let mut plaintext = [0u8; 100];
        let mut ciphertext: Vec<u8> = vec![0u8; expected_ciphertext_len];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(ciphertext.as_mut_slice()),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG), // Invalid flag
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BAD_FLAGS));
    }
}

#[test]
fn test_rsa_2k_encrypt_with_invalid_flag() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_with_invalid_flag(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_with_invalid_flag_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_with_invalid_flag(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_with_invalid_flag_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_with_invalid_flag(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_with_invalid_flag() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_with_invalid_flag(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_with_invalid_flag_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_with_invalid_flag(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_with_invalid_flag_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_with_invalid_flag(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_with_invalid_flag() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_with_invalid_flag(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_with_invalid_flag_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_with_invalid_flag(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_with_invalid_flag_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_with_invalid_flag(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

fn test_helper_rsa_decrypt_with_invalid_flag(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_alg: NCryptShaAlgorithm,
    enable_crt: Option<bool>,
) {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let (_import_key, target_key) = import_wrapped_key(
            azihsm_provider.handle(),
            key_type,
            key_enc_algo,
            NCRYPT_ALLOW_DECRYPT_FLAG,
            enable_crt,
        );

        let padding_info: BCRYPT_OAEP_PADDING_INFO = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: padding_alg.into(),
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        };

        // Determine the size of the ciphertext buffer by examining the type of
        // key we're dealing with
        let expected_ciphertext_len = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };

        let mut plaintext = [0u8; 100];
        let mut ciphertext: Vec<u8> = vec![0u8; expected_ciphertext_len];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(ciphertext.as_mut_slice()),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext.len(), ciphertext_len as usize);

        let mut decrypted: Vec<u8> = vec![0u8; expected_ciphertext_len];
        let mut decrypted_len = 0u32;

        let result = NCryptDecrypt(
            target_key.handle(),
            Some(ciphertext.as_slice()),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(decrypted.as_mut_slice()),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG), // Invalid flag
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BAD_FLAGS));
    }
}

#[test]
fn test_rsa_2k_decrypt_with_invalid_flag() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_with_invalid_flag(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_2k_decrypt_with_invalid_flag_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_with_invalid_flag(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_2k_decrypt_with_invalid_flag_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_with_invalid_flag(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_decrypt_with_invalid_flag() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_with_invalid_flag(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_3k_decrypt_with_invalid_flag_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_with_invalid_flag(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_decrypt_with_invalid_flag_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_with_invalid_flag(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_decrypt_with_invalid_flag() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_with_invalid_flag(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_4k_decrypt_with_invalid_flag_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_with_invalid_flag(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_decrypt_with_invalid_flag_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_with_invalid_flag(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

fn test_helper_rsa_encrypt_with_no_pad_oaep_flag(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_alg: NCryptShaAlgorithm,
    enable_crt: Option<bool>,
) {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let (_import_key, target_key) = import_wrapped_key(
            azihsm_provider.handle(),
            key_type,
            key_enc_algo,
            NCRYPT_ALLOW_DECRYPT_FLAG,
            enable_crt,
        );

        let padding_info: BCRYPT_OAEP_PADDING_INFO = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: padding_alg.into(),
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        };

        // Determine the size of the ciphertext buffer by examining the type of
        // key we're dealing with
        let expected_ciphertext_len = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };

        let mut plaintext = [0u8; 100];
        let mut ciphertext: Vec<u8> = vec![0u8; expected_ciphertext_len];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(ciphertext.as_mut_slice()),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(0), // No NCRYPT_PAD_OAEP_FLAG
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}

#[test]
fn test_rsa_2k_encrypt_with_no_pad_oaep_flag() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_with_no_pad_oaep_flag(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_with_no_pad_oaep_flag_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_with_no_pad_oaep_flag(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_with_no_pad_oaep_flag_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_with_no_pad_oaep_flag(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_with_no_pad_oaep_flag() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_with_no_pad_oaep_flag(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_with_no_pad_oaep_flag_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_with_no_pad_oaep_flag(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_with_no_pad_oaep_flag_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_with_no_pad_oaep_flag(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_with_no_pad_oaep_flag() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_with_no_pad_oaep_flag(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_with_no_pad_oaep_flag_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_with_no_pad_oaep_flag(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_with_no_pad_oaep_flag_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_with_no_pad_oaep_flag(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

fn test_helper_rsa_decrypt_with_no_pad_oaep_flag(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_alg: NCryptShaAlgorithm,
    enable_crt: Option<bool>,
) {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let (_import_key, target_key) = import_wrapped_key(
            azihsm_provider.handle(),
            key_type,
            key_enc_algo,
            NCRYPT_ALLOW_DECRYPT_FLAG,
            enable_crt,
        );

        let padding_info: BCRYPT_OAEP_PADDING_INFO = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: padding_alg.into(),
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        };

        // Determine the size of the ciphertext buffer by examining the type of
        // key we're dealing with
        let expected_ciphertext_len = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };

        let mut plaintext = [0u8; 100];
        let mut ciphertext: Vec<u8> = vec![0u8; expected_ciphertext_len];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(ciphertext.as_mut_slice()),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext.len(), ciphertext_len as usize);

        let mut decrypted: Vec<u8> = vec![0u8; expected_ciphertext_len];
        let mut decrypted_len = 0u32;

        let result = NCryptDecrypt(
            target_key.handle(),
            Some(ciphertext.as_slice()),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(decrypted.as_mut_slice()),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(0), // No NCRYPT_PAD_OAEP_FLAG
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}

#[test]
fn test_rsa_2k_decrypt_with_no_pad_oaep_flag() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_with_no_pad_oaep_flag(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_2k_decrypt_with_no_pad_oaep_flag_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_with_no_pad_oaep_flag(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_2k_decrypt_with_no_pad_oaep_flag_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_with_no_pad_oaep_flag(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_decrypt_with_no_pad_oaep_flag() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_with_no_pad_oaep_flag(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_3k_decrypt_with_no_pad_oaep_flag_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_with_no_pad_oaep_flag(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_decrypt_with_no_pad_oaep_flag_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_with_no_pad_oaep_flag(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_decrypt_with_no_pad_oaep_flag() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_with_no_pad_oaep_flag(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_4k_decrypt_with_no_pad_oaep_flag_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_with_no_pad_oaep_flag(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_decrypt_with_no_pad_oaep_flag_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_decrypt_with_no_pad_oaep_flag(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

fn test_helper_rsa_encrypt_decrypt_with_corrupt_ciphertext(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_alg: NCryptShaAlgorithm,
    enable_crt: Option<bool>,
) {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let (_import_key, target_key) = import_wrapped_key(
            azihsm_provider.handle(),
            key_type,
            key_enc_algo,
            NCRYPT_ALLOW_DECRYPT_FLAG,
            enable_crt,
        );

        let padding_info: BCRYPT_OAEP_PADDING_INFO = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: padding_alg.into(),
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        };

        // Determine the size of the ciphertext buffer by examining the type of
        // key we're dealing with
        let expected_ciphertext_len = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };

        let mut plaintext = [0u8; 100];
        let mut ciphertext: Vec<u8> = vec![0u8; expected_ciphertext_len];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(ciphertext.as_mut_slice()),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext.len(), ciphertext_len as usize);

        // Corrupt the ciphertext.
        ciphertext[0] = ciphertext[0].wrapping_add(1);
        ciphertext[1] = ciphertext[1].wrapping_add(1);

        let mut decrypted: Vec<u8> = vec![0u8; expected_ciphertext_len];
        let mut decrypted_len = 0u32;

        let result = NCryptDecrypt(
            target_key.handle(),
            Some(ciphertext.as_slice()),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(decrypted.as_mut_slice()),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BAD_DATA)); // NTE_BAD_DATA
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_with_corrupt_ciphertext() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_corrupt_ciphertext(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_with_corrupt_ciphertext_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_corrupt_ciphertext(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_with_corrupt_ciphertext_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_corrupt_ciphertext(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_with_corrupt_ciphertext() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_corrupt_ciphertext(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_with_corrupt_ciphertext_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_corrupt_ciphertext(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_with_corrupt_ciphertext_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_corrupt_ciphertext(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_with_corrupt_ciphertext() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_corrupt_ciphertext(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_with_corrupt_ciphertext_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_corrupt_ciphertext(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_with_corrupt_ciphertext_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_corrupt_ciphertext(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

fn test_helper_rsa_encrypt_decrypt_with_deleted_key(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_alg: NCryptShaAlgorithm,
    enable_crt: Option<bool>,
) {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let (_import_key, mut target_key) = import_wrapped_key(
            azihsm_provider.handle(),
            key_type,
            key_enc_algo,
            NCRYPT_ALLOW_DECRYPT_FLAG,
            enable_crt,
        );

        let padding_info: BCRYPT_OAEP_PADDING_INFO = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: padding_alg.into(),
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        };

        // Determine the size of the ciphertext buffer by examining the type of
        // key we're dealing with
        let expected_ciphertext_len = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };

        let mut plaintext = [0u8; 100];
        let mut ciphertext: Vec<u8> = vec![0u8; expected_ciphertext_len];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(ciphertext.as_mut_slice()),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext.len(), ciphertext_len as usize);

        // Delete the key
        let deleted_key = target_key.release();
        let result = NCryptDeleteKey(deleted_key, NCRYPT_SILENT_FLAG.0);
        assert!(result.is_ok());

        let mut decrypted: Vec<u8> = vec![0u8; expected_ciphertext_len];
        let mut decrypted_len = 0u32;

        let result = NCryptDecrypt(
            deleted_key,
            Some(ciphertext.as_slice()),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(decrypted.as_mut_slice()),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_HANDLE));
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_with_deleted_key() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_deleted_key(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_with_deleted_key_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_deleted_key(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_with_deleted_key_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_deleted_key(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_with_deleted_key() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_deleted_key(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_with_deleted_key_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_deleted_key(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_with_deleted_key_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_deleted_key(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_with_deleted_key() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_deleted_key(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_with_deleted_key_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_deleted_key(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_with_deleted_key_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_deleted_key(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

fn test_helper_rsa_encrypt_decrypt_with_wrong_usage(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_alg: NCryptShaAlgorithm,
    enable_crt: Option<bool>,
) {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        // Generate and import an RSA private key, but set the usage to only
        // allow signing. This should create an error below when we try to
        // encrypt/decrypt with a key that's only permitted to be used for
        // signing.
        let (_import_key, target_key) = import_wrapped_key(
            azihsm_provider.handle(),
            key_type,
            key_enc_algo,
            NCRYPT_ALLOW_SIGNING_FLAG,
            enable_crt,
        );

        let padding_info: BCRYPT_OAEP_PADDING_INFO = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: padding_alg.into(),
            pbLabel: ptr::null_mut(),
            cbLabel: 0,
        };

        // Determine the size of the ciphertext buffer by examining the type of
        // key we're dealing with
        let expected_ciphertext_len = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };

        let mut plaintext = [0u8; 100];
        let mut ciphertext: Vec<u8> = vec![0u8; expected_ciphertext_len];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let result = NCryptEncrypt(
            target_key.handle(),
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(ciphertext.as_mut_slice()),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext.len(), ciphertext_len as usize);

        let mut decrypted: Vec<u8> = vec![0u8; expected_ciphertext_len];
        let mut decrypted_len = 0u32;

        let result = NCryptDecrypt(
            target_key.handle(),
            Some(ciphertext.as_slice()),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(decrypted.as_mut_slice()),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_PAD_OAEP_FLAG,
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(E_UNEXPECTED));
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_with_wrong_usage() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_wrong_usage(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_with_wrong_usage_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_wrong_usage(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_2k_encrypt_decrypt_with_wrong_usage_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_wrong_usage(
                KeyType::Rsa2k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_with_wrong_usage() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_wrong_usage(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_with_wrong_usage_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_wrong_usage(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_3k_encrypt_decrypt_with_wrong_usage_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_wrong_usage(
                KeyType::Rsa3k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_with_wrong_usage() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_wrong_usage(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                None, // don't touch RSA-CRT property
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_with_wrong_usage_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_wrong_usage(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(true), // intentionally enable RSA-CRT
            );
        }
    }
}

#[test]
fn test_rsa_4k_encrypt_decrypt_with_wrong_usage_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            test_helper_rsa_encrypt_decrypt_with_wrong_usage(
                KeyType::Rsa4k,
                *key_enc_alg,
                *padding_alg,
                Some(false), // intentionally disable RSA-CRT
            );
        }
    }
}
