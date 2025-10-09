// Copyright (C) Microsoft Corporation. All rights reserved.
mod common;
use std::ptr;

use winapi::shared::winerror::ERROR_INVALID_DATA;
use winapi::shared::winerror::E_UNEXPECTED;
use winapi::shared::winerror::NTE_BAD_SIGNATURE;
use winapi::shared::winerror::NTE_BUFFER_TOO_SMALL;
use winapi::shared::winerror::NTE_INVALID_PARAMETER;
use windows::core::Owned;
use windows::core::HRESULT;
use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::*;

use der::Decode;
use pkcs1::RsaPrivateKey;
use pkcs8::PrivateKeyInfo;
use symcrypt::{
    hash::HashAlgorithm,
    rsa::{RsaKey, RsaKeyUsage},
};

use crypto::rand::rand_bytes;

use crate::common::*;

// RSA Sign with SHA-1 is not supported
#[test]
fn test_rsa_2k_sign_sha1_rejected() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            NCryptShaAlgorithm::Sha1,
            true, // expect failure
            false,
        );
    }
}

// RSA Verify with SHA-1 should be supported
// Create RSA 2k Key, sign data using SHA-1 externally
// Import the RSA 2k Key, and verify the data
#[test]
fn test_rsa_2k_verify_sha1() {
    fn _sign(key: &RsaKey, digest: &[u8]) -> Vec<u8> {
        // sign the digest with the SymCrypt RSA private key
        key.pkcs1_sign(digest, HashAlgorithm::Sha1)
            .expect("Failed to sign with SymCrypt RSA private key")
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
    let (der_rsa_key_private, _der_rsa_key_pub) = generate_rsa_der(KeyType::Rsa2k);

    // Digest size for SHA-1
    let digest = [7; 20];

    // Generate signature using the private key
    let signature = {
        // parse the contents of the RSA private key (which is in PKCS8-DER
        // format), and use it to construct a `RsaPrivateKey` object
        let private_key_info = PrivateKeyInfo::from_der(&der_rsa_key_private)
            .expect("Failed to decode PKCS8 RSA private key");
        let private_key = RsaPrivateKey::from_der(private_key_info.private_key)
            .expect("Failed to decode PKCS8 RSA private key");

        // use the `RsaPrivateKey` object to set up a usable SymCrypt RSA key
        let key = RsaKey::set_key_pair(
            private_key.modulus.as_bytes(),
            private_key.public_exponent.as_bytes(),
            private_key.prime1.as_bytes(),
            private_key.prime2.as_bytes(),
            RsaKeyUsage::Sign,
        )
        .expect("Failed to create SymCrypt RSA private key");

        _sign(&key, &digest)
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
            &NCRYPT_ALLOW_SIGNING_FLAG.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(imported_key.handle(), NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Verify Signature
        let padding_info_pkcs1 = BCRYPT_PKCS1_PADDING_INFO {
            pszAlgId: NCryptShaAlgorithm::Sha1.into(),
        };
        let padding_info_param = Some(ptr::addr_of!(padding_info_pkcs1) as *const std::ffi::c_void);

        let result = NCryptVerifySignature(
            imported_key.handle(),
            padding_info_param,
            &digest,
            &signature,
            NCRYPT_PAD_PKCS1_FLAG,
        );
        assert!(result.is_ok(), "{:?}", result);
    }
}

// ========== RSA 2k/3k/4k, SHA 256/384/512, PKCS1 Padding Tests ========== //
#[test]
fn test_rsa_2k_sign_verify_pkcs1_sha256() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pkcs1_sha256_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pkcs1_sha256_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pkcs1_sha256() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pkcs1_sha256_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pkcs1_sha256_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pkcs1_sha256() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pkcs1_sha256_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pkcs1_sha256_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pkcs1_sha384() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha384;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pkcs1_sha384_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha384;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pkcs1_sha384_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha384;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pkcs1_sha384() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha384;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pkcs1_sha384_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha384;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pkcs1_sha384_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha384;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pkcs1_sha384() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha384;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pkcs1_sha384_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha384;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pkcs1_sha384_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha384;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pkcs1_sha512() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha512;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pkcs1_sha512_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha512;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pkcs1_sha512_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha512;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pkcs1_sha512() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha512;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pkcs1_sha512_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha512;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pkcs1_sha512_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha512;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pkcs1_sha512() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha512;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pkcs1_sha512_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha512;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pkcs1_sha512_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = Some(NCryptPaddingType::Pkcs1);
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha512;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

// =========== RSA 2k/3k/4k, SHA 256/384/512/1, PSS Padding Tests =========== //
#[test]
fn test_rsa_2k_sign_verify_pss_sha256() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pss_sha256_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pss_sha256_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pss_sha256() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pss_sha256_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pss_sha256_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pss_sha256() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pss_sha256_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pss_sha256_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pss_sha384() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha384;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pss_sha384_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha384;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pss_sha384_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha384;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pss_sha384() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha384;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pss_sha384_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha384;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pss_sha384_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha384;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pss_sha384() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha384;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pss_sha384_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha384;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pss_sha384_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha384;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pss_sha512() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha512;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pss_sha512_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha512;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pss_sha512_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha512;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pss_sha512() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha512;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pss_sha512_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha512;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pss_sha512_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha512;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pss_sha512() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha512;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pss_sha512_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha512;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pss_sha512_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = Some(NCryptPaddingType::Pss);
        let padding_flag_type = Some(NCryptPaddingType::Pss);
        let padding_alg = NCryptShaAlgorithm::Sha512;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

// ===================== RSA 2k/3k/4k, No-Padding Tests ===================== //
#[test]
fn test_rsa_2k_sign_verify_pkcs1_none() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = None;
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pkcs1_none_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = None;
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pkcs1_none_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = None;
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pkcs1_none() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = None;
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pkcs1_none_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = None;
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pkcs1_none_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = None;
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pkcs1_none() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = None;
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pkcs1_none_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = None;
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pkcs1_none_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = None;
        let padding_flag_type = Some(NCryptPaddingType::Pkcs1);
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pss_none() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = None;
        let padding_flag_type = None;
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pss_none_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = None;
        let padding_flag_type = None;
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_2k_sign_verify_pss_none_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa2k;
        let padding_type = None;
        let padding_flag_type = None;
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pss_none() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = None;
        let padding_flag_type = None;
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pss_none_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = None;
        let padding_flag_type = None;
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_3k_sign_verify_pss_none_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa3k;
        let padding_type = None;
        let padding_flag_type = None;
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pss_none() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = None;
        let padding_flag_type = None;
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            None, // don't touch `RsaCrtEnabled` property
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pss_none_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = None;
        let padding_flag_type = None;
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(true), // intentionally enable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

#[test]
fn test_rsa_4k_sign_verify_pss_none_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_type = KeyType::Rsa4k;
        let padding_type = None;
        let padding_flag_type = None;
        let padding_alg = NCryptShaAlgorithm::Sha256;
        let key = test_helper_rsa_key_unwrap(
            &key_type,
            *key_enc_alg,
            Some(false), // intentionally disable RSA-CRT
            key_usage,
        );
        test_helper_rsa_sign_verify(
            &key,
            &key_type,
            padding_type,
            padding_flag_type,
            padding_alg,
            false,
            false,
        );
    }
}

// ======================== Extra Situational Tests ========================= //
fn test_helper_rsa_sign_buffer_incorrect_size(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_type: Option<NCryptPaddingType>,
    padding_flag_type: Option<NCryptPaddingType>,
    padding_alg: NCryptShaAlgorithm,
    enable_crt: Option<bool>,
    buffer_size_adjustment: i32,
) {
    let mut azihsm_provider = ProviderHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let (_import_key, target_key) = import_wrapped_key(
            azihsm_provider.handle(),
            key_type,
            key_enc_algo,
            NCRYPT_ALLOW_SIGNING_FLAG,
            enable_crt,
        );

        // Based on the provided key type, choose an appropriate maximum size
        // for the ciphertext and plaintext.
        let data_len_max: usize = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };

        // Choose a digest size appropriate to the specified padding algorithm
        let digest_size: usize = match padding_alg {
            NCryptShaAlgorithm::Sha256 => 32,
            NCryptShaAlgorithm::Sha384 => 48,
            NCryptShaAlgorithm::Sha512 => 64,
            NCryptShaAlgorithm::Sha1 => 20,
        };

        // Set the padding flag based on the provided parameter.
        let mut padding_flag = NCRYPT_FLAGS(0);
        if let Some(pftype) = padding_flag_type {
            padding_flag = match pftype {
                NCryptPaddingType::Pkcs1 => NCRYPT_PAD_PKCS1_FLAG,
                NCryptPaddingType::Pss => NCRYPT_PAD_PSS_FLAG,
            };
        }

        // Similarly, set up the padding info structs, if the provided
        // `padding_type` parameter was specified.
        let padding_info_pkcs1;
        let padding_info_pss;
        let mut padding_info_param: Option<*const std::ffi::c_void> = None;
        if let Some(ptype) = padding_type {
            // set up the padding info structs, if necessary
            match ptype {
                NCryptPaddingType::Pkcs1 => {
                    padding_info_pkcs1 = BCRYPT_PKCS1_PADDING_INFO {
                        pszAlgId: padding_alg.into(),
                    };
                    padding_info_param =
                        Some(ptr::addr_of!(padding_info_pkcs1) as *const std::ffi::c_void);
                }
                NCryptPaddingType::Pss => {
                    padding_info_pss = BCRYPT_PSS_PADDING_INFO {
                        pszAlgId: padding_alg.into(),
                        cbSalt: rand::random::<u32>() % digest_size as u32,
                    };
                    padding_info_param =
                        Some(ptr::addr_of!(padding_info_pss) as *const std::ffi::c_void);
                }
            };
        }

        // Create a randomized hash digest.
        let mut digest = vec![1u8; digest_size];
        rand_bytes(&mut digest).expect("Failed to generate random bytes");

        let mut signature_size = 0u32;
        let result = NCryptSignHash(
            target_key.handle(),
            padding_info_param,
            &digest,
            None,
            ptr::addr_of_mut!(signature_size),
            padding_flag,
        );
        assert!(result.is_ok());
        assert_eq!(signature_size, data_len_max as u32);

        // Add the specified amount to the expect signature size (either
        // positive or negative).
        let signature_buffer_size: i32 = (signature_size as i32) + buffer_size_adjustment;
        let mut signature = vec![0u8; signature_buffer_size as usize];
        let result = NCryptSignHash(
            target_key.handle(),
            padding_info_param,
            &digest,
            Some(&mut signature),
            ptr::addr_of_mut!(signature_size),
            padding_flag,
        );

        // Depending on what we added to (or subtracted from) the signature
        // buffer size, we'll expect different results:
        if buffer_size_adjustment < 0 {
            assert!(result.is_err(), "result {:?}", result);
            assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BUFFER_TOO_SMALL));
        } else {
            assert!(result.is_ok());
            assert_eq!(signature_size, data_len_max as u32);
        }
    }
}

#[test]
fn test_rsa_2k_sign_buffer_lt_required() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa2k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_buffer_incorrect_size(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    None, // don't touch the RSA-CRT property
                    -1,   // decrease signature buffer size by 1
                );
            }
        }
    }
}

#[test]
fn test_rsa_2k_sign_buffer_lt_required_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa2k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_buffer_incorrect_size(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(true), // intentionally enable RSA-CRT
                    -1,         // decrease signature buffer size by 1
                );
            }
        }
    }
}

#[test]
fn test_rsa_2k_sign_buffer_lt_required_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa2k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_buffer_incorrect_size(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(false), // intentionally disable RSA-CRT
                    -1,          // decrease signature buffer size by 1
                );
            }
        }
    }
}

#[test]
fn test_rsa_3k_sign_buffer_lt_required() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa3k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_buffer_incorrect_size(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    None, // don't touch the RSA-CRT property
                    -1,   // decrease signature buffer size by 1
                );
            }
        }
    }
}

#[test]
fn test_rsa_3k_sign_buffer_lt_required_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa3k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_buffer_incorrect_size(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(true), // intentionally enable RSA-CRT
                    -1,         // decrease signature buffer size by 1
                );
            }
        }
    }
}

#[test]
fn test_rsa_3k_sign_buffer_lt_required_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa3k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_buffer_incorrect_size(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(false), // intentionally disable RSA-CRT
                    -1,          // decrease signature buffer size by 1
                );
            }
        }
    }
}

#[test]
fn test_rsa_4k_sign_buffer_lt_required() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa4k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_buffer_incorrect_size(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    None, // don't touch the RSA-CRT property
                    -1,   // decrease signature buffer size by 1
                );
            }
        }
    }
}

#[test]
fn test_rsa_4k_sign_buffer_lt_required_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa4k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_buffer_incorrect_size(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(true), // intentionally enable RSA-CRT
                    -1,         // decrease signature buffer size by 1
                );
            }
        }
    }
}

#[test]
fn test_rsa_4k_sign_buffer_lt_required_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa4k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_buffer_incorrect_size(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(false), // intentionally disable RSA-CRT
                    -1,          // decrease signature buffer size by 1
                );
            }
        }
    }
}

#[test]
fn test_rsa_2k_sign_buffer_gt_required() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa2k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_buffer_incorrect_size(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    None, // don't touch the RSA-CRT property
                    1,    // increase signature buffer size by 1
                );
            }
        }
    }
}

#[test]
fn test_rsa_2k_sign_buffer_gt_required_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa2k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_buffer_incorrect_size(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(true), // intentionally enable RSA-CRT
                    1,          // increase signature buffer size by 1
                );
            }
        }
    }
}

#[test]
fn test_rsa_2k_sign_buffer_gt_required_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa2k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_buffer_incorrect_size(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(false), // intentionally disable RSA-CRT
                    1,           // increase signature buffer size by 1
                );
            }
        }
    }
}

#[test]
fn test_rsa_3k_sign_buffer_gt_required() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa3k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_buffer_incorrect_size(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    None, // don't touch the RSA-CRT property
                    1,    // increase signature buffer size by 1
                );
            }
        }
    }
}

#[test]
fn test_rsa_3k_sign_buffer_gt_required_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa3k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_buffer_incorrect_size(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(true), // intentionally enable RSA-CRT
                    1,          // increase signature buffer size by 1
                );
            }
        }
    }
}

#[test]
fn test_rsa_3k_sign_buffer_gt_required_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa3k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_buffer_incorrect_size(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(false), // intentionally disable RSA-CRT
                    1,           // increase signature buffer size by 1
                );
            }
        }
    }
}

#[test]
fn test_rsa_4k_sign_buffer_gt_required() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa4k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_buffer_incorrect_size(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    None, // don't touch the RSA-CRT property
                    1,    // increase signature buffer size by 1
                );
            }
        }
    }
}

#[test]
fn test_rsa_4k_sign_buffer_gt_required_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa4k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_buffer_incorrect_size(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(true), // intentionally enable RSA-CRT
                    1,          // increase signature buffer size by 1
                );
            }
        }
    }
}

#[test]
fn test_rsa_4k_sign_buffer_gt_required_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa4k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_buffer_incorrect_size(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(false), // intentionally disable RSA-CRT
                    1,           // increase signature buffer size by 1
                );
            }
        }
    }
}

fn test_helper_rsa_sign_no_finalize(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_type: Option<NCryptPaddingType>,
    padding_flag_type: Option<NCryptPaddingType>,
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

        // Set Key Usage.
        let key_usage = NCRYPT_ALLOW_SIGNING_FLAG;
        let result = NCryptSetProperty(
            target_key.handle(),
            NCRYPT_KEY_USAGE_PROPERTY,
            &key_usage.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set the `RsaCrtEnabled` property to enable or disable CRT for this
        // key, before we finalize it, if a value was given.
        if let Some(enable_crt_val) = enable_crt {
            // We pass in `1` for the expected initial value, because RSA keys
            // are, by default, imported with CRT enabled. This means the
            // `RsaCrtEnabled` property should return `1`.
            set_key_rsa_crt_enabled_property_withcheck(&target_key, enable_crt_val as u32, 1);
        }

        // Based on the provided key type, choose an appropriate maximum size
        // for the ciphertext and plaintext.
        let data_len_max: usize = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };

        // Choose a digest size appropriate to the specified padding algorithm
        let digest_size: usize = match padding_alg {
            NCryptShaAlgorithm::Sha256 => 32,
            NCryptShaAlgorithm::Sha384 => 48,
            NCryptShaAlgorithm::Sha512 => 64,
            NCryptShaAlgorithm::Sha1 => 20,
        };

        // Set the padding flag based on the provided parameter.
        let mut padding_flag = NCRYPT_FLAGS(0);
        if let Some(pftype) = padding_flag_type {
            padding_flag = match pftype {
                NCryptPaddingType::Pkcs1 => NCRYPT_PAD_PKCS1_FLAG,
                NCryptPaddingType::Pss => NCRYPT_PAD_PSS_FLAG,
            };
        }

        // Similarly, set up the padding info structs, if the provided
        // `padding_type` parameter was specified.
        let padding_info_pkcs1;
        let padding_info_pss;
        let mut padding_info_param: Option<*const std::ffi::c_void> = None;
        if let Some(ptype) = padding_type {
            // set up the padding info structs, if necessary
            match ptype {
                NCryptPaddingType::Pkcs1 => {
                    padding_info_pkcs1 = BCRYPT_PKCS1_PADDING_INFO {
                        pszAlgId: padding_alg.into(),
                    };
                    padding_info_param =
                        Some(ptr::addr_of!(padding_info_pkcs1) as *const std::ffi::c_void);
                }
                NCryptPaddingType::Pss => {
                    padding_info_pss = BCRYPT_PSS_PADDING_INFO {
                        pszAlgId: padding_alg.into(),
                        cbSalt: rand::random::<u32>() % digest_size as u32,
                    };
                    padding_info_param =
                        Some(ptr::addr_of!(padding_info_pss) as *const std::ffi::c_void);
                }
            };
        }

        // No finalize key.

        // Generate a random digest.
        let mut digest = vec![1u8; digest_size];
        rand_bytes(&mut digest).expect("Failed to generate random bytes");

        let mut signature_size = 0u32;
        let mut signature = vec![0u8; data_len_max];
        let result = NCryptSignHash(
            target_key.handle(),
            padding_info_param,
            &digest,
            Some(&mut signature),
            ptr::addr_of_mut!(signature_size),
            padding_flag,
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(E_UNEXPECTED));
    }
}

#[test]
fn test_rsa_2k_sign_no_finalize() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa2k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_no_finalize(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    None, // don't touch the RSA-CRT property
                );
            }
        }
    }
}

#[test]
fn test_rsa_2k_sign_no_finalize_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa2k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_no_finalize(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(true), // intentionally enable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_2k_sign_no_finalize_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa2k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_no_finalize(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(false), // intentionally disable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_3k_sign_no_finalize() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa3k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_no_finalize(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    None, // don't touch the RSA-CRT property
                );
            }
        }
    }
}

#[test]
fn test_rsa_3k_sign_no_finalize_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa3k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_no_finalize(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(true), // intentionally enable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_3k_sign_no_finalize_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa3k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_no_finalize(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(false), // intentionally disable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_4k_sign_no_finalize() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa4k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_no_finalize(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    None, // don't touch the RSA-CRT property
                );
            }
        }
    }
}

#[test]
fn test_rsa_4k_sign_no_finalize_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa4k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_no_finalize(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(true), // intentionally enable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_4k_sign_no_finalize_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa4k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_no_finalize(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(false), // intentionally disable RSA-CRT
                );
            }
        }
    }
}

fn test_helper_rsa_sign_incorrect_key_usage(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_type: Option<NCryptPaddingType>,
    padding_flag_type: Option<NCryptPaddingType>,
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
            NCRYPT_ALLOW_DECRYPT_FLAG, // Incorrect key usage
            enable_crt,
        );

        // Based on the provided key type, choose an appropriate maximum size
        // for the ciphertext and plaintext.
        let data_len_max: usize = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };

        // Choose a digest size appropriate to the specified padding algorithm
        let digest_size: usize = match padding_alg {
            NCryptShaAlgorithm::Sha256 => 32,
            NCryptShaAlgorithm::Sha384 => 48,
            NCryptShaAlgorithm::Sha512 => 64,
            NCryptShaAlgorithm::Sha1 => 20,
        };

        // Set the padding flag based on the provided parameter.
        let mut padding_flag = NCRYPT_FLAGS(0);
        if let Some(pftype) = padding_flag_type {
            padding_flag = match pftype {
                NCryptPaddingType::Pkcs1 => NCRYPT_PAD_PKCS1_FLAG,
                NCryptPaddingType::Pss => NCRYPT_PAD_PSS_FLAG,
            };
        }

        // Similarly, set up the padding info structs, if the provided
        // `padding_type` parameter was specified.
        let padding_info_pkcs1;
        let padding_info_pss;
        let mut padding_info_param: Option<*const std::ffi::c_void> = None;
        if let Some(ptype) = padding_type {
            // set up the padding info structs, if necessary
            match ptype {
                NCryptPaddingType::Pkcs1 => {
                    padding_info_pkcs1 = BCRYPT_PKCS1_PADDING_INFO {
                        pszAlgId: padding_alg.into(),
                    };
                    padding_info_param =
                        Some(ptr::addr_of!(padding_info_pkcs1) as *const std::ffi::c_void);
                }
                NCryptPaddingType::Pss => {
                    padding_info_pss = BCRYPT_PSS_PADDING_INFO {
                        pszAlgId: padding_alg.into(),
                        cbSalt: rand::random::<u32>() % digest_size as u32,
                    };
                    padding_info_param =
                        Some(ptr::addr_of!(padding_info_pss) as *const std::ffi::c_void);
                }
            };
        }

        let mut digest = vec![1u8; digest_size];
        rand_bytes(&mut digest).expect("Failed to generate random bytes");

        let mut signature_size = 0u32;
        let mut signature = vec![0u8; data_len_max];
        let result = NCryptSignHash(
            target_key.handle(),
            padding_info_param,
            &digest,
            Some(&mut signature),
            ptr::addr_of_mut!(signature_size),
            padding_flag,
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(
            result.unwrap_err().code(),
            HRESULT::from_win32(ERROR_INVALID_DATA)
        );
    }
}

#[test]
fn test_rsa_2k_sign_incorrect_key_usage() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa2k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_incorrect_key_usage(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    None, // don't touch the RSA-CRT property
                );
            }
        }
    }
}

#[test]
fn test_rsa_2k_sign_incorrect_key_usage_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa2k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_incorrect_key_usage(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(true), // intentionally enable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_2k_sign_incorrect_key_usage_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa2k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_incorrect_key_usage(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(false), // intentionally disable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_3k_sign_incorrect_key_usage() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa3k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_incorrect_key_usage(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    None, // don't touch the RSA-CRT property
                );
            }
        }
    }
}

#[test]
fn test_rsa_3k_sign_incorrect_key_usage_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa3k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_incorrect_key_usage(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(true), // intentionally enable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_3k_sign_incorrect_key_usage_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa3k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_incorrect_key_usage(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(false), // intentionally disable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_4k_sign_incorrect_key_usage() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa4k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_incorrect_key_usage(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    None, // don't touch the RSA-CRT property
                );
            }
        }
    }
}

#[test]
fn test_rsa_4k_sign_incorrect_key_usage_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa4k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_incorrect_key_usage(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(true), // intentionally enable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_4k_sign_incorrect_key_usage_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa4k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_incorrect_key_usage(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(false), // intentionally disable RSA-CRT
                );
            }
        }
    }
}

fn test_helper_rsa_sign_algid_null(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_type: Option<NCryptPaddingType>,
    padding_flag_type: Option<NCryptPaddingType>,
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
            NCRYPT_ALLOW_SIGNING_FLAG,
            enable_crt,
        );

        // Based on the provided key type, choose an appropriate maximum size
        // for the ciphertext and plaintext.
        let data_len_max: usize = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };

        // Choose a digest size appropriate to the specified padding algorithm
        let digest_size: usize = match padding_alg {
            NCryptShaAlgorithm::Sha256 => 32,
            NCryptShaAlgorithm::Sha384 => 48,
            NCryptShaAlgorithm::Sha512 => 64,
            NCryptShaAlgorithm::Sha1 => 20,
        };

        // Set the padding flag based on the provided parameter.
        let mut padding_flag = NCRYPT_FLAGS(0);
        if let Some(pftype) = padding_flag_type {
            padding_flag = match pftype {
                NCryptPaddingType::Pkcs1 => NCRYPT_PAD_PKCS1_FLAG,
                NCryptPaddingType::Pss => NCRYPT_PAD_PSS_FLAG,
            };
        }

        // Similarly, set up the padding info structs, if the provided
        // `padding_type` parameter was specified.
        let padding_info_pkcs1;
        let padding_info_pss;
        let mut padding_info_param: Option<*const std::ffi::c_void> = None;
        if let Some(ptype) = padding_type {
            // set up the padding info structs, if necessary
            match ptype {
                NCryptPaddingType::Pkcs1 => {
                    padding_info_pkcs1 = BCRYPT_PKCS1_PADDING_INFO {
                        pszAlgId: PCWSTR::null(), // <-- NULL pszAlgId
                    };
                    padding_info_param =
                        Some(ptr::addr_of!(padding_info_pkcs1) as *const std::ffi::c_void);
                }
                NCryptPaddingType::Pss => {
                    padding_info_pss = BCRYPT_PSS_PADDING_INFO {
                        pszAlgId: PCWSTR::null(), // <-- NULL pszAlgId
                        cbSalt: rand::random::<u32>() % digest_size as u32,
                    };
                    padding_info_param =
                        Some(ptr::addr_of!(padding_info_pss) as *const std::ffi::c_void);
                }
            };
        }

        // Generate a random digest
        let mut digest = vec![1u8; digest_size];
        rand_bytes(&mut digest).expect("Failed to generate random bytes");

        let mut signature_size = 0u32;
        let mut signature = vec![0u8; data_len_max];
        let result = NCryptSignHash(
            target_key.handle(),
            padding_info_param,
            &digest,
            Some(&mut signature),
            ptr::addr_of_mut!(signature_size),
            padding_flag,
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_INVALID_PARAMETER));
    }
}

#[test]
fn test_rsa_2k_sign_algid_null() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa2k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_algid_null(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    None, // don't touch the RSA-CRT property
                );
            }
        }
    }
}

#[test]
fn test_rsa_2k_sign_algid_null_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa2k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_algid_null(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(true), // intentionally enable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_2k_sign_algid_null_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa2k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_algid_null(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(false), // intentionally disable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_3k_sign_algid_null() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa3k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_algid_null(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    None, // don't touch the RSA-CRT property
                );
            }
        }
    }
}

#[test]
fn test_rsa_3k_sign_algid_null_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa3k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_algid_null(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(true), // intentionally enable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_3k_sign_algid_null_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa3k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_algid_null(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(false), // intentionally disable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_4k_sign_algid_null() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa4k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_algid_null(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    None, // don't touch the RSA-CRT property
                );
            }
        }
    }
}

#[test]
fn test_rsa_4k_sign_algid_null_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa4k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_algid_null(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(true), // intentionally enable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_4k_sign_algid_null_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa4k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_rsa_sign_algid_null(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(false), // intentionally disable RSA-CRT
                );
            }
        }
    }
}

fn test_helper_verify_failure(
    key_type: KeyType,
    key_enc_algo: KeyEncryptionAlgorithm,
    padding_type: Option<NCryptPaddingType>,
    padding_flag_type: Option<NCryptPaddingType>,
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
            NCRYPT_ALLOW_SIGNING_FLAG,
            enable_crt,
        );

        // Based on the provided key type, choose an appropriate maximum size
        // for the ciphertext and plaintext.
        let data_len_max: usize = match key_type {
            KeyType::Rsa2k => RSA_2K_DATA_SIZE_LIMIT,
            KeyType::Rsa3k => RSA_3K_DATA_SIZE_LIMIT,
            KeyType::Rsa4k => RSA_4K_DATA_SIZE_LIMIT,
            _ => panic!("Provided KeyType is not RSA: {:?}", key_type),
        };

        // Choose a digest size appropriate to the specified padding algorithm
        let digest_size: usize = match padding_alg {
            NCryptShaAlgorithm::Sha256 => 32,
            NCryptShaAlgorithm::Sha384 => 48,
            NCryptShaAlgorithm::Sha512 => 64,
            NCryptShaAlgorithm::Sha1 => 20,
        };

        // Set the padding flag based on the provided parameter.
        let mut padding_flag = NCRYPT_FLAGS(0);
        if let Some(pftype) = padding_flag_type {
            padding_flag = match pftype {
                NCryptPaddingType::Pkcs1 => NCRYPT_PAD_PKCS1_FLAG,
                NCryptPaddingType::Pss => NCRYPT_PAD_PSS_FLAG,
            };
        }

        // Similarly, set up the padding info structs, if the provided
        // `padding_type` parameter was specified.
        let padding_info_pkcs1;
        let padding_info_pss;
        let mut padding_info_param: Option<*const std::ffi::c_void> = None;
        if let Some(ptype) = padding_type {
            // set up the padding info structs, if necessary
            match ptype {
                NCryptPaddingType::Pkcs1 => {
                    padding_info_pkcs1 = BCRYPT_PKCS1_PADDING_INFO {
                        pszAlgId: padding_alg.into(),
                    };
                    padding_info_param =
                        Some(ptr::addr_of!(padding_info_pkcs1) as *const std::ffi::c_void);
                }
                NCryptPaddingType::Pss => {
                    padding_info_pss = BCRYPT_PSS_PADDING_INFO {
                        pszAlgId: padding_alg.into(),
                        cbSalt: rand::random::<u32>() % digest_size as u32,
                    };
                    padding_info_param =
                        Some(ptr::addr_of!(padding_info_pss) as *const std::ffi::c_void);
                }
            };
        }

        // Generate a random digest.
        let mut digest = vec![1u8; digest_size];
        rand_bytes(&mut digest).expect("Failed to generate random bytes");

        let mut signature_size = 0u32;
        let result = NCryptSignHash(
            target_key.handle(),
            padding_info_param,
            &digest,
            None,
            ptr::addr_of_mut!(signature_size),
            padding_flag,
        );
        assert!(result.is_ok());
        assert_eq!(signature_size, data_len_max as u32);

        let mut signature = vec![0u8; signature_size as usize];
        let result = NCryptSignHash(
            target_key.handle(),
            padding_info_param,
            &digest,
            Some(&mut signature),
            ptr::addr_of_mut!(signature_size),
            padding_flag,
        );
        assert!(result.is_ok());
        assert_eq!(signature_size, data_len_max as u32);

        // Corrupt the signature.
        signature[0] = signature[0].wrapping_add(1);
        let result = NCryptVerifySignature(
            target_key.handle(),
            padding_info_param,
            &digest,
            &signature,
            padding_flag,
        );
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.unwrap_err().code(), HRESULT(NTE_BAD_SIGNATURE));
    }
}

#[test]
fn test_rsa_2k_verify_failure() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa2k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_verify_failure(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    None, // don't touch the RSA-CRT property
                );
            }
        }
    }
}

#[test]
fn test_rsa_2k_verify_failure_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa2k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_verify_failure(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(true), // intentionally enable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_2k_verify_failure_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa2k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_verify_failure(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(false), // intentionally disable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_3k_verify_failure() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa3k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_verify_failure(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    None, // don't touch the RSA-CRT property
                );
            }
        }
    }
}

#[test]
fn test_rsa_3k_verify_failure_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa3k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_verify_failure(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(true), // intentionally enable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_3k_verify_failure_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa3k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_verify_failure(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(false), // intentionally disable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_4k_verify_failure() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa4k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_verify_failure(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    None, // don't touch the RSA-CRT property
                );
            }
        }
    }
}

#[test]
fn test_rsa_4k_verify_failure_crt_enable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa4k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_verify_failure(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(true), // intentionally enable RSA-CRT
                );
            }
        }
    }
}

#[test]
fn test_rsa_4k_verify_failure_crt_disable() {
    for key_enc_alg in KEY_ENC_ALOG.iter() {
        for padding_alg in NCRYPT_SHA_ALGORITHMS.iter() {
            for pad_type in NCRYPT_PADDING_TYPES.iter() {
                let key_type = KeyType::Rsa4k;
                let padding_type = Some(*pad_type);
                let padding_flag_type = Some(*pad_type);
                test_helper_verify_failure(
                    key_type,
                    *key_enc_alg,
                    padding_type,
                    padding_flag_type,
                    *padding_alg,
                    Some(false), // intentionally disable RSA-CRT
                );
            }
        }
    }
}
