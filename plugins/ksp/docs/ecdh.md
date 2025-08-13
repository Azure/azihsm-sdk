# ECDH Algorithm Support in Azure Integrated HSM (AZIHSM) KSP

## Introduction
This document provides a detailed description of the technical implementation of the ECDH Algorithm support in AZIHSM Key Storage Provider (AZIHSM-KSP). It covers the usage of NCRYPT APIs to target the ECDH algorithm, including specific data sizes, buffers, flags, and other relevant details.

## Overview
The ECDH (Elliptic Curve Diffie-Hellman) algorithm is widely used for secure key exchange. This document describes how to use the ECDH algorithm using NCRYPT APIs. The focus is on the key exchange process and the subsequent key derivation using two algorithms: HKDF (HMAC-based Key Derivation Function) and KBKDF (Key-Based Key Derivation Function). These key derivation algorithms ensure that the derived keys are secure and suitable for cryptographic operations.

## ECDH Shared Secret Generation and Key Derivation usign KDF

### NCRYPT API Usage for ECDH Shared Secret Generation

#### Sequence of operation
1. **Create an ECDH Key**
    - NCRYPT API to use: `NCryptCreatePersistedKey()`
    - Algorithm ID: use one of the following ID's
        `BCRYPT_ECDH_ALGORITHM`, or
        `BCRYPT_ECDH_P256_ALGORITHM`, or
        `BCRYPT_ECDH_P384_ALGORITHM`, or
        `BCRYPT_ECDH_P521_ALGORITHM`
        - Reference: *https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers*
    - Flags to use: `NCRYPT_DO_NOT_FINALIZE_FLAG`

2. **Set Property**
    - NCRYPT API to use: `NCryptSetProperty()`
    - **Setting the Curve Type**
        - Property Identifier to use to set the curve type:
            `NCRYPT_ECC_CURVE_NAME_PROPERTY`
        - BCRYPT Identifier to set Curve type:
            `BCRYPT_ECC_CURVE_NISTP256` or
            `BCRYPT_ECC_CURVE_NISTP384` or
            `BCRYPT_ECC_CURVE_NISTP521`
        - Flags to use for Set Property: None

3. **Call Finalize to finalize the key and its properties**
    - NCRYPT API to use: `NCryptFinalizeKey()`
    - Flags to use: `None`

4. **Export Public Key**
    - NCRYPT API to use: `NCryptExportKey()`
        - BlobType used : `NCRYPT_OPAQUETRANSPORT_BLOB`
        - Flags used: None

5. **Public Key exchange between 2 parties**

6. **Import the Public Key Blob**
    - NCRYPT API to use: `NCryptImportKey()`
    - BlobType used : `NCRYPT_OPAQUETRANSPORT_BLOB`
    - Flags used: `NCRYPT_DO_NOT_FINALIZE_FLAG`

7. **Generate Secret Agreement**
    - NCRYPT API to use: `NCryptSecretAgreement()`
    - Flags used: None

8. **Derive the Target Key Using KDFs**
    - This KSP supports two key derivation algorithms
        - **HKDF**
        - **KB-KDF**


    **Key Derivation using HKDF**
    - Supported Key types for derivation:
        - `AES-128`, or `AES-192`, or `AES-256`
    - NCRYPT API to use: `NCryptDeriveKey()`
    - KDF Identifier: `BCRYPT_HKDF_ALGORITHM`
    - Data that needs to be passed as part of parameter list:
        - Digest Kind
            - BufferType Identifier: `KDF_HASH_ALGORITHM`
            - DigestKind Identifier:
                - `BCRYPT_SHA1_ALGORITHM` (or)
                - `BCRYPT_SHA256_ALGORITHM` (or)
                - `BCRYPT_SHA384_ALGORITHM` (or)
                - `BCRYPT_SHA512_ALGORITHM`
        - Salt
            - BufferType Identifier: `KDF_HKDF_SALT`
            - Salt data max size: `64 Bytes`
        - Info
            - BufferType Identifier: `KDF_HKDF_INFO`
            - Info data max size: `16 Bytes`
        - Key Bit length
            - BufferType Identifier: `KDF_KEYBITLENGTH`
            - Supported Key Bit Length:
                - `128`, `192` or `256`


    **Key Derivation using KB-KDF**
    - Supported Key types for derivation:
        - `AES-128` or `AES-192` or `AES-256`
    - NCRYPT API to use: `NCryptDeriveKey()`
    - KDF Identifier: `BCRYPT_SP800108_CTR_HMAC_ALGORITHM`
    - Data that needs to be passed as part of parameter list:
        - Digest Kind
            - BufferType Identifier: `KDF_HASH_ALGORITHM`
            - DigestKind Identifier:
                - `BCRYPT_SHA1_ALGORITHM` (or)
                - `BCRYPT_SHA256_ALGORITHM` (or)
                - `BCRYPT_SHA384_ALGORITHM` (or)
                - `BCRYPT_SHA512_ALGORITHM`
        - Context
            - BufferType Identifier: `KDF_CONTEXT`
            - Context data max size: `16 Bytes`
        - Label
            - BufferType Identifier: `KDF_LABEL`
            - Label data max size: `16 Bytes`
        - Key Bit length
            - BufferType Identifier: `KDF_KEYBITLENGTH`
            - Supported Key Bit Length:
                - `128`, `192` or `256`

9. **Import the derived key buffer to get the key handle**
    - NCRYPT API to use: `NCryptImportKey()`
    - BlobType used : `AzIHsmDerivedKeyImportBlob`
        - *Please Note: "AzIHsmDerivedKeyImportBlob" is a custom string identifier that needs to be used to import a derived key after the key derivation operation*
    - Flags used: `NCRYPT_DO_NOT_FINALIZE_FLAG`

10. **Set Property for the derived AES key**
    - NCRYPT API to use: `NCryptSetProperty()`
    - **Setting the Encryption Mode**
        - Property Identifier to use to set the chaining mode:  `NCRYPT_CHAINING_MODE_PROPERTY`
        - BCRYPT Identifier to set Encryption mode: `BCRYPT_CHAIN_MODE_CBC`
        *Please Note: BCRYPT_CHAIN_MODE_GCM is currently NOT supported for a derived key*
        - Flags to use for Set Property: None
    - **Setting the Key Length**
        - Property Identifier to use to set Key Length: `NCRYPT_LENGTH_PROPERTY`
        - Expected Key Length: 128, 192, or 256

11. **Call Finalize to finalize the derived key and its properties**
    - NCRYPT API to use: `NCryptFinalizeKey()`

#### Note:
1. As shown in the below code snippet methods like NCryptEncrypt, NcryptDecrypt, and NCryptExportKey require two consecutive calls:
    - The first call retrieves the length of the buffer needed for the operation.
    - The second call, with the allocated buffer passed in, writes the output bytes into the buffer.

## Examples
Here is a code snippet to use ECDH to generate the secret and then use KDFs to derive the target key.

```rust
// Constants
const AES_KEY_BIT_LENGTH_128: usize = 128;
const AZIHSM_DERIVED_KEY_IMPORT_BLOB: PCWSTR = w!("AzIHsmDerivedKeyImportBlob");
enum BlobType {
    PublicKeyBlob,
    AzIHsmImportKeyBlob,
}

// ECDH followed by HKDF test method
fn test_ecc_p256_hkdf_derive_aes_128_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP256,
        AES_KEY_BIT_LENGTH_128,
        BCRYPT_HKDF_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_128 as u32,
    );
}

// ECDH followed by KB-KDF test method
fn test_ecc_p256_kbkdf_derive_aes_128_key() {
    test_derive_key_inner(
        BCRYPT_ECC_CURVE_NISTP256,
        AES_KEY_BIT_LENGTH_128,
        BCRYPT_SP800108_CTR_HMAC_ALGORITHM,
        BCRYPT_CHAIN_MODE_CBC,
        AES_KEY_BIT_LENGTH_128 as u32,
    );
}

// Entry Method
fn test_derive_key_inner(
    curve_name: PCWSTR,
    derived_key_bitlen: usize,
    kdf_type: PCWSTR,
    derived_key_encryption_mode: PCWSTR,
    derived_key_length: u32,
) {
    let mut azihsm_provider: NCRYPT_PROV_HANDLE = NCRYPT_PROV_HANDLE(0);

    // Alice's parameters
    let mut alice_key_handle: NCRYPT_KEY_HANDLE = NCRYPT_KEY_HANDLE(0);
    let mut alice_imported_bob_key_handle: NCRYPT_KEY_HANDLE = NCRYPT_KEY_HANDLE(0);
    let mut alice_secret_handle: NCRYPT_SECRET_HANDLE = NCRYPT_SECRET_HANDLE(0);
    let mut alice_derived_key_handle: NCRYPT_KEY_HANDLE = NCRYPT_KEY_HANDLE(0);

    // Bob's parameters
    let mut bob_key_handle: NCRYPT_KEY_HANDLE = NCRYPT_KEY_HANDLE(0);
    let mut bob_imported_alice_key_handle: NCRYPT_KEY_HANDLE = NCRYPT_KEY_HANDLE(0);
    let mut bob_secret_handle: NCRYPT_SECRET_HANDLE = NCRYPT_SECRET_HANDLE(0);
    let mut bob_derived_key_handle: NCRYPT_KEY_HANDLE = NCRYPT_KEY_HANDLE(0);

    unsafe {
        let result = NCryptOpenStorageProvider(&mut azihsm_provider, AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        // Key Creation and Public Key Export for Alice
        create_and_finalize_key(
            azihsm_provider,
            &mut alice_key_handle,
            BCRYPT_ECDH_ALGORITHM,
            Some(curve_name),
        );

        let alice_exported_key = export_public_key(alice_key_handle);

        // Key Creation and Public Key Export for Bob
        create_and_finalize_key(
            azihsm_provider,
            &mut bob_key_handle,
            BCRYPT_ECDH_ALGORITHM,
            Some(curve_name),
        );

        let bob_exported_key = export_public_key(bob_key_handle);

        // Public Key Exchange between Alice and Bob
        alice_imported_bob_key_handle =
            import_key(azihsm_provider, &bob_exported_key, BlobType::PublicKeyBlob);

        bob_imported_alice_key_handle =
            import_key(azihsm_provider, &alice_exported_key, BlobType::PublicKeyBlob);

        // Secret Generation
        alice_secret_handle = generate_secret(alice_key_handle, alice_imported_bob_key_handle);
        bob_secret_handle = generate_secret(bob_key_handle, bob_imported_alice_key_handle);

        // Derive key for alice using alice_secret
        let alice_derived_key_buffer =
            derive_key(alice_secret_handle, derived_key_bitlen, kdf_type);

        // Import alice derived key buffer to get the key handle
        alice_derived_key_handle = import_key(
            azihsm_provider,
            &alice_derived_key_buffer,
            BlobType::AzIHsmImportKeyBlob,
        );

        // Set encryption mode and key length for alice aes derived key
        set_property(
            alice_derived_key_handle,
            Some(derived_key_encryption_mode),
            Some(derived_key_length),
        );

        // Finalize Alice's derived key
        let result = NCryptFinalizeKey(alice_derived_key_handle, NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Derive key for bob using bob_secret
        let bob_derived_key_buffer = derive_key(bob_secret_handle, derived_key_bitlen, kdf_type);

        // Import bob derived key buffer to get the key handle
        bob_derived_key_handle = import_key(
            azihsm_provider,
            &bob_derived_key_buffer,
            BlobType::AzIHsmImportKeyBlob,
        );

        // Set encryption mode and key length for bob aes derived key
        set_property(
            bob_derived_key_handle,
            Some(derived_key_encryption_mode),
            Some(derived_key_length),
        );

        // Finalize the Bob's derived key
        let result = NCryptFinalizeKey(bob_derived_key_handle, NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // use alice key for encrypting plain text and bob key
        // for decrypting and compare the data for validation.
        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).unwrap();
        let mut iv_orig = iv.clone();

        let mut padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: iv.as_mut_ptr(),
            cbIV: iv.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        // Get Ciphertext length
        let result = NCryptEncrypt(
            alice_derived_key_handle,
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        // Allocate buffer for ciphertext
        let mut ciphertext = vec![0u8; ciphertext_len as usize];

        // Get Ciphertext
        let result = NCryptEncrypt(
            alice_derived_key_handle,
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        // Decrypt
        let mut decrypted_len = 0u32;

        // Get Decrypted length
        let result = NCryptDecrypt(
            bob_derived_key_handle,
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        // Allocate buffer for decrypted text
        let mut decrypted = vec![0u8; decrypted_len as usize];

        // Get Decrypted text
        let result = NCryptDecrypt(
            bob_derived_key_handle,
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext, decrypted);

        cleanup(
            vec![
                alice_key_handle,
                bob_key_handle,
                alice_imported_bob_key_handle,
                bob_imported_alice_key_handle,
                alice_derived_key_handle,
                bob_derived_key_handle,
            ],
            vec![alice_secret_handle, bob_secret_handle],
            azihsm_provider,
        );
    }
}

// Helper method for create ECDH key, set property and finalize
fn create_and_finalize_key(
    azihsm_provider: NCRYPT_PROV_HANDLE,
    key_handle: &mut NCRYPT_KEY_HANDLE,
    algorithm: PCWSTR,
    curve: Option<PCWSTR>,
) {
    let result = NCryptCreatePersistedKey(
        azihsm_provider,
        key_handle,
        algorithm,
        None,
        CERT_KEY_SPEC(0),
        NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
    );
    assert!(result.is_ok());

    if algorithm == BCRYPT_ECDH_ALGORITHM {
        if let Some(curve_name) = curve {
            let curve_type = std::slice::from_raw_parts(
                curve_name.as_ptr().cast::<u8>(),
                curve_name.to_string().unwrap().len() * std::mem::size_of::<u16>(),
            );

            let result = NCryptSetProperty(
                *key_handle,
                NCRYPT_ECC_CURVE_NAME_PROPERTY,
                curve_type,
                NCRYPT_FLAGS(0),
            );
            assert!(result.is_ok());
        }
    }

    let result = NCryptFinalizeKey(*key_handle, NCRYPT_FLAGS(0));
    assert!(result.is_ok());
}

// Helper method for exporting public key
fn export_public_key(key_handle: NCRYPT_KEY_HANDLE) -> Vec<u8> {
    let mut export_buffer_size = 0u32;
    let result = NCryptExportKey(
        key_handle,
        None,
        NCRYPT_OPAQUETRANSPORT_BLOB,
        None,
        None,
        ptr::addr_of_mut!(export_buffer_size),
        NCRYPT_FLAGS(0),
    );
    assert!(result.is_ok());
    assert!(
        export_buffer_size > 0,
        "Expected non-zero export buffer size, but found {}",
        export_buffer_size
    );

    let mut export_buffer = vec![0u8; export_buffer_size as usize];
    let result = NCryptExportKey(
        key_handle,
        None,
        NCRYPT_OPAQUETRANSPORT_BLOB,
        None,
        Some(&mut export_buffer),
        ptr::addr_of_mut!(export_buffer_size),
        NCRYPT_FLAGS(0),
    );
    assert!(result.is_ok());
    assert!(!export_buffer.is_empty(), "Export buffer is empty!");

    export_buffer[..export_buffer_size as usize].to_vec()
}

// Helper method for public and derived Key Import
fn import_key(
    azihsm_provider: NCRYPT_PROV_HANDLE,
    key_blob: &[u8],
    blob_type: BlobType,
) -> NCRYPT_KEY_HANDLE {
    let mut imported_key_handle: NCRYPT_KEY_HANDLE = NCRYPT_KEY_HANDLE(0);
    let result = match blob_type {
        BlobType::PublicKeyBlob => NCryptImportKey(
            azihsm_provider,
            NCRYPT_KEY_HANDLE(0),
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            &mut imported_key_handle,
            key_blob,
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        ),
        BlobType::AzIHsmImportKeyBlob => NCryptImportKey(
            azihsm_provider,
            NCRYPT_KEY_HANDLE(0),
            AZIHSM_DERIVED_KEY_IMPORT_BLOB,
            None,
            &mut imported_key_handle,
            key_blob,
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        ),
    };
    assert!(result.is_ok());
    imported_key_handle
}

// Helper method for Set Property
fn set_property(
    key_handle: NCRYPT_KEY_HANDLE,
    encryption_mode_name: Option<PCWSTR>,
    key_length: Option<u32>,
) {
    // Set encryption mode if provided
    if let Some(mode_name) = encryption_mode_name {
        let encryption_mode = std::slice::from_raw_parts(
            mode_name.as_ptr().cast::<u8>(),
            mode_name.to_string().unwrap().len() * std::mem::size_of::<u16>(),
        );
        let result = NCryptSetProperty(
            key_handle,
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok(), "Failed to set encryption mode property");
    }

    // Set key length if provided
    if let Some(length) = key_length {
        let length_bytes = length.to_le_bytes();
        let result = NCryptSetProperty(
            key_handle,
            NCRYPT_LENGTH_PROPERTY,
            &length_bytes,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok(), "Failed to set key length property");
    }
}

// Helper for ECDH Secret Generation
fn generate_secret(
    key_handle: NCRYPT_KEY_HANDLE,
    imported_key_handle: NCRYPT_KEY_HANDLE,
) -> NCRYPT_SECRET_HANDLE {
    let mut secret_handle: NCRYPT_SECRET_HANDLE = NCRYPT_SECRET_HANDLE(0);

    let result = NCryptSecretAgreement(
        key_handle,
        imported_key_handle,
        &mut secret_handle,
        NCRYPT_FLAGS(0),
    );
    assert!(result.is_ok());

    secret_handle
}

// Helper wrapper for key derivation
fn derive_key(
    secret_handle: NCRYPT_SECRET_HANDLE,
    derived_key_bitlen: usize,
    kdf: PCWSTR,
) -> Vec<u8> {
    if equals(kdf, BCRYPT_HKDF_ALGORITHM) {
        return hkdf_derive(secret_handle, derived_key_bitlen);
    } else if equals(kdf, BCRYPT_SP800108_CTR_HMAC_ALGORITHM) {
        return kbkdf_derive(secret_handle, derived_key_bitlen);
    } else {
        println!("Error: Unsupported KDF type {:?}", kdf);
        assert!(false);
    }
    // This line is unreachable, but returning an empty vector to satisfy the return type
    Vec::new()
}

// Helper method for HKDF derive
fn hkdf_derive(secret_handle: NCRYPT_SECRET_HANDLE, derived_key_bitlen: usize) -> Vec<u8> {
    let mut salt_data = [0u8; 64];
    let salt_bytes = "salt".as_bytes();
    salt_data[..salt_bytes.len()].copy_from_slice(salt_bytes);

    let mut info = [0u8; 16];
    let info_bytes = "label".as_bytes();
    info[..info_bytes.len()].copy_from_slice(info_bytes);

    let key_bit_length = derived_key_bitlen as u32;
    let param_buffers = [
        // digest kind
        BCryptBuffer {
            cbBuffer: (BCRYPT_SHA256_ALGORITHM.to_string().unwrap().len()
                * std::mem::size_of::<u16>()) as u32,
            BufferType: KDF_HASH_ALGORITHM,
            pvBuffer: BCRYPT_SHA256_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
        },
        // info
        BCryptBuffer {
            cbBuffer: info_bytes.len() as u32,
            BufferType: KDF_HKDF_INFO,
            pvBuffer: info_bytes.as_ptr() as *mut std::ffi::c_void,
        },
        // salt
        BCryptBuffer {
            cbBuffer: salt_data.len() as u32,
            BufferType: KDF_HKDF_SALT,
            pvBuffer: salt_data.as_ptr() as *mut std::ffi::c_void,
        },
        // key bit length
        BCryptBuffer {
            cbBuffer: std::mem::size_of::<u32>() as u32,
            BufferType: KDF_KEYBITLENGTH,
            pvBuffer: &key_bit_length as *const u32 as *mut std::ffi::c_void,
        },
    ];

    let param_list = BCryptBufferDesc {
        ulVersion: NCRYPTBUFFER_VERSION,
        cBuffers: param_buffers.len() as u32,
        pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
    };

    let mut output_size = 0u32;
    let result = NCryptDeriveKey(
        secret_handle,
        BCRYPT_HKDF_ALGORITHM,
        Some(&param_list),
        None,
        ptr::addr_of_mut!(output_size),
        0,
    );
    assert!(result.is_ok());

    let mut derived_key_buf = vec![0u8; output_size as usize];
    let result = NCryptDeriveKey(
        secret_handle,
        BCRYPT_HKDF_ALGORITHM,
        Some(&param_list),
        Some(&mut derived_key_buf),
        ptr::addr_of_mut!(output_size),
        0,
    );
    assert!(result.is_ok());
    derived_key_buf = derived_key_buf[..output_size as usize].to_vec();
    println!("HKDF Key buffer: {:?}", derived_key_buf);
    derived_key_buf
}

// Helper method for KB-KDF derive
fn kbkdf_derive(secret_handle: NCRYPT_SECRET_HANDLE, derived_key_bitlen: usize) -> Vec<u8> {
    let mut label_data = [0u8; 16];
    let label_bytes = "label".as_bytes();
    label_data[..label_bytes.len()].copy_from_slice(label_bytes);

    let mut context = [0u8; 16];
    let context_bytes = "context".as_bytes();
    context[..context_bytes.len()].copy_from_slice(context_bytes);

    let key_bit_length = derived_key_bitlen as u32;
    let param_buffers = [
        // digest kind
        BCryptBuffer {
            cbBuffer: (BCRYPT_SHA256_ALGORITHM.to_string().unwrap().len()
                * std::mem::size_of::<u16>()) as u32,
            BufferType: KDF_HASH_ALGORITHM,
            pvBuffer: BCRYPT_SHA256_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
        },
        // context
        BCryptBuffer {
            cbBuffer: context_bytes.len() as u32,
            BufferType: KDF_CONTEXT,
            pvBuffer: context_bytes.as_ptr() as *mut std::ffi::c_void,
        },
        // label
        BCryptBuffer {
            cbBuffer: label_data.len() as u32,
            BufferType: KDF_LABEL,
            pvBuffer: label_data.as_ptr() as *mut std::ffi::c_void,
        },
        // key bit length
        BCryptBuffer {
            cbBuffer: std::mem::size_of::<u32>() as u32,
            BufferType: KDF_KEYBITLENGTH,
            pvBuffer: &key_bit_length as *const u32 as *mut std::ffi::c_void,
        },
    ];

    let param_list = BCryptBufferDesc {
        ulVersion: NCRYPTBUFFER_VERSION,
        cBuffers: param_buffers.len() as u32,
        pBuffers: param_buffers.as_ptr() as *mut BCryptBuffer,
    };

    let mut output_size = 0u32;
    let result = NCryptDeriveKey(
        secret_handle,
        BCRYPT_SP800108_CTR_HMAC_ALGORITHM,
        Some(&param_list),
        None,
        ptr::addr_of_mut!(output_size),
        0,
    );
    assert!(result.is_ok());

    let mut derived_key_buf = vec![0u8; output_size as usize];
    let result = NCryptDeriveKey(
        secret_handle,
        BCRYPT_SP800108_CTR_HMAC_ALGORITHM,
        Some(&param_list),
        Some(&mut derived_key_buf),
        ptr::addr_of_mut!(output_size),
        0,
    );
    assert!(result.is_ok());
    derived_key_buf = derived_key_buf[..output_size as usize].to_vec();
    println!("KBKDF Key buffer: {:?}", derived_key_buf);
    derived_key_buf
}

// Utility helper
fn cleanup(
    key_handles: Vec<NCRYPT_KEY_HANDLE>,
    secret_handles: Vec<NCRYPT_SECRET_HANDLE>,
    azihsm_provider: NCRYPT_PROV_HANDLE,
) {
    for key_handle in key_handles {
        let result = NCryptDeleteKey(key_handle, NCRYPT_SILENT_FLAG.0);
        assert!(result.is_ok());
    }

    for secret_handle in secret_handles {
        let secret: NCRYPT_HANDLE = NCRYPT_HANDLE(secret_handle.0);
        let result = NCryptFreeObject(secret);
        assert!(result.is_ok());
    }

    let result = NCryptFreeObject(azihsm_provider);
    assert!(result.is_ok());
}

// Utility helper
fn equals(lhs: PCWSTR, rhs: PCWSTR) -> bool {
    unsafe {
        let lhs_str = WideCString::from_ptr_str(lhs.as_ptr());
        let rhs_str = WideCString::from_ptr_str(rhs.as_ptr());
        lhs_str == rhs_str
    }
}

