// Copyright (C) Microsoft Corporation. All rights reserved.
mod common;
use std::mem::size_of;
use std::ptr;

use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::*;

use crypto::rand::rand_bytes;

use crate::common::*;

#[derive(Debug, Copy, Clone)]
enum EccCurve {
    P256,
    P384,
    P521,
}

#[derive(Debug, Copy, Clone)]
enum RsaSize {
    Size2k,
    Size3k,
    Size4k,
}

impl CleanupTrait for BCRYPT_ALG_HANDLE {
    fn cleanup(&self) {
        unsafe {
            if !self.is_invalid() {
                _ = BCryptCloseAlgorithmProvider(*self, 0);
            }
        }
    }
}

impl CleanupTrait for BCRYPT_KEY_HANDLE {
    fn cleanup(&self) {
        unsafe {
            if !self.is_invalid() {
                _ = BCryptDestroyKey(*self);
            }
        }
    }
}

impl CleanupTrait for BCRYPT_SECRET_HANDLE {
    fn cleanup(&self) {
        unsafe {
            if !self.is_invalid() {
                _ = BCryptDestroySecret(*self);
            }
        }
    }
}

type BcryptAlgHandle = Handle<BCRYPT_ALG_HANDLE>;
type BcryptKeyHandle = Handle<BCRYPT_KEY_HANDLE>;
type BcryptSecretHandle = Handle<BCRYPT_SECRET_HANDLE>;

unsafe fn ncrypt_create_ec_key(
    provider: &ProviderHandle,
    alg_string: PCWSTR,
    curve: EccCurve,
) -> KeyHandle {
    let mut key = KeyHandle::new();

    let result = NCryptCreatePersistedKey(
        provider.handle(),
        key.as_mut(),
        alg_string,
        None,
        CERT_KEY_SPEC(0),
        NCRYPT_FLAGS(0),
    );
    assert!(result.is_ok(), "result {:?}", result);

    let curve_type = match curve {
        EccCurve::P256 => std::slice::from_raw_parts(
            BCRYPT_ECC_CURVE_NISTP256.as_ptr().cast::<u8>(),
            BCRYPT_ECC_CURVE_NISTP256.to_string().unwrap().len() * size_of::<u16>(),
        ),
        EccCurve::P384 => std::slice::from_raw_parts(
            BCRYPT_ECC_CURVE_NISTP384.as_ptr().cast::<u8>(),
            BCRYPT_ECC_CURVE_NISTP384.to_string().unwrap().len() * size_of::<u16>(),
        ),
        EccCurve::P521 => std::slice::from_raw_parts(
            BCRYPT_ECC_CURVE_NISTP521.as_ptr().cast::<u8>(),
            BCRYPT_ECC_CURVE_NISTP521.to_string().unwrap().len() * size_of::<u16>(),
        ),
    };
    let result = NCryptSetProperty(
        key.handle(),
        NCRYPT_ECC_CURVE_NAME_PROPERTY,
        curve_type,
        NCRYPT_FLAGS(0),
    );
    assert!(result.is_ok(), "result {:?}", result);

    let result = NCryptFinalizeKey(key.handle(), NCRYPT_FLAGS(0));
    assert!(result.is_ok(), "result {:?}", result);

    key
}

unsafe fn ncrypt_sign(
    key: &KeyHandle,
    digest: &[u8],
    padding_info: Option<*const std::ffi::c_void>,
    flags: NCRYPT_FLAGS,
) -> Vec<u8> {
    let mut signature_size = 0u32;
    let result = NCryptSignHash(
        key.handle(),
        padding_info,
        digest,
        None,
        ptr::addr_of_mut!(signature_size),
        flags,
    );
    assert!(result.is_ok(), "result {:?}", result);

    let mut signature = vec![0u8; signature_size as usize];
    let result = NCryptSignHash(
        key.handle(),
        padding_info,
        digest,
        Some(&mut signature),
        ptr::addr_of_mut!(signature_size),
        flags,
    );
    assert!(result.is_ok(), "result {:?}", result);

    signature[..signature_size as usize].to_vec()
}

unsafe fn ncrypt_export_key(key: &KeyHandle, blob_type: PCWSTR) -> Vec<u8> {
    let mut exportbuffer_size = 0u32;
    let result = NCryptExportKey(
        key.handle(),
        None,
        blob_type,
        None,
        None,
        ptr::addr_of_mut!(exportbuffer_size),
        NCRYPT_FLAGS(0),
    );
    assert!(result.is_ok(), "result {:?}", result);
    assert!(
        exportbuffer_size > 0,
        "Expected non-zero export buffer size, but found {}",
        exportbuffer_size
    );

    let mut export_buffer = vec![0u8; exportbuffer_size as usize];
    let result = NCryptExportKey(
        key.handle(),
        None,
        blob_type,
        None,
        Some(&mut export_buffer),
        ptr::addr_of_mut!(exportbuffer_size),
        NCRYPT_FLAGS(0),
    );
    assert!(result.is_ok(), "result {:?}", result);
    assert!(!export_buffer.is_empty(), "Export buffer is empty!");

    export_buffer[..exportbuffer_size as usize].to_vec()
}

unsafe fn ncrypt_import_public_key(
    provider: &ProviderHandle,
    blob_type: PCWSTR,
    public_key_buffer: &[u8],
) -> KeyHandle {
    let mut key = KeyHandle::new();

    let result = NCryptImportKey(
        provider.handle(),
        None,
        blob_type,
        None,
        key.as_mut(),
        public_key_buffer,
        NCRYPT_FLAGS(0),
    );
    assert!(result.is_ok(), "result {:?}", result);

    key
}

unsafe fn ncrypt_secret_agreement(private_key: &KeyHandle, public_key: &KeyHandle) -> SecretHandle {
    let mut secret_handle = SecretHandle::new();
    let result = NCryptSecretAgreement(
        private_key.handle(),
        public_key.handle(),
        secret_handle.as_mut(),
        NCRYPT_FLAGS(0),
    );
    assert!(result.is_ok(), "result {:?}", result);

    secret_handle
}

unsafe fn ncrypt_derive_aes_key(
    provider: &ProviderHandle,
    secret: &SecretHandle,
    kdf_algorithm: PCWSTR,
    kdf_params: Option<*const BCryptBufferDesc>,
    key_bit_length: u32,
) -> KeyHandle {
    // Get derived key information into buffer
    let mut derived_buffer_size = 0u32;
    let result = NCryptDeriveKey(
        secret.handle(),
        kdf_algorithm,
        kdf_params,
        None,
        ptr::addr_of_mut!(derived_buffer_size),
        0,
    );
    assert!(result.is_ok(), "result {:?}", result);

    let mut derived_buffer = vec![0u8; derived_buffer_size as usize];
    let result = NCryptDeriveKey(
        secret.handle(),
        kdf_algorithm,
        kdf_params,
        Some(&mut derived_buffer),
        ptr::addr_of_mut!(derived_buffer_size),
        0,
    );
    assert!(result.is_ok(), "result {:?}", result);

    // Import derived key buffer to get as key handle
    let mut derived_key = KeyHandle::new();
    let result = NCryptImportKey(
        provider.handle(),
        NCRYPT_KEY_HANDLE(0),
        AZIHSM_DERIVED_KEY_IMPORT_BLOB,
        None,
        derived_key.as_mut(),
        &derived_buffer,
        NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
    );
    assert!(result.is_ok(), "result {:?}", result);

    // Set encryption mode and key length for aes derived key
    set_property(
        derived_key.handle(),
        Some(BCRYPT_CHAIN_MODE_CBC),
        Some(key_bit_length),
    );

    // Finalize derived key
    let result = NCryptFinalizeKey(derived_key.handle(), NCRYPT_FLAGS(0));
    assert!(result.is_ok(), "result {:?}", result);

    derived_key
}

unsafe fn ncrypt_aes_encrypt(key: &KeyHandle, iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut iv_copy = iv.to_vec();
    let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
        cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
        pbIV: iv_copy.as_mut_ptr(),
        cbIV: iv_copy.len() as u32,
        cbOtherInfo: 0,
        pbOtherInfo: std::ptr::null_mut(),
        dwFlags: 0,
    };

    let mut encrypted_len = 0u32;
    let result = NCryptEncrypt(
        key.handle(),
        Some(plaintext),
        Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
        None,
        ptr::addr_of_mut!(encrypted_len),
        NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
    );
    assert!(result.is_ok(), "result {:?}", result);

    let mut encrypted = vec![0u8; encrypted_len as usize];
    let result = NCryptEncrypt(
        key.handle(),
        Some(plaintext),
        Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
        Some(&mut encrypted),
        ptr::addr_of_mut!(encrypted_len),
        NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
    );
    assert!(result.is_ok(), "result {:?}", result);

    encrypted[..encrypted_len as usize].to_vec()
}

unsafe fn ncrypt_aes_decrypt(key: &KeyHandle, iv: &[u8], encrypted: &[u8]) -> Vec<u8> {
    let mut iv_copy = iv.to_vec();
    let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
        cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
        pbIV: iv_copy.as_mut_ptr(),
        cbIV: iv_copy.len() as u32,
        cbOtherInfo: 0,
        pbOtherInfo: std::ptr::null_mut(),
        dwFlags: 0,
    };

    let mut decrypted_len = 0u32;
    let result = NCryptDecrypt(
        key.handle(),
        Some(encrypted),
        Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
        None,
        ptr::addr_of_mut!(decrypted_len),
        NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
    );
    assert!(result.is_ok(), "result {:?}", result);

    let mut decrypted = vec![0u8; decrypted_len as usize];
    let result = NCryptDecrypt(
        key.handle(),
        Some(encrypted),
        Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
        Some(&mut decrypted),
        ptr::addr_of_mut!(decrypted_len),
        NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
    );
    assert!(result.is_ok(), "result {:?}", result);

    decrypted[..decrypted_len as usize].to_vec()
}

unsafe fn bcrypt_create_ec_key(alg_handle: &BcryptAlgHandle, curve: EccCurve) -> BcryptKeyHandle {
    let mut key = BcryptKeyHandle::new();
    let bits = match curve {
        EccCurve::P256 => 256,
        EccCurve::P384 => 384,
        EccCurve::P521 => 521,
    };

    let result = BCryptGenerateKeyPair(alg_handle.handle(), key.as_mut(), bits, 0);
    assert!(result.is_ok(), "result {:?}", result);

    let result = BCryptFinalizeKeyPair(key.handle(), 0);
    assert!(result.is_ok(), "result {:?}", result);

    key
}

unsafe fn bcrypt_export_key(key: &BcryptKeyHandle, blob_type: PCWSTR) -> Vec<u8> {
    let mut exportbuffer_size = 0u32;
    let result = BCryptExportKey(
        key.handle(),
        None,
        blob_type,
        None,
        ptr::addr_of_mut!(exportbuffer_size),
        0,
    );
    assert!(result.is_ok(), "result {:?}", result);
    assert!(
        exportbuffer_size > 0,
        "Expected non-zero export buffer size, but found {}",
        exportbuffer_size
    );

    let mut export_buffer = vec![0u8; exportbuffer_size as usize];
    let result = BCryptExportKey(
        key.handle(),
        None,
        blob_type,
        Some(&mut export_buffer),
        ptr::addr_of_mut!(exportbuffer_size),
        0,
    );
    assert!(result.is_ok(), "result {:?}", result);
    assert!(!export_buffer.is_empty(), "Export buffer is empty!");

    export_buffer[..exportbuffer_size as usize].to_vec()
}

unsafe fn bcrypt_import_public_key(
    alg_handle: &BcryptAlgHandle,
    blob_type: PCWSTR,
    public_key_buffer: &[u8],
) -> BcryptKeyHandle {
    let mut key = BcryptKeyHandle::new();

    let result = BCryptImportKeyPair(
        alg_handle.handle(),
        None,
        blob_type,
        key.as_mut(),
        public_key_buffer,
        0,
    );
    assert!(result.is_ok(), "result {:?}", result);

    key
}

unsafe fn bcrypt_verify(
    key: &BcryptKeyHandle,
    digest: &[u8],
    signature: &[u8],
    padding_info: Option<*const std::ffi::c_void>,
    flags: BCRYPT_FLAGS,
) {
    let result = BCryptVerifySignature(key.handle(), padding_info, digest, signature, flags);
    assert!(result.is_ok(), "result {:?}", result);
}

unsafe fn bcrypt_secret_agreement(
    private_key: &BcryptKeyHandle,
    public_key: &BcryptKeyHandle,
) -> BcryptSecretHandle {
    let mut secret_handle = BcryptSecretHandle::new();
    let result = BCryptSecretAgreement(
        private_key.handle(),
        public_key.handle(),
        secret_handle.as_mut(),
        0,
    );
    assert!(result.is_ok(), "result {:?}", result);

    secret_handle
}

unsafe fn bcrypt_derive_aes_key(
    secret: &BcryptSecretHandle,
    kdf_algorithm: PCWSTR,
    kdf_params: Option<*const BCryptBufferDesc>,
    key_bit_length: u32,
) -> BcryptKeyHandle {
    // Get secret bytes in buffer
    let mut secret_buffer_size = 0u32;
    let result = BCryptDeriveKey(
        secret.handle(),
        BCRYPT_KDF_RAW_SECRET,
        None,
        None,
        ptr::addr_of_mut!(secret_buffer_size),
        0,
    );
    assert!(result.is_ok(), "result {:?}", result);

    let mut secret_buffer_le = vec![0u8; secret_buffer_size as usize];
    let result = BCryptDeriveKey(
        secret.handle(),
        BCRYPT_KDF_RAW_SECRET,
        None,
        Some(&mut secret_buffer_le),
        ptr::addr_of_mut!(secret_buffer_size),
        0,
    );
    assert!(result.is_ok(), "result {:?}", result);

    // Secret bytes are exported in little endian
    fn reverse_copy(dst: &mut [u8], src: &[u8]) {
        for (item1, item2) in src.iter().rev().zip(dst.iter_mut()) {
            *item2 = *item1;
        }
    }
    let mut secret_buffer_be = vec![0u8; secret_buffer_size as usize];
    reverse_copy(&mut secret_buffer_be, &secret_buffer_le);

    // Format secret data as symmetric key blob
    // https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_key_data_blob_header
    let mut secret_blob_vec = vec![0u8; 0];
    // ULONG Magic value
    secret_blob_vec.extend_from_slice(&BCRYPT_KEY_DATA_BLOB_MAGIC.to_le_bytes());
    // ULONG dwVersion
    secret_blob_vec.extend_from_slice(&(1_u32).to_le_bytes());
    // ULONG cbKeyData
    secret_blob_vec.extend_from_slice(&secret_buffer_size.to_le_bytes());
    // KeyData
    secret_blob_vec.extend_from_slice(&secret_buffer_be);

    // Get algorithm handle for KDF
    let mut alg_handle = BcryptAlgHandle::new();
    let result = BCryptOpenAlgorithmProvider(
        alg_handle.as_mut(),
        kdf_algorithm,
        MS_PRIMITIVE_PROVIDER,
        BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
    );
    assert!(result.is_ok(), "result {:?}", result);

    // Import secret data as key handle
    let mut secret_key = BcryptKeyHandle::new();
    let result = BCryptImportKey(
        alg_handle.handle(),
        None,
        BCRYPT_KEY_DATA_BLOB,
        secret_key.as_mut(),
        None,
        &secret_blob_vec,
        0,
    );
    assert!(result.is_ok(), "result {:?}", result);

    // Derive data from secret key
    let mut derived_key_buffer_size = key_bit_length / 8;
    let mut derived_key_buffer = vec![0u8; derived_key_buffer_size as usize];
    let result = BCryptKeyDerivation(
        secret_key.handle(),
        kdf_params,
        &mut derived_key_buffer,
        ptr::addr_of_mut!(derived_key_buffer_size),
        0,
    );
    assert!(result.is_ok(), "result {:?}", result);

    // Import derived data as AES key
    let mut aes_blob_vec = vec![0u8; 0];
    // https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_key_data_blob_header
    // ULONG Magic value
    aes_blob_vec.extend_from_slice(&BCRYPT_KEY_DATA_BLOB_MAGIC.to_le_bytes());
    // ULONG dwVersion
    aes_blob_vec.extend_from_slice(&(1_u32).to_le_bytes());
    // ULONG cbKeyData
    aes_blob_vec.extend_from_slice(&derived_key_buffer_size.to_le_bytes());
    // KeyData
    aes_blob_vec.extend_from_slice(&derived_key_buffer[..derived_key_buffer_size as usize]);

    let mut derived_key = BcryptKeyHandle::new();
    let result = BCryptImportKey(
        BCRYPT_AES_CBC_ALG_HANDLE,
        None,
        BCRYPT_KEY_DATA_BLOB,
        derived_key.as_mut(),
        None,
        &aes_blob_vec,
        0,
    );
    assert!(result.is_ok(), "result {:?}", result);

    derived_key
}

unsafe fn bcrypt_aes_encrypt(key: &BcryptKeyHandle, iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut encrypted_len = 0u32;
    let mut iv_copy = iv.to_vec();

    let result = BCryptEncrypt(
        key.handle(),
        Some(plaintext),
        None,
        Some(&mut iv_copy),
        None,
        ptr::addr_of_mut!(encrypted_len),
        BCRYPT_FLAGS(0),
    );
    assert!(result.is_ok(), "result {:?}", result);

    let mut encrypted = vec![0u8; encrypted_len as usize];
    let result = BCryptEncrypt(
        key.handle(),
        Some(plaintext),
        None,
        Some(&mut iv_copy),
        Some(&mut encrypted),
        ptr::addr_of_mut!(encrypted_len),
        BCRYPT_FLAGS(0),
    );
    assert!(result.is_ok(), "result {:?}", result);

    encrypted[..encrypted_len as usize].to_vec()
}

unsafe fn bcrypt_aes_decrypt(key: &BcryptKeyHandle, iv: &[u8], encrypted: &[u8]) -> Vec<u8> {
    let mut iv_copy = iv.to_vec();

    let mut decrypted_len = 0u32;
    let result = BCryptDecrypt(
        key.handle(),
        Some(encrypted),
        None,
        Some(&mut iv_copy),
        None,
        ptr::addr_of_mut!(decrypted_len),
        BCRYPT_FLAGS(0),
    );
    assert!(result.is_ok(), "result {:?}", result);

    let mut decrypted = vec![0u8; decrypted_len as usize];
    let result = BCryptDecrypt(
        key.handle(),
        Some(encrypted),
        None,
        Some(&mut iv_copy),
        Some(&mut decrypted),
        ptr::addr_of_mut!(decrypted_len),
        BCRYPT_FLAGS(0),
    );
    assert!(result.is_ok(), "result {:?}", result);

    decrypted[..decrypted_len as usize].to_vec()
}

#[test]
fn test_ecdsa_export_pubkey_bcrypt_256() {
    test_ecdsa_export_pubkey_bcrypt_helper(EccCurve::P256);
}

#[test]
fn test_ecdsa_export_pubkey_bcrypt_384() {
    test_ecdsa_export_pubkey_bcrypt_helper(EccCurve::P384);
}

#[test]
fn test_ecdsa_export_pubkey_bcrypt_521() {
    test_ecdsa_export_pubkey_bcrypt_helper(EccCurve::P521);
}

fn test_ecdsa_export_pubkey_bcrypt_helper(curve: EccCurve) {
    let mut azihsm_provider = ProviderHandle::new();
    let mut alg_handle = BcryptAlgHandle::new();

    unsafe {
        // Open AziHSM provider
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok(), "result {:?}", result);

        // Create key in AziHSM
        let azihsm_key = ncrypt_create_ec_key(&azihsm_provider, BCRYPT_ECDSA_ALGORITHM, curve);

        // Sign with AziHSM
        let digest_size = 32;
        let mut digest = vec![0u8; digest_size];
        rand_bytes(&mut digest).expect("Failed to generate random bytes");

        let signature = ncrypt_sign(&azihsm_key, &digest, None, NCRYPT_FLAGS(0));

        // Export public key
        let export_buffer = ncrypt_export_key(&azihsm_key, BCRYPT_ECCPUBLIC_BLOB);

        // Open Bcrypt provider
        let alg_string = match curve {
            EccCurve::P256 => BCRYPT_ECDSA_P256_ALGORITHM,
            EccCurve::P384 => BCRYPT_ECDSA_P384_ALGORITHM,
            EccCurve::P521 => BCRYPT_ECDSA_P521_ALGORITHM,
        };
        let result = BCryptOpenAlgorithmProvider(
            alg_handle.as_mut(),
            alg_string,
            MS_PRIMITIVE_PROVIDER,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        );
        assert!(result.is_ok(), "result {:?}", result);

        // Import key in bcrypt
        let bcrypt_key =
            bcrypt_import_public_key(&alg_handle, BCRYPT_ECCPUBLIC_BLOB, &export_buffer);

        // Verify signature in bcrypt
        bcrypt_verify(&bcrypt_key, &digest, &signature, None, BCRYPT_FLAGS(0));
    }
}

#[test]
fn test_rsa_export_pubkey_bcrypt_2k() {
    test_rsa_export_pubkey_bcrypt_helper(RsaSize::Size2k);
}

#[test]
fn test_rsa_export_pubkey_bcrypt_3k() {
    test_rsa_export_pubkey_bcrypt_helper(RsaSize::Size3k);
}

#[test]
fn test_rsa_export_pubkey_bcrypt_4k() {
    test_rsa_export_pubkey_bcrypt_helper(RsaSize::Size4k);
}

fn test_rsa_export_pubkey_bcrypt_helper(rsa_size: RsaSize) {
    let mut azihsm_provider = ProviderHandle::new();
    let mut alg_handle = BcryptAlgHandle::new();

    unsafe {
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok(), "result {:?}", result);

        // Import RSA key in AziHSM
        let key_type = match rsa_size {
            RsaSize::Size2k => KeyType::Rsa2k,
            RsaSize::Size3k => KeyType::Rsa3k,
            RsaSize::Size4k => KeyType::Rsa4k,
        };

        let (_import_key, azihsm_key) = import_wrapped_key(
            azihsm_provider.handle(),
            key_type,
            KeyEncryptionAlgorithm::RSA_AES_KEY_WRAP_256,
            NCRYPT_ALLOW_SIGNING_FLAG,
            None,
        );

        // Sign with AziHSM
        let padding_info: BCRYPT_PKCS1_PADDING_INFO = BCRYPT_PKCS1_PADDING_INFO {
            pszAlgId: NCRYPT_SHA256_ALGORITHM,
        };
        let digest_size = 32;
        let mut digest = vec![1u8; digest_size];
        rand_bytes(&mut digest).expect("Failed to generate random bytes");

        let signature = ncrypt_sign(
            &azihsm_key,
            &digest,
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            NCRYPT_PAD_PKCS1_FLAG,
        );

        // Export public key
        let export_buffer = ncrypt_export_key(&azihsm_key, BCRYPT_RSAPUBLIC_BLOB);

        // Open Bcrypt provider
        let result = BCryptOpenAlgorithmProvider(
            alg_handle.as_mut(),
            BCRYPT_RSA_SIGN_ALGORITHM,
            MS_PRIMITIVE_PROVIDER,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        );
        assert!(result.is_ok(), "result {:?}", result);

        // Import key in bcrypt
        let bcrypt_key =
            bcrypt_import_public_key(&alg_handle, BCRYPT_RSAPUBLIC_BLOB, &export_buffer);

        bcrypt_verify(
            &bcrypt_key,
            &digest,
            &signature,
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            BCRYPT_PAD_PKCS1,
        );
    }
}

fn test_ecdh_kbkdf_bcrypt_helper(curve: EccCurve) {
    let mut azihsm_provider = ProviderHandle::new();
    let mut alg_handle = BcryptAlgHandle::new();

    unsafe {
        // Alice uses Azihsm provider
        let result = NCryptOpenStorageProvider(azihsm_provider.as_mut(), AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok(), "result {:?}", result);

        // Alice creates EC key and exports
        let alice_key = ncrypt_create_ec_key(&azihsm_provider, BCRYPT_ECDH_ALGORITHM, curve);

        // Export public key
        let alice_public_key_buffer = ncrypt_export_key(&alice_key, BCRYPT_ECCPUBLIC_BLOB);

        // Bob uses Bcrypt provider
        let alg_string = match curve {
            EccCurve::P256 => BCRYPT_ECDH_P256_ALGORITHM,
            EccCurve::P384 => BCRYPT_ECDH_P384_ALGORITHM,
            EccCurve::P521 => BCRYPT_ECDH_P521_ALGORITHM,
        };
        let result = BCryptOpenAlgorithmProvider(
            alg_handle.as_mut(),
            alg_string,
            MS_PRIMITIVE_PROVIDER,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        );
        assert!(result.is_ok(), "result {:?}", result);

        let bob_key = bcrypt_create_ec_key(&alg_handle, curve);

        // Export public key
        let bob_public_key_buffer = bcrypt_export_key(&bob_key, BCRYPT_ECCPUBLIC_BLOB);

        // Alice and Bob import keys
        let alice_imported_bob_key = ncrypt_import_public_key(
            &azihsm_provider,
            BCRYPT_ECCPUBLIC_BLOB,
            &bob_public_key_buffer,
        );
        let bob_imported_alice_key =
            bcrypt_import_public_key(&alg_handle, BCRYPT_ECCPUBLIC_BLOB, &alice_public_key_buffer);

        // Alice and Bob Secret Agreement
        let alice_secret = ncrypt_secret_agreement(&alice_key, &alice_imported_bob_key);

        let bob_secret = bcrypt_secret_agreement(&bob_key, &bob_imported_alice_key);

        // Define KBKDF parameters
        let mut label_data = [0u8; 16];
        let label_bytes = "label".as_bytes();
        label_data[..label_bytes.len()].copy_from_slice(label_bytes);

        let mut context = [0u8; 16];
        let context_bytes = "context".as_bytes();
        context[..context_bytes.len()].copy_from_slice(context_bytes);

        let key_bit_length: u32 = 256;
        let ncrypt_param_buffers = [
            // digest kind
            BCryptBuffer {
                cbBuffer: (BCRYPT_SHA256_ALGORITHM.to_string().unwrap().len()
                    * std::mem::size_of::<u16>()) as u32,
                BufferType: KDF_HASH_ALGORITHM,
                pvBuffer: BCRYPT_SHA256_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
            },
            // context
            BCryptBuffer {
                cbBuffer: context.len() as u32,
                BufferType: KDF_CONTEXT,
                pvBuffer: context.as_ptr() as *mut std::ffi::c_void,
            },
            // label
            BCryptBuffer {
                cbBuffer: label_data.len() as u32,
                BufferType: KDF_LABEL,
                pvBuffer: label_data.as_ptr() as *mut std::ffi::c_void,
            },
            // key bit length; Required for NCRYPT
            BCryptBuffer {
                cbBuffer: std::mem::size_of::<u32>() as u32,
                BufferType: KDF_KEYBITLENGTH,
                pvBuffer: &key_bit_length as *const u32 as *mut std::ffi::c_void,
            },
        ];

        let ncrypt_param_list = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: ncrypt_param_buffers.len() as u32,
            pBuffers: ncrypt_param_buffers.as_ptr() as *mut BCryptBuffer,
        };

        // Alice import derived key buffer to get the key handle
        let alice_derived_key = ncrypt_derive_aes_key(
            &azihsm_provider,
            &alice_secret,
            BCRYPT_SP800108_CTR_HMAC_ALGORITHM,
            Some(&ncrypt_param_list),
            key_bit_length,
        );

        // Define KBKDF parameters for bcrypt
        let bcrypt_param_buffers = [
            // digest kind
            BCryptBuffer {
                cbBuffer: (BCRYPT_SHA256_ALGORITHM.to_string().unwrap().len()
                    * std::mem::size_of::<u16>()) as u32,
                BufferType: KDF_HASH_ALGORITHM,
                pvBuffer: BCRYPT_SHA256_ALGORITHM.as_ptr() as *mut std::ffi::c_void,
            },
            // context
            BCryptBuffer {
                cbBuffer: context.len() as u32,
                BufferType: KDF_CONTEXT,
                pvBuffer: context.as_ptr() as *mut std::ffi::c_void,
            },
            // label
            BCryptBuffer {
                cbBuffer: label_data.len() as u32,
                BufferType: KDF_LABEL,
                pvBuffer: label_data.as_ptr() as *mut std::ffi::c_void,
            },
            // BCrypt does not use key bit length
        ];
        let bcrypt_param_list = BCryptBufferDesc {
            ulVersion: NCRYPTBUFFER_VERSION,
            cBuffers: bcrypt_param_buffers.len() as u32,
            pBuffers: bcrypt_param_buffers.as_ptr() as *mut BCryptBuffer,
        };
        // Bob derive key
        let bob_derived_key = bcrypt_derive_aes_key(
            &bob_secret,
            BCRYPT_SP800108_CTR_HMAC_ALGORITHM,
            Some(&bcrypt_param_list),
            key_bit_length,
        );

        // AES encrypt with BCrypt, decrypt with Manticore
        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).expect("Failed to generate random bytes");

        let mut plaintext = vec![0u8; 128];
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let encrypted = bcrypt_aes_encrypt(&bob_derived_key, &iv, &plaintext);
        let decrypted = ncrypt_aes_decrypt(&alice_derived_key, &iv, &encrypted);
        assert_eq!(plaintext, decrypted);

        // AES encrypt with Manticore, decrypt with BCrypt
        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).expect("Failed to generate random bytes");

        let mut plaintext = vec![0u8; 128];
        rand_bytes(&mut plaintext).expect("Failed to generate random bytes");

        let encrypted = ncrypt_aes_encrypt(&alice_derived_key, &iv, &plaintext);
        let decrypted = bcrypt_aes_decrypt(&bob_derived_key, &iv, &encrypted);
        assert_eq!(plaintext, decrypted);
    }
}

#[test]
fn test_ecdh_kbkdf_bcrypt_256() {
    test_ecdh_kbkdf_bcrypt_helper(EccCurve::P256);
}

#[test]
fn test_ecdh_kbkdf_bcrypt_384() {
    test_ecdh_kbkdf_bcrypt_helper(EccCurve::P384);
}

#[test]
fn test_ecdh_kbkdf_bcrypt_521() {
    test_ecdh_kbkdf_bcrypt_helper(EccCurve::P521);
}

unsafe fn set_property(
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
